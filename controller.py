import threading 
import time
import logging
from typing import Any, Dict, Optional
from llm_bridge import LlmConfig, OpenAICompatLLM
from playwright_client import PlaywrightWorkerClient
from proxy_client import ProxyControlClient
from session_parser import SessionReducer


log = logging.getLogger("session_controller")

class SessionController:
    def __init__(
        self,
        worker: Optional[PlaywrightWorkerClient],
        proxy: Optional[ProxyControlClient],
        llm: OpenAICompatLLM,
        *,
        proxy_poll_interval_s: float = 2.0,
        observe_interval_s: float = 8.0,
    ):
        self.worker = worker
        self.proxy = proxy
        self.llm = llm
        self.reducer = SessionReducer()

        self.proxy_poll_interval_s = proxy_poll_interval_s
        self.observe_interval_s = observe_interval_s

        self._running = False
        self._proxy_thread: Optional[threading.Thread] = None
        self._observe_thread: Optional[threading.Thread] = None

        if self.worker is not None:
            self.worker.register_event_callback(self._on_worker_event)

    def _on_worker_event(self, event_msg: Dict[str, Any]) -> None:
        self.reducer.ingest_browser_event(event_msg)

    def start_session(
        self,
        bootstrap_payload: Optional[Dict[str, Any]] = None,
        start_url: Optional[str] = None,
    ) -> None:
        if self.worker is not None:
            log.info("worker.start()")
            self.worker.start()

            log.info("worker.bootstrap()")
            self.worker.bootstrap(bootstrap_payload or {})

            log.info("capture_checkpoint(startup)")
            self.capture_checkpoint("startup")

            if start_url:
                log.info("worker.navigate(%s)", start_url)
                self.worker.navigate(start_url)
                log.info("capture_checkpoint(after_start_url)")
                self.capture_checkpoint("after_start_url")

        self._running = True

        if self.proxy is not None:
            self._proxy_thread = threading.Thread(target=self._proxy_loop, daemon=True)
            self._proxy_thread.start()

        self._observe_thread = threading.Thread(target=self._observe_loop, daemon=True)
        self._observe_thread.start()

    def _proxy_loop(self) -> None:
        if self.proxy is None:
            return
        while self._running:
            try:
                flows = self.proxy.get_flows()
                self.reducer.ingest_proxy_flows(flows)
            except Exception as exc:
                self.reducer.ingest_browser_event(
                    {
                        "event": "proxy_poll_error",
                        "timestamp": None,
                        "payload": {"error": str(exc)},
                    }
                )
            time.sleep(self.proxy_poll_interval_s)

    def _observe_loop(self) -> None:
        while self._running:
            try:
                observation = self.reducer.build_light_observation(consume=True)
                if observation:
                    note = self.llm.observe(observation)
                    self.reducer.add_observe_note(note)

                    should_capture = bool(note.get("should_capture_more", False))
                    if should_capture and self.worker is not None:
                        self.capture_checkpoint("llm_requested_capture")
            except Exception as exc:
                self.reducer.ingest_browser_event(
                    {
                        "event": "observe_loop_error",
                        "timestamp": None,
                        "payload": {"error": str(exc)},
                    }
                )
            time.sleep(self.observe_interval_s)

    def capture_checkpoint(self, reason: str) -> None:
        if self.worker is None:
            return

        page_info = {}
        scripts = {}
        cookies = {}
        storage = {}

        try:
            page_info = self.worker.get_page_info()
        except Exception:
            log.exception("get_page_info failed")

        try:
            scripts = self.worker.collect_scripts()
        except Exception:
            log.exception("collect_scripts failed")

        try:
            cookies = self.worker.get_cookies()
        except Exception:
            log.exception("get_cookies failed")

        try:
            storage = self.worker.get_storage()
        except Exception:
            log.exception("get_storage failed")

        self.reducer.ingest_page_checkpoint(
            reason=reason,
            page_info=page_info,
            scripts=scripts,
            cookies=cookies,
            storage=storage,
        )

    def finalize(self) -> Dict[str, Any]:
        if self.worker is not None:
            self.capture_checkpoint("finalize_pre_sync")

        try:
            if self.proxy is not None:
                flows = self.proxy.get_flows()
                self.reducer.ingest_proxy_flows(flows)
        except Exception:
            log.exception("finalize proxy sync failed")

        report = self.reducer.build_finalize_report()

        try:
            analysis = self.llm.finalize(report)
        except Exception as exc:
            log.exception("llm finalize failed")
            analysis = {
                "summary": "LLM finalize timed out or failed.",
                "priority_vectors": [],
                "top_flow_ids": [f.get("flow_id") for f in report.get("top_flows", [])[:5]],
                "next_actions": ["Retry finalize with a smaller report or a higher timeout."],
                "error": str(exc),
            }

        return {
            "report": report,
            "analysis": analysis,
        }

    def stop(self) -> None:
        self._running = False
        if self.worker is not None:
            self.worker.close()

