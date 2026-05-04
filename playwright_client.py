import json
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Queue, Empty
from typing import Any, Callable, Dict, Optional

@dataclass
class PendingCall:
    event: threading.Event
    response: Optional[Dict[str, Any]] = None


class PlaywrightWorkerClient:
    def __init__(self, worker_path: str):
        self.worker_path = str(Path(worker_path).resolve())
        self.proc: Optional[subprocess.Popen] = None
        self._id_lock = threading.Lock()
        self._next_id = 1
        self._pending: Dict[int, PendingCall] = {}
        self._event_callbacks: list[Callable[[Dict[str, Any]], None]] = []
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._alive = False
        self.stderr_lines: Queue[str] = Queue()
        self.stderr_log_path = "/tmp/playwright_worker.stderr.log"
        self.stdout_log_path = "/tmp/playwright_worker.stdout.log"
        self._stdout_log_fp = None
        self._stderr_log_fp = None
        self.worker_errors: Queue[str] = Queue()

    def _drain_stderr(self, limit: int = 20) -> list[str]:
        lines = []
        for _ in range(limit):
            try:
                lines.append(self.stderr_lines.get_nowait())
            except Empty:
                break
        return lines
    
# helper novo
    def _drain_worker_errors(self, limit: int = 20) -> list[str]:
        out = []
        for _ in range(limit):
            try:
                out.append(self.worker_errors.get_nowait())
            except Empty:
                break
        return out


    def start(self) -> None:
        if self.proc is not None:
            return

        self.proc = subprocess.Popen(
            ["node", self.worker_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._alive = True
        
        self._stderr_log_fp = open(self.stderr_log_path, "a", buffering=1, encoding="utf-8")
        self._stdout_log_fp = open(self.stdout_log_path, "a", buffering=1, encoding="utf-8")
        self._stdout_thread = threading.Thread(target=self._read_stdout_loop, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr_loop, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()
        
        time.sleep(0.5)

        if self.proc.poll() is not None:
            stderr = "\n".join(self._drain_stderr())
            raise RuntimeError(f"playwright worker exited immediatly with code {self.proc.returncode}. stderr: \n{stderr}")

    def register_event_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self._event_callbacks.append(callback)

    def _next_call_id(self) -> int:
        with self._id_lock:
            cid = self._next_id
            self._next_id += 1
            return cid

    def _read_stdout_loop(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for raw_line in self.proc.stdout:
            if self._stdout_log_fp is not None:
                self._stdout_log_fp.write(raw_line)
                self._stdout_log_fp.flush()
            line = raw_line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            mtype = msg.get("type")
            if mtype == "reply":
                cid = msg.get("id")
                pending = self._pending.get(cid)
                if pending is not None:
                    pending.response = msg
                    pending.event.set()
            elif mtype == "event":
                for cb in self._event_callbacks:
                    try:
                        cb(msg)
                    except Exception:
                        pass
            elif mtype == "error":
                err = msg.get("error", "unknown_worker_error")
                self.worker_errors.put(str(err))


    def _read_stderr_loop(self) -> None:
        assert self.proc is not None and self.proc.stderr is not None
        for line in self.proc.stderr:
            clean = line.strip("\n")
            self.stderr_lines.put(line.rstrip("\n"))

            if self._stderr_log_fp is not None:
                self._stderr_log_fp.write(clean + "\n")
                self._stderr_log_fp.flush()

    def call(self, cmd: str, payload: Optional[Dict[str, Any]] = None, timeout_s: int = 60) -> Dict[str, Any]:
        if self.proc is None or self.proc.stdin is None:
            raise RuntimeError("playwright worker is not started")
        
        if self.proc.poll() is not None:
            stderr = "\n".join(self._drain_stderr())
            raise RuntimeError(f"playwright worker already exited with code {self.proc.returncode}. stderr:\n{stderr}")

        cid = self._next_call_id()
        pending = PendingCall(event=threading.Event())
        self._pending[cid] = pending

        msg = {"id": cid, "cmd": cmd, "payload": payload or {}}
        try:
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
        except Exception as exc:
            self._pending.pop(cid, None)
            stderr = "\n".join(self._drain_stderr())
            raise RuntimeError(f"failed to write to worker stdin: {exc}\nstderr:\n{stderr}")

        if not pending.event.wait(timeout=timeout_s):
            self._pending.pop(cid, None)
            stderr = "\n".join(self._drain_stderr())
            worker_errors = "\n".join(self._drain_worker_errors())
            rc = self.proc.poll()
            raise TimeoutError(f"timeout waiting for worker reply: {cmd};"
                                f"returncode={rc};stderr:\n{stderr}\nworker_stdout_errors:\n{worker_errors}")

        self._pending.pop(cid, None)
        assert pending.response is not None

        if not pending.response.get("ok", False):
            raise RuntimeError(
                f"worker command failed: {cmd} -> {pending.response.get('error', 'unknown_error')}"
            )

        return pending.response.get("payload", {})

    def bootstrap(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.call("bootstrap", payload)

    def shutdown(self) -> Dict[str, Any]:
        return self.call("shutdown", {}, timeout_s=30)

    def navigate(self, url: str, wait_until: int = 2, timeout_ms: int = 30000) -> Dict[str, Any]:
        return self.call(
            "navigate",
            {
                "url": url,
                "wait_until": wait_until,
                "timeout_ms": timeout_ms,
            },
            timeout_s=max(30, timeout_ms // 1000 + 5),
        )

    def get_page_info(self) -> Dict[str, Any]:
        return self.call("get_page_info", {})

    def snapshot_dom(self) -> Dict[str, Any]:
        return self.call("snapshot_dom", {})

    def collect_scripts(self) -> Dict[str, Any]:
        return self.call("collect_scripts", {})

    def collect_network(self) -> Dict[str, Any]:
        return self.call("collect_network", {})

    def get_cookies(self) -> Dict[str, Any]:
        return self.call("get_cookies", {})

    def get_storage(self) -> Dict[str, Any]:
        return self.call("get_storage", {})

    def eval_js(self, expression: str) -> Dict[str, Any]:
        return self.call("eval_js", {"expression": expression})

    def close(self) -> None:
        if self._stderr_log_fp is not None:
            try:
                self._stderr_log_fp.close()
            except Exception:
                pass
            self._stderr_log_fp = None
        try:
            if self.proc is not None and self._alive:
                try:
                    self.shutdown()
                except Exception:
                    pass
        finally:
            if self.proc is not None:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=3)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
            self.proc = None
            self._alive = False
