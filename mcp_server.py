import json
import logging
import os
import threading
import traceback
from pathlib import Path

from typing import Any, Optional

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from controller import SessionController
from llm_bridge import load_llm_from_env
from playwright_client import PlaywrightWorkerClient
from proxy_client import ProxyControlClient


# IMPORTANTE:
# Servidor MCP em stdio não deve escrever em stdout.
# Logging vai para stderr por padrão.
BASE_DIR = Path(__file__).resolve().parent
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
)
log = logging.getLogger("session_mcp")

mcp = FastMCP("browser-session-runtime")

_controller_lock = threading.Lock()
_controller: Optional[SessionController] = None
def dbg(msg: str) -> None:
    with open("/tmp/iara_mcp.log", "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return{str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return[_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")
    return value 


def _playwright_enabled() -> bool:
    return os.getenv("USE_PLAYWRIGHT", "false").strip().lower() == "true"


def _build_bootstrap_payload(headless: bool | None = None) -> dict[str, Any]:
    browser_name = os.getenv("PW_BROWSER", "chromium").lower()
    engine_map = {
        "chromium": 1,
        "firefox": 2,
        "webkit": 3,
    }

    proxy_server = os.getenv("MITM_PROXY_SERVER", "").strip()
    har_path = os.getenv("PW_HAR_PATH", "artifacts/session.har.zip")

    effective_headless = (
        headless
        if headless is not None
        else os.getenv("PW_HEADLESS", "false").lower() == "true"
    )

    return {
        "engine": engine_map.get(browser_name, 1),
        "headless": effective_headless,
        "devtools": os.getenv("PW_DEVTOOLS", "false").lower() == "true",
        "enable_javascript": True,
        "ignore_https_errors": os.getenv("PW_IGNORE_HTTPS_ERRORS", "true").lower() == "true",
        "navigation_timeout_ms": int(os.getenv("PW_NAVIGATION_TIMEOUT_MS", "30000")),
        "initial_url": os.getenv("START_URL", ""),
        "proxy": {
            "enabled": bool(proxy_server),
            "server": proxy_server,
            "bypass": os.getenv("MITM_PROXY_BYPASS", ""),
            "username": os.getenv("MITM_PROXY_USERNAME", ""),
            "password": os.getenv("MITM_PROXY_PASSWORD", ""),
        },
        # só vai funcionar depois do patch no bootstrap.js
        "record_har": {
            "path": har_path,
            "content": "attach",
            "mode": "full",
        },
    }

def _make_controller() -> SessionController:
    proxy_api_url = os.getenv("MITM_CONTROL_URL", "http://127.0.0.1:8765") #Where your mitm is running

    Path("artifacts").mkdir(exist_ok=True)
    worker: Optional[PlaywrightWorkerClient] = None

    if _playwright_enabled():
        worker_path = os.getenv(
            "PW_WORKER_PATH",
            str(BASE_DIR/"browser_bridge/playwright_worker.js"),
        )    
        
        worker = PlaywrightWorkerClient(worker_path)

    proxy = ProxyControlClient(proxy_api_url)
    llm = load_llm_from_env()

    return SessionController(worker, proxy, llm)


def _get_controller() -> SessionController:

    global _controller
    with _controller_lock:
        if _controller is None:
            _controller = _make_controller()
        controller = _controller
        assert controller is not None
        return controller


def _require_active_controller() ->SessionController:
    global _controller
    with _controller_lock:
        if _controller is None:
            raise RuntimeError("no active session")
        return _controller


def _require_proxy_client() -> ProxyControlClient:
    controller = _require_active_controller()
    proxy = controller.proxy
    if proxy is None:
        raise RuntimeError("proxy is disabled")
    return proxy


@mcp.tool()
def start_session(
    start_url: str = "",
    headless: bool | None = None,
) -> dict[str, Any]:
    
    """
    Inicia a sessão observada.
    Sobe o Playwright worker, conecta no mitmproxy e ativa o loop leve de observação.
    """
    global _controller

    controller: Optional[SessionController] = None

    try:
        dbg(f"start_session called start_url={start_url}")
        dbg("before acquiring _controller_lock")
    
        acquired = _controller_lock.acquire(timeout=3)
        dbg(f"lock acquired? {acquired}")
        if not acquired:
            return{
                "ok": False,
                "status":"lock_timeout",
                "error": "_controller_lock is stuck",
            }

        try:
            dbg("inside lock")
            if _controller is not None:
                dbg("session already running")
                return{
                    "ok": False,
                    "status": "session_already_running",
                }
            dbg("creating controller")
            _controller = _make_controller()
            controller = _controller
            dbg("controller created")
        finally:
            _controller_lock.release()
            dbg("lock released")

        if controller is None:
            return {
                "ok": False,
                "status": "start_failed",
                "error": "controller was not created",
            }

        if controller.proxy is not None:
            try:
                health = controller.proxy.health()
                dbg(f"proxy health ok: {health}")
            except Exception:
                dbg("proxy health failed")
                dbg(traceback.format_exc())
                with _controller_lock:
                    if _controller is controller:
                        _controller = None
                return{
                    "ok": False,
                    "status": "proxy_unreachable",
                    "error": "mitmproxy control API is not reachable",
                }

        dbg("calling controller.start_session")
        bootstrap_payload = (
            _build_bootstrap_payload(headless= headless)
            if controller.worker is not None
            else None
        )
        effective_start_url = (
            (start_url or None)
            if controller.worker is not None
            else None
        )
        controller.start_session(
            bootstrap_payload=bootstrap_payload,
            start_url= effective_start_url,
        )

        dbg("controller.start_session returned")
        return{
            "ok": True,
            "status": "session_started",
            "start_url": (start_url or None) if _controller.worker is not None else None,
            "headless": headless,
        }

    except Exception:
        dbg("error starting session")
        dbg(traceback.format_exc())

        try:
            if controller is not None:
                controller.stop()

        except Exception:
            dbg("controller.stop failed")
            dbg(traceback.format_exc())

        with _controller_lock:
            if _controller is controller:
                _controller = None
        return{
            "ok": False,
            "status": "start_failed",
            "error":"see /tmp/iara_mcp.log"
        }

@mcp.tool()
def checkpoint(reason: str = "manual_checkpoint") -> dict[str, Any]:
    """
    Captura um checkpoint da página atual:
    page info, scripts, cookies e storage.
    """
    controller = _require_active_controller()
    if controller.worker is None:
        return {
            "ok": True,
            "status":"checkpoint_skipped",
            "reason": reason,
            "message":"playwright is disabled",
        }
    try:
        controller.capture_checkpoint(reason=reason)
        return {
            "ok": True,
            "status": "checkpoint_captured",
            "reason": reason,
        }
    except Exception as exc:
        log.exception("checkpoint failed")
        return {
            "ok": False,
            "status": "checkpoint_failed",
            "error": str(exc),
        }


@mcp.tool()
def get_live_summary() -> dict[str, Any]:
    """
    Retorna um resumo leve da sessão em andamento,
    sem disparar a análise pesada.
    """
    controller = _require_active_controller()
    try:
        summary = controller.reducer.build_light_observation(consume= False)
        return {
            "ok": True,
            "status": "live_summary",
            "summary": summary or {},
        }
    except Exception as exc:
        log.exception("get_live_summary failed")
        return {
            "ok": False,
            "status": "live_summary_failed",
            "error": str(exc),
        }


@mcp.tool()
def finalize() -> dict[str, Any]:
    """
    Congela a sessão atual, sincroniza flows,
    monta o relatório consolidado e pede análise pesada à LLM.
    """
    controller = _get_controller()
    try:
        result = controller.finalize()
        return {
            "ok": True,
            "status": "finalized",
            "result": result,
        }
    except Exception as exc:
        log.exception("finalize failed")
        return {
            "ok": False,
            "status": "finalize_failed",
            "error": str(exc),
        }


def _clip_text(value: Any, max_len: int = 1200) -> Any:
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len] + "...[truncated]"
    return value


def _compact_headers(headers: Any, max_items: int = 20) -> dict[str, Any]:
    if not isinstance(headers, dict):
        return {}
    out = {}
    for i, (k, v) in enumerate(headers.items()):
        if i >= max_items:
            break
        out[str(k)] = _clip_text(str(v), 300)
    return out


def _compact_flow(flow: dict[str, Any], include_bodies: bool = False, body_max_len: int = 1200) -> dict[str, Any]:
    req = flow.get("original_request", {}) or {}
    res = flow.get("original_response", {}) or {}
    mreq = flow.get("mutated_request", {}) or {}
    mres = flow.get("mutated_response", {}) or {}

    def pack_http(msg: dict[str, Any], *, is_response: bool) -> dict[str, Any]:
        if not msg:
            return {}

        out: dict[str, Any] = {
            "headers": _compact_headers(msg.get("headers", {})),
        }

        if is_response:
            out["status_code"] = msg.get("status_code")
        else:
            out["method"] = msg.get("method")
            out["url"] = msg.get("url")

        body = msg.get("body")
        if isinstance(body, str):
            out["body_len"] = len(body.encode("utf-8"))
            if include_bodies:
                out["body_preview"] = _clip_text(body, body_max_len)
        elif body is not None:
            body_text = str(body)
            out["body_len"] = len(body_text.encode("utf-8"))
            if include_bodies:
                out["body_preview"] = _clip_text(body_text, body_max_len)

        return out

    return {
        "id": flow.get("id"),
        "scheme": flow.get("scheme"),
        "host": flow.get("host"),
        "path": flow.get("path"),
        "intercepted": flow.get("intercepted"),
        "mutated": flow.get("mutated"),
        "has_websocket": flow.get("has_websocket"),
        "applied_rule_ids": flow.get("applied_rule_ids", []),
        "created_at": flow.get("created_at"),
        "original_request": pack_http(req, is_response=False),
        "original_response": pack_http(res, is_response=True),
        "mutated_request": pack_http(mreq, is_response=False) if mreq else {},
        "mutated_response": pack_http(mres, is_response=True) if mres else {},
    }

@mcp.tool()
def get_flow(
    flow_id: str,
    include_bodies: bool = False,
    body_max_len: int = 1200,
) -> dict[str, Any]:
    """
    Busca um flow específico no mitmproxy control API.
    Retorna versão compacta por padrão.
    """
    try:
        proxy = _require_proxy_client()
        flow = proxy.get_flow(flow_id)
        compact = _compact_flow(
            _json_safe(flow),
            include_bodies=include_bodies,
            body_max_len=max(200, min(body_max_len, 4000)),
        )
        return {
            "ok": True,
            "status": "flow_loaded",
            "flow": compact,
        }
    except Exception as exc:
        log.exception("get_flow failed")
        return {
            "ok": False,
            "status": "get_flow_failed",
            "error": str(exc),
        }

@mcp.tool()
def list_recent_flows_light(limit: int = 20) -> dict[str, Any]:
    """
    Lista flows recentes em formato leve, sem bodies completos.
    """
    try:
        proxy = _require_proxy_client()
        flows = proxy.get_flows()

        compact = []
        for flow in flows[:max(1, min(limit, 50))]:
            req = flow.get("original_request", {}) or {}
            res = flow.get("original_response", {}) or {}

            compact.append({
                "id": flow.get("id"),
                "host": flow.get("host"),
                "path": flow.get("path"),
                "scheme": flow.get("scheme"),
                "intercepted": flow.get("intercepted"),
                "mutated": flow.get("mutated"),
                "has_websocket": flow.get("has_websocket"),
                "applied_rule_ids": flow.get("applied_rule_ids", []),
                "request": {
                    "method": req.get("method"),
                    "url": req.get("url"),
                    "content_type": (req.get("headers", {}) or {}).get("content-type", ""),
                    "body_len": len((req.get("body") or "").encode("utf-8")) if isinstance(req.get("body"), str) else 0,
                },
                "response": {
                    "status_code": res.get("status_code"),
                    "content_type": (res.get("headers", {}) or {}).get("content-type", ""),
                    "body_len": len((res.get("body") or "").encode("utf-8")) if isinstance(res.get("body"), str) else 0,
                },
            })

        return {
            "ok": True,
            "status": "recent_flows",
            "count": len(compact),
            "flows": compact,
        }
    except Exception as exc:
        log.exception("list_recent_flows failed")
        return {
            "ok": False,
            "status": "list_recent_flows_failed",
            "error": str(exc),
        }

@mcp.tool()
def apply_rules(rules_json: str) -> dict[str, Any]:
    
    #Substitui o conjunto de regras do mitmproxy.
    #Passe um JSON array em string.
    
    try:
        proxy = _require_proxy_client()
        rules = json.loads(rules_json)
        if not isinstance(rules, list):
            return {
                "ok": False,
                "status": "invalid_rules",
                "error": "rules_json must decode to a list",
            }

        result = proxy.replace_rules(rules)
        return {
            "ok": True,
            "status": "rules_replaced",
            "result": result,
        }
    except Exception as exc:
        log.exception("apply_rules failed")
        return {
            "ok": False,
            "status": "apply_rules_failed",
            "error": str(exc),
        }


@mcp.tool()
def clear_rules() -> dict[str, Any]:
    
    #Limpa todas as regras ativas no addon do mitmproxy.
    
    try:
        proxy = _require_proxy_client()
        result = proxy.clear_rules()
        return {
            "ok": True,
            "status": "rules_cleared",
            "result": result,
        }
    except Exception as exc:
        log.exception("clear_rules failed")
        return {
            "ok": False,
            "status": "clear_rules_failed",
            "error": str(exc),
        }

@mcp.tool()
def ask_llm(prompt: str) -> dict[str, Any]:
    controller = _get_controller()
    try:
        result = controller.llm.ask(prompt)
        return{
            "ok": True,
            "status": "llm_replied",
            "response": result,
        }
    except Exception as exc:
        log.exception("ask_llm failed")
        return{
            "ok": False,
            "status": "ask_llm_failed",
            "error": str(exc),
        }

@mcp.tool()
def stop_session() -> dict[str, Any]:
    """
    Encerra a sessão atual e libera recursos do Playwright worker.
    """
    global _controller

    with _controller_lock:
        if _controller is None:
            return {
                "ok": True,
                "status": "no_active_session",
            }

        controller = _controller
        _controller = None

    try:
        controller.stop()
        return {
            "ok": True,
            "status": "session_stopped",
        }
    except Exception as exc:
        log.exception("stop_session failed")
        return {
            "ok": False,
            "status": "stop_failed",
            "error": str(exc),
        }


def main() -> None:
    load_dotenv()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
