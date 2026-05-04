import json
import threading
import re
from copy import deepcopy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from mitmproxy.net.http.cookies import CookieAttrs
from mitmproxy import ctx, http

MAX_FLOWS = 500


TELEMETRY_HOST_HINTS = (
    "datadoghq.com",
    "browser-intake-datadoghq.com",
    "google-analytics.com",
    "googletagmanager.com",
    "segment.io",
    "api.segment.io",
    "amplitude.com",
    "sentry.io",
    "newrelic.com",
    "mixpanel.com",
    "doubleclick.net",
    "hotjar.com",
    "fullstory.com",
    "/collect",
    "/track",
    "/tracking",
    "/events",
    "/analytics",
    "/telemetry",
    "/beacon",
    "/rum",
    "/metrics",
    "/logs",
)

TELEMETRY_PATH_RE = re.compile(
    r"(?:^|/)(?:collect|events?|track|analytics?|telemetry|beacon|rum|logs?|metrics?|batch)(?:/|$|\?)",
    re.IGNORECASE,
)

STATIC_ASSET_RE = re.compile(
    r"\.(?:css|png|jpe?g|gif|webp|bmp|ico|svg|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|ogg|avi|mov|map)(?:\?.*)?$",
    re.IGNORECASE,
)


TELEMETRY_QUERY_KEYS = {
    "tid", "cid", "vid", "event", "events", "en", "t", "dp", "dl",
}
NON_INTERESTING_FETCH_DEST = {
    "image",
    "style",
    "font",
    "audio",
    "video",
    "manifest",
    "track",
    "object",
    "paintworklet",
}

DROP_ACCEPT_HINTS = (
    "text/css",
    "image/",
    "font/",
    "audio/",
    "video/",
)

DROP_RESPONSE_CT_EXACT = {
    "text/css",
    "application/manifest+json",
}

DROP_RESPONSE_CT_PREFIXES = (
    "image/",
    "font/",
    "audio/",
    "video/",
)

WELL_KNOWN_STATIC_PATH_HINTS = (
    "/favicon.ico",
    "/robots.txt",
    "/manifest.json",
    "/site.webmanifest",
    "apple-touch-icon",
    "browserconfig.xml",
)

class IaraProxyAddon:
    def __init__(self):
        self.rules: List[dict] = []
        self.flows: Dict[str, dict] = {}
        self.flow_order: List[str] = []
        self.control_host = "127.0.0.1"
        self.control_port = 8765
        self.httpd = None
        self.httpd_thread = None
        self.lock = threading.Lock()
        self.debug_enabled = False
        self.flow_seq = 0

        self.drop_telemetry = True
        self.dropped_count = 0
        self.dropped_by_reason: Dict[str, int] = {}

    def load(self, loader):
        loader.add_option(
            name="iara_control_host",
            typespec=str,
            default="127.0.0.1",
            help="IARA proxy control host",
        )
        loader.add_option(
            name="iara_control_port",
            typespec=int,
            default=8765,
            help="IARA proxy control port",
        )
        loader.add_option(
            name="iara_debug",
            typespec=bool,
            default=False,
            help="Enable verbose IARA roxy debug logs",
        )
        loader.add_option(
            name="iara_drop_telemetry",
            typespec=bool,
            default=True,
            help="Drop telemetry-like flows before they enter IARA storage",
        )

    def configure(self, updated):
        if "iara_control_host" in updated:
            self.control_host = ctx.options.iara_control_host
        if "iara_control_port" in updated:
            self.control_port = ctx.options.iara_control_port
        if "iara_debug" in updated:
            self.debug_enabled = ctx.options.iara_debug
        if "iara_drop_telemetry" in updated:
            self.drop_telemetry = ctx.options.iara_drop_telemetry

    def _h(self, headers, name: str)-> str:
        return (headers.get(name, "") or "").lower()

    def debug(self, message:str):
        if self.debug_enabled:
            ctx.log.info(f"[IARA DEBUG] {message}")


    def mark_dropped(self, flow, reason: str) -> bool:

        if flow.metadata.get("iara_drop_reason"):
            return True

        flow.metadata["iara_drop_reason"] = reason

        with self.lock:
            self.dropped_count += 1
            self.dropped_by_reason[reason] = self.dropped_by_reason.get(reason, 0) + 1

        self.debug(
            f"dropped flow id={flow.id} reason={reason} "
            f"method={flow.request.method} url={flow.request.pretty_url}"
        )
        return True

    def is_static_asset(self, flow) -> bool:
        path = flow.request.path or ""
        url = flow.request.pretty_url or ""

        if STATIC_ASSET_RE.search(path) or STATIC_ASSET_RE.search(url):
            return True

        return False


    def dropped(self, flow) -> bool:

        if flow.metadata.get("iara_drop_reason"):
            return True

        if not self.drop_telemetry:
            return False

        method = (flow.request.method or "").upper()
        url = (flow.request.pretty_url or "").lower()
        path = (flow.request.path or "").lower()
        query_keys = {str(k).lower() for k in flow.request.query.keys()}

        fetch_dest = self._h(flow.request.headers, "sec-fetch-dest")
        accept = self._h(flow.request.headers, "accept")
        purpose = self._h(flow.request.headers, "purpose")
        sec_purpose = self._h(flow.request.headers, "sec-purpose")

        if TELEMETRY_PATH_RE.search(url):
            return self.mark_dropped(flow, "telemetry_path")
        
        if self.is_static_asset(flow):
            return self.mark_dropped(flow, "static_asset")
        
        if query_keys & TELEMETRY_QUERY_KEYS:
            return self.mark_dropped(flow, "telemetry_query")

        if method in {"OPTIONS", "HEAD"}:
            return self.mark_dropped(flow, f"method:{method.lower()}")

        if any(hint in url for hint in TELEMETRY_HOST_HINTS):
            return self.mark_dropped(flow, "telemetry")

        if fetch_dest in NON_INTERESTING_FETCH_DEST:
            return self.mark_dropped(flow, f"fetch_dest:{fetch_dest}")

        if any(hint in accept for hint in DROP_ACCEPT_HINTS):
            return self.mark_dropped(flow, "accept_header")

        if "prefetch" in purpose or "prefetch" in sec_purpose:
            return self.mark_dropped(flow, "prefetch")

        if flow.response:
            
            resp_ct = self._h(flow.response.headers, "content-type").split(";", 1)[0].strip()
            
            if resp_ct in DROP_RESPONSE_CT_EXACT:
                return self.mark_dropped(flow, f"response_ct{resp_ct}")
            
            if any(resp_ct.startswith(prefix) for prefix in DROP_RESPONSE_CT_PREFIXES):
                return self.mark_dropped(flow, f"response_ct{resp_ct}")

        return False

    def running(self):
        self.debug(f"starting control server host={self.control_host} port={self.control_port}")
        self.start_control_server()

    def done(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()



    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def start_control_server(self):
        addon = self

        class Handler(BaseHTTPRequestHandler):
            def _json(self, status: int, payload: Any):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/health":
                    with addon.lock:
                        count = len(addon.flow_order)
                        rules_count = len(addon.rules)
                        dropped_count = addon.dropped_count
                        dropped_by_reason = dict(addon.dropped_by_reason)
                    return self._json(200, 
                                      {
                                          "ok": True,
                                          "flows": count,
                                          "rules": rules_count,
                                          "dropped": dropped_count,
                                          "dropped_by_reason": dropped_by_reason,
                                    },
                                  )

                if self.path == "/flows":
                    items = []
                    with addon.lock:
                        for flow_id in reversed(addon.flow_order[-100:]):
                            flow = addon.flows.get(flow_id)
                            if flow:
                                items.append(flow)
                    return self._json(200, {"items": items})

                if self.path.startswith("/flows/"):
                    flow_id = self.path.split("/flows/", 1)[1]
                    with addon.lock:
                        flow = addon.flows.get(flow_id)
                    if flow is None:
                        return self._json(404, {"ok": False, "error": "flow not found"})
                    return self._json(200, {"ok": True, "item": flow})

                return self._json(404, {"ok": False, "error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b"{}"

                try:
                    payload = json.loads(raw.decode("utf-8"))
                except Exception:
                    return self._json(400, {"ok": False, "error": "invalid json"})

                if self.path == "/rules/replace":
                    rules = payload.get("rules", [])
                    if not isinstance(rules, list):
                        return self._json(400, {"ok": False, "error": "rules must be a list"})

                    normalized = sorted(
                        rules,
                        key=lambda r: (int(r.get("priority", 0)), str(r.get("id", ""))),
                    )
                    with addon.lock:
                        addon.rules = normalized
                        count = len(addon.rules)
                    addon.debug(f"rules replaced count={count}")
                    return self._json(200, {"ok": True, "count": count})

                if self.path == "/rules/clear":
                    with addon.lock:
                        addon.rules = []
                    addon.debug("rules cleared")
                    return self._json(200, {"ok": True})

                return self._json(404, {"ok": False, "error": "not found"})

            def log_message(self, *args, **kwargs):
                return

        self.httpd = ThreadingHTTPServer((self.control_host, self.control_port), Handler)
        self.httpd_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.httpd_thread.start()
        ctx.log.info(f"IARA control API listening on {self.control_host}:{self.control_port}")

    def request(self, flow: http.HTTPFlow):
        
        if self.dropped(flow):
            return

        self.debug(f"request start id={flow.id} method={flow.request.method} url={flow.request.pretty_url}")
        entry = self.ensure_flow_entry(flow)
        original = self.serialize_request(flow)
        entry["original_request"] = original

        rules = self.get_rules_snapshot()
        intercepted, mutated, applied, dropped = self.apply_rules_for_hook(
            flow, rules, "request"
        )
        body_intercepted, body_mutated, body_applied, body_dropped = self.apply_rules_for_hook(
            flow, rules, "request_body"
        )

        entry["intercepted"] = entry["intercepted"] or intercepted or body_intercepted
        entry["mutated"] = entry["mutated"] or mutated or body_mutated
        entry["applied_rule_ids"] = self.merge_rule_ids(
            entry.get("applied_rule_ids", []), applied + body_applied
        )
        entry["mutated_request"] = self.serialize_request(flow)
        entry["scheme"] = flow.request.scheme
        entry["host"] = flow.request.pretty_host
        entry["path"] = flow.request.path
        entry["has_websocket"] = flow.websocket is not None

        self.remember_flow(flow.id, entry)
        self.debug(f"request done id={flow.id} intercepted={entry['intercepted']}"
                   f"mutated={entry['mutated']} applied={entry['applied_rule_ids']}"
                   )    
        if dropped or body_dropped:
            return

    def response(self, flow: http.HTTPFlow):

        if self.dropped(flow):
            return

        self.debug(f"response start id={flow.id} status={flow.response.status_code if flow.response else 0}")
        entry = self.ensure_flow_entry(flow)
        original = self.serialize_response(flow)
        entry["original_response"] = original

        rules = self.get_rules_snapshot()
        intercepted, mutated, applied, dropped = self.apply_rules_for_hook(
            flow, rules, "response"
        )
        body_intercepted, body_mutated, body_applied, body_dropped = self.apply_rules_for_hook(
            flow, rules, "response_body"
        )

        entry["intercepted"] = entry["intercepted"] or intercepted or body_intercepted
        entry["mutated"] = entry["mutated"] or mutated or body_mutated
        entry["applied_rule_ids"] = self.merge_rule_ids(
            entry.get("applied_rule_ids", []), applied + body_applied
        )

        mutated_response = self.serialize_response(flow)
        entry["mutated_response"] = mutated_response if mutated_response != original else None
        entry["scheme"] = flow.request.scheme
        entry["host"] = flow.request.pretty_host
        entry["path"] = flow.request.path
        entry["has_websocket"] = flow.websocket is not None
        self.debug(f"response done={flow.id} intercepted={entry['intercepted']}"
                   f"mutated={entry['mutated']} applied={entry['applied_rule_ids']}"
                   )
        self.remember_flow(flow.id, entry)

        if dropped or body_dropped:
            return

    def websocket_message(self, flow):
        if self.dropped(flow):
            return
        
        entry = self.ensure_flow_entry(flow)
        rules = self.get_rules_snapshot()
        intercepted, mutated, applied, _ = self.apply_rules_for_hook(
            flow, rules, "websocket_message"
        )
        entry["intercepted"] = entry["intercepted"] or intercepted
        entry["mutated"] = entry["mutated"] or mutated
        entry["applied_rule_ids"] = self.merge_rule_ids(
            entry.get("applied_rule_ids", []), applied
        )
        self.remember_flow(flow.id, entry)

    def get_rules_snapshot(self) -> List[dict]:
        with self.lock:
            return deepcopy(self.rules)

    def merge_rule_ids(self, current: List[str], new_ids: List[str]) -> List[str]:
        out = list(current)
        for rid in new_ids:
            if rid and rid not in out:
                out.append(rid)
        return out

    def ensure_flow_entry(self, flow) -> dict:
        with self.lock:
            existing = self.flows.get(flow.id)
            if existing is not None:
                return deepcopy(existing)

        request = self.serialize_request(flow)
        entry = {
            "id": flow.id,
            "scheme": flow.request.scheme,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "intercepted": False,
            "mutated": False,
            "has_websocket": flow.websocket is not None,
            "original_request": request,
            "mutated_request": request,
            "original_response": None,
            "mutated_response": None,
            "applied_rule_ids": [],
            "created_at": self.now_iso(),
        }
        self.remember_flow(flow.id, entry)
        return entry

    def remember_flow(self, flow_id: str, entry: dict):
        with self.lock:
            if flow_id not in self.flows:
                self.flow_order.append(flow_id)
            self.flows[flow_id] = deepcopy(entry)

            while len(self.flow_order) > MAX_FLOWS:
                old = self.flow_order.pop(0)
                self.flows.pop(old, None)

    def serialize_request(self, flow: http.HTTPFlow):
        body = flow.request.get_text(strict=False)
        return {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "body": body,
        }

    def serialize_response(self, flow: http.HTTPFlow):
        body = flow.response.get_text(strict=False) if flow.response else ""
        return {
            "status_code": flow.response.status_code if flow.response else 0,
            "headers": dict(flow.response.headers) if flow.response else {},
            "body": body,
        }

    def apply_rules_for_hook(
        self, flow, rules: List[dict], hook_name: str
    ) -> Tuple[bool, bool, List[str], bool]:
        intercepted = False
        mutated_any = False
        applied: List[str] = []
        dropped = False

        for rule in rules:
            if not rule.get("enabled", True):
                continue
            if rule.get("hook", "request") != hook_name:
                continue
            if not self.match_rule(flow, rule, hook_name):
                continue

            intercepted = True
            self.debug(f"rule matched hook={hook_name} id={rule.get('id', '')}"
                       f"action={rule.get('action', '')}path={flow.request.path}"
                       )
            changed = self.apply_rule(flow, rule, hook_name)
            self.debug(f"rule applied hook={hook_name} id={rule.get('id','')} changed={changed}")
            applied.append(rule.get("id", ""))
            mutated_any = mutated_any or changed

            if rule.get("action") == "drop_flow":
                dropped = True
                break

            if rule.get("stop_on_match", False):
                break

        return intercepted, mutated_any, applied, dropped

    def match_rule(self, flow, rule: dict, hook_name: str) -> bool:
        match = rule.get("match", {}) or {}
        return self.match_common(flow, match, hook_name)

    def match_common(self, flow, match: dict, hook_name: str) -> bool:
        case_sensitive = bool(match.get("case_sensitive", False))
        flags = 0 if case_sensitive else re.IGNORECASE

        method = match.get("method")
        if method and flow.request.method.upper() != method.upper():
            return False

        host_regex = match.get("host_regex")
        if host_regex and not re.search(host_regex, flow.request.pretty_host, flags):
            return False

        path_regex = match.get("path_regex")
        if path_regex and not re.search(path_regex, flow.request.path, flags):
            return False

        url_regex = match.get("url_regex")
        if url_regex and not re.search(url_regex, flow.request.pretty_url, flags):
            return False

        content_type_regex = match.get("content_type_regex")
        if content_type_regex:
            if hook_name.startswith("response"):
                ctype = flow.response.headers.get("content-type", "") if flow.response else ""
            else:
                ctype = flow.request.headers.get("content-type", "")
            if not re.search(content_type_regex, ctype, flags):
                return False

        status_codes = match.get("status_codes") or []
        if status_codes and hook_name.startswith("response"):
            if not flow.response or flow.response.status_code not in status_codes:
                return False

        header_regex = match.get("header_regex") or {}
        if header_regex:
            headers = flow.response.headers if hook_name.startswith("response") and flow.response else flow.request.headers
            for key, pattern in header_regex.items():
                value = headers.get(key, "")
                if not re.search(pattern, str(value), flags):
                    return False

        query_regex = match.get("query_regex") or {}
        if query_regex:
            for key, pattern in query_regex.items():
                value = flow.request.query.get(key, "")
                if not re.search(pattern, str(value), flags):
                    return False

        return True

    def apply_rule(self, flow, rule: dict, hook_name: str) -> bool:
        action_obj = rule.get("action")
        if not isinstance(action_obj, str):
            self.debug(f"invalid action in rule id={rule.get('id', '')}:{action_obj!r}")
            return False
        action = action_obj
        payload = rule.get("payload", {}) or {}

        if action == "mark_only":
            return False

        if action == "drop_flow":
            flow.kill()
            return True

        if hook_name == "request":
            return self.apply_request_rule(flow, action, payload)
        if hook_name == "request_body":
            return self.apply_request_body_rule(flow, action, payload)
        if hook_name == "response":
            return self.apply_response_rule(flow, action, payload)
        if hook_name == "response_body":
            return self.apply_response_body_rule(flow, action, payload)
        if hook_name == "websocket_message":
            return False

        return False

    def payload_obj(self, payload: dict, key: str) -> dict:
        value = payload.get(key, payload)
        return value if isinstance(value, dict) else {}

    def apply_request_rule(self, flow: http.HTTPFlow, action: str, payload: dict) -> bool:
        if action == "set_header":
            src = self.payload_obj(payload, "header")
            name = src.get("name", "")
            if not name:
                return False
            before = flow.request.headers.get(name)
            flow.request.headers[name] = str(src.get("value", ""))
            return before != flow.request.headers.get(name)

        if action == "remove_header":
            src = self.payload_obj(payload, "header")
            name = src.get("name", "")
            if not name or name not in flow.request.headers:
                return False
            del flow.request.headers[name]
            return True

        if action in {"set_query_param", "replace_query_param"}:
            src = self.payload_obj(payload, "query_param")
            name = src.get("name", "")
            if not name:
                return False
            old = flow.request.query.get(name)
            old_value = src.get("old_value", "")
            if action == "replace_query_param" and old_value and str(old) != str(old_value):
                return False
            flow.request.query[name] = str(src.get("value", ""))
            return old != flow.request.query.get(name)

        if action == "remove_query_param":
            src = self.payload_obj(payload, "query_param")
            name = src.get("name", "")
            if not name or name not in flow.request.query:
                return False
            del flow.request.query[name]
            return True

        if action == "set_cookie":
            src = self.payload_obj(payload, "cookie")
            name = src.get("name", "")
            if not name:
                return False
            old = flow.request.cookies.get(name)
            flow.request.cookies[name] = str(src.get("value", ""))
            return old != flow.request.cookies.get(name)

        if action == "remove_cookie":
            src = self.payload_obj(payload, "cookie")
            name = src.get("name", "")
            if not name or name not in flow.request.cookies:
                return False
            del flow.request.cookies[name]
            return True

        if action == "change_method":
            src = self.payload_obj(payload, "method")
            value = str(src.get("value", "")).upper()
            if not value or value == flow.request.method:
                return False
            flow.request.method = value
            return True

        if action == "rewrite_path":
            src = self.payload_obj(payload, "regex_replace")
            regex = src.get("regex", "")
            replacement = src.get("replacement", "")
            before = flow.request.path
            after = re.sub(regex, replacement, before)
            if after == before:
                return False
            flow.request.path = after
            return True

        if action == "rewrite_url_regex":
            src = self.payload_obj(payload, "regex_replace")
            regex = src.get("regex", "")
            replacement = src.get("replacement", "")
            before = flow.request.pretty_url
            after = re.sub(regex, replacement, before)
            if after == before:
                return False
            flow.request.url = after
            return True

        if action == "override_host":
            src = self.payload_obj(payload, "host")
            value = str(src.get("value", "")).strip()
            if not value or value == flow.request.pretty_host:
                return False
            flow.request.host = value
            flow.request.headers["Host"] = value
            return True

        if action == "override_scheme":
            src = self.payload_obj(payload, "scheme")
            value = str(src.get("value", "")).strip()
            if not value:
                return False
            parts = urlsplit(flow.request.pretty_url)
            if value == parts.scheme:
                return False
            flow.request.url = urlunsplit((value, parts.netloc, parts.path, parts.query, parts.fragment))
            return True

        return False

    def apply_request_body_rule(self, flow: http.HTTPFlow, action: str, payload: dict) -> bool:
        return self.apply_message_body_rule(flow.request, action, payload)

    def apply_response_rule(self, flow: http.HTTPFlow, action: str, payload: dict) -> bool:
        if not flow.response:
            return False

        if action == "set_header":
            src = self.payload_obj(payload, "header")
            name = src.get("name", "")
            if not name:
                return False
            before = flow.response.headers.get(name)
            flow.response.headers[name] = str(src.get("value", ""))
            return before != flow.response.headers.get(name)

        if action == "remove_header":
            src = self.payload_obj(payload, "header")
            name = src.get("name", "")
            if not name or name not in flow.response.headers:
                return False
            del flow.response.headers[name]
            return True

        if action == "set_cookie":
            src = self.payload_obj(payload, "cookie")
            name = src.get("name", "")
            if not name:
                return False
            old = flow.response.cookies.get(name)
            flow.response.cookies[name] = (str(src.get("value", "")), CookieAttrs())
            return old != flow.response.cookies.get(name)

        if action == "remove_cookie":
            src = self.payload_obj(payload, "cookie")
            name = src.get("name", "")
            if not name or name not in flow.response.cookies:
                return False
            del flow.response.cookies[name]
            return True

        if action == "drop_flow":
            flow.kill()
            return True

        return False

    def apply_response_body_rule(self, flow: http.HTTPFlow, action: str, payload: dict) -> bool:
        if not flow.response:
            return False
        return self.apply_message_body_rule(flow.response, action, payload)

    def apply_message_body_rule(self, message, action: str, payload: dict) -> bool:
        body = message.get_text(strict=False)

        if action == "replace_body_regex":
            src = self.payload_obj(payload, "regex_replace")
            after = re.sub(src.get("regex", ""), str(src.get("replacement", "")), body)
            if after == body:
                return False
            message.set_text(after)
            return True

        if action == "replace_body_literal":
            src = self.payload_obj(payload, "literal_replace")
            find = str(src.get("find", ""))
            replacement = str(src.get("replacement", ""))
            after = body.replace(find, replacement)
            if after == body:
                return False
            message.set_text(after)
            return True

        if action == "set_body":
            src = self.payload_obj(payload, "body")
            after = str(src.get("value", ""))
            if after == body:
                return False
            message.set_text(after)
            return True

        if action == "replace_json_field":
            src = self.payload_obj(payload, "json_field")
            try:
                data = json.loads(body)
                value = json.loads(src.get("value_json", "null"))
            except Exception:
                return False
            changed = self.set_json_path(
                data,
                str(src.get("path", "")),
                value,
                bool(src.get("create_missing", True)),
            )
            if not changed:
                return False
            message.set_text(json.dumps(data))
            return True

        if action in {"replace_form_field", "remove_form_field"}:
            src = self.payload_obj(payload, "form_field")
            name = str(src.get("name", ""))
            if not name:
                return False
            pairs = parse_qsl(body, keep_blank_values=True)
            changed = False
            new_pairs = []
            for k, v in pairs:
                if k != name:
                    new_pairs.append((k, v))
                    continue
                changed = True
                if action == "replace_form_field":
                    new_pairs.append((k, str(src.get("value", ""))))
            if action == "replace_form_field" and not changed:
                new_pairs.append((name, str(src.get("value", ""))))
                changed = True
            if not changed:
                return False
            message.set_text(urlencode(new_pairs, doseq=True))
            return True

        return False

    def set_json_path(self, obj: Any, path: str, value: Any, create_missing: bool) -> bool:
        if not path:
            return False

        normalized = path[2:] if path.startswith("$.") else path
        parts = [p for p in normalized.split(".") if p]
        if not parts:
            return False

        cursor = obj
        for key in parts[:-1]:
            if not isinstance(cursor, dict):
                return False
            if key not in cursor:
                if not create_missing:
                    return False
                cursor[key] = {}
            if not isinstance(cursor[key], dict):
                return False
            cursor = cursor[key]

        leaf = parts[-1]
        before = cursor.get(leaf) if isinstance(cursor, dict) else None
        if not isinstance(cursor, dict):
            return False
        cursor[leaf] = value
        return before != value


addons = [IaraProxyAddon()]
