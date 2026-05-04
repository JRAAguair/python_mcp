import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit


STATIC_EXT_RE = re.compile(
    r"\.(?:css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|mp4|webm|mp3)(?:\?|$)",
    re.IGNORECASE,
)

ID_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
UUID_RE = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?=/|$)",
    re.IGNORECASE,
)

TELEMETRY_HOST_HINTS = (
    "datadoghq.com",
    "google-analytics.com",
    "googletagmanager.com",
    "segment.io",
    "amplitude.com",
    "sentry.io",
    "newrelic.com",
    "mixpanel.com",
    "hotjar.com",
)

TELEMETRY_PATH_HINTS = (
    "/rum",
    "/telemetry",
    "/collect",
    "/track",
    "/analytics",
    "/events",
    "/csp-report",
)


SMALL_LIST_INLINE_LIMIT = 3

METHOD_ENUM = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "PATCH": 3,
    "DELETE": 4,
    "HEAD": 5,
    "OPTIONS": 6,
    "OTHER": 7,
}

FLOW_CLASS_ENUM = {
    "unknown": 0,
    "auth": 1,
    "app_api": 2,
    "graphql": 3,
    "telemetry": 4,
    "csp_report": 5,
}

EVENT_TYPE_ENUM = {
    "unknown": 0,
    "page_checkpoint": 1,
    "flow_matured": 2,
    "proxy_sync": 3,
}

CHANGE_FIELD_BITS = {
    "new_flow": 1 << 0,
    "request_method": 1 << 1,
    "request_url": 1 << 2,
    "request_body": 1 << 3,
    "response_attached": 1 << 4,
    "response_status": 1 << 5,
    "response_headers": 1 << 6,
    "response_body": 1 << 7,
    "intercepted": 1 << 8,
    "mutated": 1 << 9,
    "applied_rule_ids": 1 << 10,
    "mutated_request": 1 << 11,
    "mutated_response": 1 << 12,
    "enrichments": 1 << 13,
    "annotations": 1 << 14,
    "tags": 1 << 15,
}

OBSERVE_CHAR_BUDGET = 7_500
FINALIZE_CHAR_BUDGET = 20_000

MAX_PAGE_SNAPSHOTS = 24
MAX_BROWSER_EVENTS = 120
MAX_NOTE_HISTORY = 12

INLINE_QUERY_KEYS = 6
INLINE_SHAPE_KEYS = 6
INLINE_SURFACES = 3
INLINE_CHANGED_FIELDS = 4
INLINE_GROUPS_OBSERVE = 5
INLINE_GROUPS_FINALIZE = 8

@dataclass
class SessionReducer:
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    page_snapshots: List[Dict[str, Any]] = field(default_factory=list)
    browser_events: List[Dict[str, Any]] = field(default_factory=list)

    flow_by_id: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    flow_summary_by_id: Dict[str, Dict[str,Any]] = field(default_factory=dict)
    flow_signature_by_id: Dict[str, str] = field(default_factory=dict)
    flow_groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)


    llm_observe_notes: List[Dict[str, Any]] = field(default_factory=list)
    working_memory: Dict[str, List[Dict[str, Any]]] = field(
        default_factory=lambda: {
            "working_hypotheses": [],
            "confirmed_findings": [],
            "dead_ends": [],
            "next_best_actions": [],
        }
    )

    _last_timeline_cursor: int = 0
    _last_flow_count: int = 0


    def _json_default(self, value: Any) -> Any:
        if isinstance(value, set):
            return sorted(value)
        return str(value)

    def _estimate_chars(self, value: Any) -> int:
        try:
            return len(json.dumps(value, ensure_ascii=False, default=self._json_default))
        except Exception:
            return len(str(value))

    def _cap_with_overflow(self, values: List[Any], limit: int) -> List[Any]:
        clean = [v for v in values if v not in (None, "", [], {})]
        if len(clean) <= limit:
            return clean
        return clean[:limit] + [f"...+{len(clean) - limit}"]

    def _status_is_error(self, status_code: Any) -> bool:
        try:
            return int(status_code) >= 400
        except Exception:
            return False

    def _enum_method(self, method: Any) -> int:
        if not method:
            return METHOD_ENUM["OTHER"]
        return METHOD_ENUM.get(str(method).upper(), METHOD_ENUM["OTHER"])

    def _enum_flow_class(self, flow_class: Any) -> int:
        if not flow_class:
            return FLOW_CLASS_ENUM["unknown"]
        return FLOW_CLASS_ENUM.get(str(flow_class), FLOW_CLASS_ENUM["unknown"])

    def _enum_event_type(self, event_type: Any) -> int:
        if not event_type:
            return EVENT_TYPE_ENUM["unknown"]
        return EVENT_TYPE_ENUM.get(str(event_type), EVENT_TYPE_ENUM["unknown"])

    def _changed_fields_mask(self, changed_fields: List[str]) -> int:
        mask = 0
        for field_name in changed_fields or []:
            mask |= CHANGE_FIELD_BITS.get(field_name, 0)
        return mask

    def _inline_or_count(self, values: List[Any], *, inline_limit: int = SMALL_LIST_INLINE_LIMIT) -> Any:
        clean = [v for v in (values or []) if v not in (None, "", [], {})]
        if not clean:
            return None
        if len(clean) <= inline_limit:
            return clean
        return len(clean)

    def _omit_empty(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        out = {}
        for key, value in (payload or {}).items():
            if value is None:
                continue
            if value == "":
                continue
            if value == []:
                continue
            if value == {}:
                continue
            out[key] = value
        return out

    def _status_bucket(self, status_code: Any) -> str:
        try:
            code = int(status_code)
        except Exception:
            return "no_response"
        return f"{code // 100}xx"

    def _compact_redirect_location(self, location: str) -> str:
        if not location:
            return ""
        try:
            parts = urlsplit(location)
            host = parts.netloc.lower()
            path = self._normalize_path(parts.path or "")
            if host and path:
                return f"{host}{path}"
            return path or host or location[:120]
        except Exception:
            return location[:120]

    def _summarize_scripts(self, scripts: Any) -> Dict[str, Any]:
        items: List[Any] = []
        if isinstance(scripts, dict):
            items = scripts.get("scripts") or scripts.get("items") or []
        elif isinstance(scripts, list):
            items = scripts

        external_hosts = set()
        inline_count = 0

        for item in items[:300]:
            if not isinstance(item, dict):
                continue
            src = item.get("src") or item.get("url") or ""
            if src:
                try:
                    host = urlsplit(src).netloc.lower()
                except Exception:
                    host = ""
                if host:
                    external_hosts.add(host)
            else:
                inline_count += 1

        count = len(items)
        if isinstance(scripts, dict):
            count = scripts.get("count", count)
            inline_count = scripts.get("inline_count", inline_count)

        return {
            "count": count,
            "inline_count": inline_count,
            "external_hosts": self._cap_with_overflow(sorted(external_hosts), 5),
        }

    def _summarize_cookies(self, cookies: Any) -> Dict[str, Any]:
        items: List[Any] = []
        if isinstance(cookies, dict):
            items = cookies.get("cookies") or cookies.get("items") or []
        elif isinstance(cookies, list):
            items = cookies

        names = []
        interesting = []

        for item in items[:300]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name:
                continue
            names.append(name)

            lname = name.lower()
            if any(x in lname for x in ("session", "sess", "auth", "token", "csrf", "xsrf", "jwt")):
                interesting.append(name)

        chosen = sorted(set(interesting or names))
        return {
            "count": len(items),
            "interesting_names": self._cap_with_overflow(chosen, 8),
        }

    def _extract_storage_keys(self, value: Any) -> List[str]:
        keys = set()

        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, dict):
                    for subk in v.keys():
                        keys.add(str(subk))
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            name = item.get("name") or item.get("key")
                            if name:
                                keys.add(str(name))
                else:
                    keys.add(str(k))

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("key")
                    if name:
                        keys.add(str(name))

        return sorted(keys)

    def _summarize_storage(self, storage: Any) -> Dict[str, Any]:
        storage = storage or {}
        if not isinstance(storage, dict):
            return {
                "local_storage_keys": [],
                "session_storage_keys": [],
            }

        local_raw = (
            storage.get("localStorage")
            or storage.get("local_storage")
            or storage.get("local")
            or {}
        )
        session_raw = (
            storage.get("sessionStorage")
            or storage.get("session_storage")
            or storage.get("session")
            or {}
        )

        local_keys = self._extract_storage_keys(local_raw)
        session_keys = self._extract_storage_keys(session_raw)

        return {
            "local_storage_keys": self._cap_with_overflow(local_keys, 8),
            "session_storage_keys": self._cap_with_overflow(session_keys, 8),
        }

    def _compact_page_snapshot(
        self,
        *,
        reason: str,
        page_info: Optional[Dict[str, Any]] = None,
        scripts: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, Any]] = None,
        storage: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        page_info = page_info or {}

        return {
            "reason": reason,
            "page_info": {
                "url": page_info.get("url") or page_info.get("current_url"),
                "title": page_info.get("title"),
                "forms": page_info.get("forms_count"),
                "inputs": page_info.get("inputs_count"),
                "buttons": page_info.get("buttons_count"),
            },
            "scripts": self._summarize_scripts(scripts),
            "cookies": self._summarize_cookies(cookies),
            "storage": self._summarize_storage(storage),
        }

    def _compact_browser_payload(self, payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload

        compact: Dict[str, Any] = {}
        direct_keys = (
            "url",
            "title",
            "status",
            "reason",
            "method",
            "action",
            "selector",
            "ok",
            "error",
            "forms_count",
            "inputs_count",
            "buttons_count",
            "request_count",
            "xhr_count",
            "fetch_count",
        )

        for key in direct_keys:
            value = payload.get(key)
            if value not in (None, "", [], {}):
                compact[key] = value

        if "scripts" in payload:
            compact["scripts"] = self._summarize_scripts(payload.get("scripts"))

        if "cookies" in payload:
            compact["cookies"] = self._summarize_cookies(payload.get("cookies"))

        if "storage" in payload:
            compact["storage"] = self._summarize_storage(payload.get("storage"))

        if not compact:
            compact = {
                "keys": self._cap_with_overflow(sorted(payload.keys()), 10),
                "key_count": len(payload),
            }

        return compact

    def _compact_browser_event_message(self, event_msg: Dict[str, Any]) -> Dict[str, Any]:
        payload = event_msg.get("payload", {}) or {}
        return {
            "type": event_msg.get("event", event_msg.get("type", "unknown")),
            "timestamp": event_msg.get("timestamp"),
            "payload": self._compact_browser_payload(payload),
        }

    def _flow_group_signature(self, summary: Dict[str, Any]) -> str:
        return "::".join(
            [
                str(summary.get("flow_class") or "unknown"),
                str(summary.get("method") or "UNKNOWN"),
                str(summary.get("host") or "unknown"),
                str(summary.get("normalized_path") or summary.get("path") or "unknown"),
                str(summary.get("status_bucket") or "no_response"),
            ]
        )

    def _rebuild_flow_group(self, signature: str) -> None:
        group = self.flow_groups.get(signature)
        if not group:
            return

        member_flow_ids = set(group.get("member_flow_ids", set()))
        summaries = [
            self.flow_summary_by_id[fid]
            for fid in member_flow_ids
            if fid in self.flow_summary_by_id
        ]

        if not summaries:
            self.flow_groups.pop(signature, None)
            return

        best = sorted(
            summaries,
            key=lambda s: (s.get("score", 0), s.get("response_length") or 0),
            reverse=True,
        )[0]

        query_keys = sorted(
            {
                key
                for summary in summaries
                for key in summary.get("query_param_keys_full", [])
                if isinstance(key, str)
            }
        )
        request_shape = sorted(
            {
                key
                for summary in summaries
                for key in summary.get("request_shape_full", [])
                if isinstance(key, str)
            }
        )
        surfaces = sorted(
            {
                key
                for summary in summaries
                for key in summary.get("surfaces_full", [])
                if isinstance(key, str)
            }
        )

        response_lengths: list[int] = []
        for summary in summaries:
            value = summary.get("response_length")
            if isinstance(value, int):
                response_lengths.append(value)

        self.flow_groups[signature] = {
            "flow_class": best.get("flow_class"),
            "method": best.get("method"),
            "host": best.get("host"),
            "normalized_path": best.get("normalized_path") or best.get("path"),
            "status_code": best.get("status_code"),
            "status_bucket": best.get("status_bucket"),
            "count": len(summaries),
            "sample_flow_id": best.get("flow_id"),

            "query_param_keys": query_keys,
            "request_shape": request_shape,
            "surfaces": surfaces,

            "max_score": int(best.get("score", 0) or 0),
            "has_set_cookie": any(summary.get("has_set_cookie") for summary in summaries),
            "is_auth_related": any(summary.get("is_auth_related") for summary in summaries),
            "response_length": max(response_lengths) if response_lengths else None,

            "member_flow_ids": member_flow_ids,
        }

    def _upsert_flow_group(self, signature: str, flow_id: str) -> None:
        group = self.flow_groups.setdefault(signature, {"member_flow_ids": set()})
        group.setdefault("member_flow_ids", set()).add(flow_id)
        self._rebuild_flow_group(signature)

    def _discard_flow_from_group(self, signature: str, flow_id: str) -> None:
        group = self.flow_groups.get(signature)
        if not group:
            return

        member_flow_ids = set(group.get("member_flow_ids", set()))
        member_flow_ids.discard(flow_id)

        if not member_flow_ids:
            self.flow_groups.pop(signature, None)
            return

        group["member_flow_ids"] = member_flow_ids
        self._rebuild_flow_group(signature)

    def _public_flow_group(self, group: Dict[str, Any]) -> Dict[str, Any]:
        qp = self._inline_or_count(group.get("query_param_keys", []))
        rs = self._inline_or_count(group.get("request_shape", []))
        sf = self._inline_or_count(group.get("surfaces", []))

        payload = {
            "id": group.get("sample_flow_id"),
            "fc": self._enum_flow_class(group.get("flow_class")),
            "m": self._enum_method(group.get("method")),
            "p": group.get("normalized_path"),
            "sc": group.get("status_code"),
            "n": group.get("count"),
            "s": int(group.get("max_score", 0) or 0),
            "rl": group.get("response_length"),
            "qp": qp,
            "rs": rs,
            "sf": sf,
            "ck": 1 if group.get("has_set_cookie") else None,
            "ar": 1 if group.get("is_auth_related") else None,
        }
        return self._omit_empty(payload)

    def _append_memory_item(self, bucket: str, item: Dict[str, Any], limit: int = 6) -> None:
        current = self.working_memory.setdefault(bucket, [])
        item_key = json.dumps(item, ensure_ascii=False, sort_keys=True)

        deduped = []
        seen = {item_key}

        deduped.append(item)
        for existing in current:
            existing_key = json.dumps(existing, ensure_ascii=False, sort_keys=True)
            if existing_key in seen:
                continue
            seen.add(existing_key)
            deduped.append(existing)

        self.working_memory[bucket] = deduped[:limit]

    def _merge_note_into_working_memory(self, note: Dict[str, Any]) -> None:
        note_type = str(note.get("type") or "").lower()

        record = {
            "finding": note.get("finding"),
            "flow_id": note.get("flow_id"),
            "severity": note.get("severity"),
        }
        record = {k: v for k, v in record.items() if v not in (None, "", [], {})}

        if record:
            if note_type in {"confirmed", "confirmed_finding", "finding", "vuln", "signal"}:
                self._append_memory_item("confirmed_findings", record)
            elif note_type in {"dead_end", "discarded", "false_positive", "no_issue"}:
                self._append_memory_item("dead_ends", record)
            else:
                self._append_memory_item("working_hypotheses", record)

        next_action = note.get("next_action")
        if next_action:
            self._append_memory_item(
                "next_best_actions",
                {
                    "next_action": next_action,
                    "flow_id": note.get("flow_id"),
                },
            )

    def _working_memory_summary(self) -> Dict[str, Any]:
        return {
            "working_hypotheses": self.working_memory.get("working_hypotheses", [])[:4],
            "confirmed_findings": self.working_memory.get("confirmed_findings", [])[:4],
            "dead_ends": self.working_memory.get("dead_ends", [])[:4],
            "next_best_actions": self.working_memory.get("next_best_actions", [])[:4],
        }

    def _filter_events_covered_by_groups(
        self,
        events: List[Dict[str, Any]],
        covered_flow_ids: set,
    ) -> List[Dict[str, Any]]:
        if not covered_flow_ids:
            return events

        filtered = []
        for ev in events:
            payload = ev.get("payload") or {}
            flow_id = payload.get("id") if isinstance(payload, dict) else None

            if ev.get("type") == "flow_matured" and flow_id in covered_flow_ids:
                continue

            filtered.append(ev)

        return filtered

    def _fit_payload_to_budget(self, payload: Dict[str, Any], *, mode: str) -> Dict[str, Any]:
        budget = OBSERVE_CHAR_BUDGET if mode == "observe" else FINALIZE_CHAR_BUDGET
        out = json.loads(json.dumps(payload, ensure_ascii=False, default=self._json_default))

        if self._estimate_chars(out) <= budget:
            return out

        flow_key = "interesting_flows" if mode == "observe" else "top_flows"

        for flow in out.get(flow_key, []):
            for key in ("qp", "rs", "sf"):
                value = flow.get(key)
                if isinstance(value, list) and len(value) > 2:
                    flow[key] = len(value)

        if self._estimate_chars(out) <= budget:
            return out

        if flow_key in out:
            out[flow_key] = out[flow_key][: (3 if mode == "observe" else 5)]

        if self._estimate_chars(out) <= budget:
            return out

        if "new_events" in out:
            out["new_events"] = out["new_events"][-6:]

        if self._estimate_chars(out) <= budget:
            return out

        if "llm_memory" in out and isinstance(out["llm_memory"], dict):
            for key, value in list(out["llm_memory"].items()):
                if isinstance(value, list):
                    out["llm_memory"][key] = value[:2]

        if self._estimate_chars(out) <= budget:
            return out

        out.pop("suppressed_summary", None)
        return out


    def ingest_browser_event(self, event_msg: Dict[str, Any]) -> None:
        event = self._compact_browser_event_message(event_msg)
        self.browser_events.append(event)
        self.browser_events = self.browser_events[-MAX_BROWSER_EVENTS:]
        self.timeline.append(event)

    def ingest_page_checkpoint(
        self,
        *,
        reason: str,
        page_info: Optional[Dict[str, Any]] = None,
        scripts: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, Any]] = None,
        storage: Optional[Dict[str, Any]] = None,
    ) -> None:
        snap = self._compact_page_snapshot(
            reason = reason,
            page_info = page_info,
            scripts = scripts,
            cookies=cookies,
            storage = storage,
        )
        self.page_snapshots.append(snap)
        self.page_snapshots = self.page_snapshots[-MAX_PAGE_SNAPSHOTS:]

        self.timeline.append(
            {
                "type": "page_checkpoint",
                "payload":{
                    "reason": reason,
                    "url": snap.get("page_info", {}).get("url"),
                    "title": snap.get("page_info",{}).get("title"),
                    "forms": snap.get("page_info", {}).get("forms"),
                    "inputs": snap.get("page_info", {}).get("inputs"),
                    "buttons": snap.get("page_info", {}).get("buttons"),
                    "script_count": snap.get("scripts", {}).get("count"),
                    "cookie_names": snap.get("cookies", {}).get("interesting_names", []),
                },
            }
        )

    def ingest_proxy_flows(self, flows: List[Dict[str, Any]]) -> None:
        changed = False
        touched_signatures = set()

        for flow in flows:
            flow_id = flow.get("id")
            if not flow_id:
                continue

            prev_flow = self.flow_by_id.get(flow_id)
            prev_signature = self.flow_signature_by_id.get(flow_id)

            self.flow_by_id[flow_id] = flow
            
            if prev_flow is None:
                changed_fields = ["new_flow"]

            else:
                changed_fields = self._flow_update_fields(prev_flow, flow)
                if not changed_fields:
                    continue
            
            summary = self._summarize_flow(flow)
            signature = self._flow_group_signature(summary)

            self.flow_summary_by_id[flow_id] = summary
            self.flow_signature_by_id[flow_id] = signature

            if prev_signature and prev_signature != signature:
                self._discard_flow_from_group(prev_signature, flow_id)

            self._upsert_flow_group(signature, flow_id)

            changed = True
            touched_signatures.add(signature)

            self.timeline.append(
                {
                    "type": "flow_matured",
                    "payload": {
                        "id": flow_id,
                        "group_signature": signature,
                        "method": summary.get("method"),
                        "path": summary.get("path"),
                        "normalized_path": summary.get("normalized_path"),
                        "changed_fields": changed_fields,
                        "status_code": summary.get("status_code"),
                        "flow_class": summary.get("flow_class"),
                        "response_length": summary.get("response_length"),
                        "surfaces": summary.get("surfaces_full"),
                        "score": summary.get("score"),
                    },
                }
            )
        if changed:
            self.timeline.append(
                {
                    "type": "proxy_sync",
                    "payload": {
                        "total_flows": len(self.flow_by_id),
                        "touched_groups":len(touched_signatures),
                    },
                }
            )

    def add_observe_note(self, note: Dict[str, Any]) -> None:
        compact = self._compact_note(note)
        
        self.llm_observe_notes.append(compact)
        self.llm_observe_notes = self.llm_observe_notes[-MAX_NOTE_HISTORY:]

        self._merge_note_into_working_memory(compact)


    def _latest_page_summary(self) -> Dict[str, Any]:
        if not self.page_snapshots:
            return {}
        
        snap = self.page_snapshots[-1]
        page_info = snap.get("page_info") or {}
        scripts = snap.get("scripts") or {}
        cookies = snap.get("cookies") or {}
        storage = snap.get("storage") or {}
        
        storage_keys = []
        storage_keys.extend(storage.get("local_storage_keys",[]))
        storage_keys.extend(storage.get("session_storage_keys", []))

        clean_storage_keys = [
            key for key in storage_keys
            if isinstance(key, str) and not key.startswith("...+")
        ]

        return {
            "reason": snap.get("reason"),
            "url": page_info.get("url"),
            "title": page_info.get("title"),
            "forms": page_info.get("forms"),
            "inputs": page_info.get("inputs"),
            "buttons": page_info.get("buttons"),
            "script_count": scripts.get("count"),
            "cookie_names": cookies.get("interesting_names", []),
            "storage_keys": self._cap_with_overflow(sorted(set(clean_storage_keys)), 6),
        }

    def _normalize_path(self, path: str) -> str:
        out = UUID_RE.sub("/{uuid}", path or "")
        out = ID_SEGMENT_RE.sub("/{id}", out)
        return out

    def _extract_json_shape(self, body: str) -> List[str]:
        if not body:
            return []
        try:
            data = json.loads(body)
        except Exception:
            return []
        if isinstance(data, dict):
            return sorted(list(data.keys()))[:20]
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return sorted(list(data[0].keys()))[:20]
        return []

    def _extract_form_shape(self, body: str) -> List[str]:
        if not body or "=" not in body:
            return []
        keys = []
        for pair in body.split("&"):
            if "=" in pair:
                keys.append(pair.split("=", 1)[0])
        return sorted(list(set(keys)))[:20]

    def _headers_lower(self, headers: Optional[Dict[str,Any]])->Dict[str,str]:
        return {str(k).lower():str(v) for k, v in (headers or{}).items()}
    
    def _query_param_keys(self, url:str)->List[str]:
        if not url:
            return[]
        try:
            pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
            return sorted({k for k, _ in pairs if k})[:30]
        except Exception:
            return[]
        
    def _response_length(self, response: Dict[str,Any]) -> Optional[int]:
        headers = self._headers_lower(response.get("headers"))
        raw_len = headers.get("content-length")
        if raw_len:
            try:
                return int(raw_len)
            except Exception:
                pass
        body = response.get("body")
        if body is None:
            return None
        if isinstance(body, (bytes, bytearray)):
            return len(body)
        if isinstance(body, str):
            return len(body.encode("utf-8"))
        try:
            return len(json.dumps(body))
        except Exception:
            return None
        
    def _is_auth_related(self, flow: Dict[str, Any]) -> bool:
        req = flow.get("original_request", {}) or {}
        res = flow.get("original_response", {}) or {}

        req_headers = self._headers_lower(req.get("headers"))
        res_headers = self._headers_lower(res.get("headers"))

        haystack = " ".join(
            [
                str(req.get("url") or ""),
                str(flow.get("path") or""),
                str(req.get("body") or ""),
                str(res_headers.get("location") or ""),
            ]
        ).lower()

        auth_markers = [
            "login", "logout", "signin", "sign-in", "signup", "sign-up",
            "register", "auth", "oauth", "token", "session", "password",
            "reset", "forgot", "mfa", "2fa", "opt", "sso",
        ]

        if any(marker in haystack for marker in auth_markers):
            return True
        
        if "authorization" in req_headers:
            return True
        if "cookies" in req_headers:
            return True
        if "set-cookie" in res_headers:
            return True
        if "www-authenticate" in res_headers:
            return True
        return False
    
    def _flow_update_fields(
            self,
            prev: Dict[str, Any],
            curr: Dict[str, Any],
    )-> List[str]:
        changed = []

        prev_req = prev.get("original_request", {}) or {}
        curr_req = curr.get("original_request", {}) or {}
        prev_res = prev.get("original_response", {}) or {}
        curr_res = curr.get("original_response", {}) or {}

        if prev_req.get("method") != curr_req.get("method"):
            changed.append("request_method")
        if prev_req.get("url") != curr_req.get("url"):
            changed.append("request_url")
        if prev_req.get("body") != curr_req.get("body"):
            changed.append("request_body")

        if not prev_res and curr_res:
            changed.append("response_attached")
        
        elif prev_res and curr_res:
            if prev_res.get("status_code") != curr_res.get("status_code"):
                changed.append("response_status")
            if prev_res.get("headers") != curr_res.get("headers"):
                changed.append("response_headers")
            if prev_res.get("body") != curr_res.get("body"):
                changed.append("response_body")

        if prev.get("intercepted") != curr.get("intercepted"):
            changed.append("intercepted")

        if prev.get("mutated") != curr.get("mutated"):
            changed.append("mutated")
        
        if prev.get("applied_rule_ids") != curr.get("applied_rule_ids"):
            changed.append("applied_rule_ids")

        if prev.get("mutated_request") != curr.get("mutated_request"):
            changed.append("mutated_request")

        if prev.get("mutated_response") != curr.get("mutated_response"):
            changed.append("mutated_response")

        for extra_key in ("enrichments", "annotations", "tags"):
            if prev.get(extra_key) != curr.get(extra_key):
                changed.append(extra_key)
        return changed

    def _flow_host(self, flow: Dict[str, Any]) -> str:
        req = flow.get("original_request", {}) or {}
        url = req.get("url") or ""
        try:
            return (urlsplit(url).netloc or "").lower()
        except Exception:
            return ""

    def _looks_like_telemetry(self, flow: Dict[str, Any]) -> bool:
        req = flow.get("original_request", {}) or {}
        url = (req.get("url") or "").lower()
        path = (flow.get("path") or "").lower()
        host = self._flow_host(flow)

        if any(h in host for h in TELEMETRY_HOST_HINTS):
            return True
        if any(h in url for h in TELEMETRY_HOST_HINTS):
            return True
        if any(p in path for p in TELEMETRY_PATH_HINTS):
            return True
        if any(p in url for p in TELEMETRY_PATH_HINTS):
            return True
        return False

    def _classify_flow(self, flow: Dict[str, Any]) -> str:
        req = flow.get("original_request", {}) or {}
        res = flow.get("original_response", {}) or {}

        req_headers = self._headers_lower(req.get("headers"))
        res_headers = self._headers_lower(res.get("headers"))
        content_type = req_headers.get("content-type", "").lower()

        if self._looks_like_telemetry(flow):
            return "telemetry"
        if "csp-report" in content_type:
            return "csp_report"
        if self._is_auth_related(flow):
            return "auth"
        if "graphql" in (req.get("url") or "").lower():
            return "graphql"
        if "application/json" in content_type:
            return "app_api"
        if "set-cookie" in res_headers:
            return "auth"
        return "unknown"

    def _should_surface_flow(self, flow: Dict[str, Any], summary: Optional[Dict[str, Any]] = None) -> bool:
        summary = summary or self._summarize_flow(flow)
        cls = summary.get("flow_class")
        status_code = summary.get("status_code")

        if cls in {"auth", "graphql", "app_api", "unknown"}:
            return True

        if self._status_is_error(status_code):
            return True
        if summary.get("has_set_cookie"):
            return True
        if summary.get("is_auth_related") and cls != "telemetry":
            return True

        if cls in {"telemetry", "csp_report"}:
            return False

        return True

    def _suppressed_group_key(self, summary: Dict[str, Any]) -> str:
        return f'{summary.get("flow_class")}::{summary.get("normalized_path") or summary.get("path") or "unknown"}'


    def _compact_event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        ev_type = ev.get("type")
        payload = ev.get("payload") or {}

        compact = {
            "t": self._enum_event_type(ev_type),
            "ts": ev.get("timestamp"),
        }

        if not isinstance(payload, dict):
            compact["p"] = payload
            return self._omit_empty(compact)

        if ev_type == "flow_matured":
            sf = self._inline_or_count(payload.get("surfaces", []))

            compact["p"] = self._omit_empty(
                {
                    "id": payload.get("id"),
                    "fc": self._enum_flow_class(payload.get("flow_class")),
                    "m": self._enum_method(payload.get("method")),
                    "p": payload.get("normalized_path") or payload.get("path"),
                    "sc": payload.get("status_code"),
                    "cf": self._changed_fields_mask(payload.get("changed_fields", [])),
                    "sf": sf,
                    "rl": payload.get("response_length"),
                    "s": int(payload.get("score", 0) or 0),
                }
            )
            return self._omit_empty(compact)

        if ev_type == "proxy_sync":
            compact["p"] = self._omit_empty(
                {
                    "tf": payload.get("total_flows"),
                    "tg": payload.get("touched_groups"),
                }
            )
            return self._omit_empty(compact)

        if ev_type == "page_checkpoint":
            compact["p"] = self._omit_empty(
                {
                    "r": payload.get("reason"),
                    "u": payload.get("url"),
                    "tt": payload.get("title"),
                }
            )
            return self._omit_empty(compact)

        compact["p"] = payload
        return self._omit_empty(compact)


    def _compact_note(self, note: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(note, dict):
            return {"value": note}

        return {
            "type": note.get("type"),
            "finding": note.get("finding") or note.get("summary") or note.get("note"),
            "flow_id": note.get("flow_id"),
            "severity": note.get("severity"),
            "next_action": note.get("next_action"),
        }

    def _summarize_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        req = flow.get("original_request", {}) or {}
        res = flow.get("original_response", {}) or {}

        req_body = req.get("body") or ""
        req_headers = self._headers_lower(req.get("headers"))
        res_headers = self._headers_lower(res.get("headers"))

        request_content_type = req_headers.get("content-type", "")
        response_content_type = res_headers.get("content-type", "")
        redirect_location = res_headers.get("location", "")
        has_set_cookie = "set-cookie" in res_headers
        is_auth_related = self._is_auth_related(flow)

        status_code = res.get("status_code")

        query_param_keys_full = self._query_param_keys(req.get("url") or "")

        request_shape_full: List[str] = []
        if "application/json" in request_content_type.lower():
            request_shape_full = self._extract_json_shape(req_body)[:20]
        elif "application/x-www-form-urlencoded" in request_content_type.lower():
            request_shape_full = self._extract_form_shape(req_body)[:20]

        surfaces_full = self._surface_tags(flow)

        host = self._flow_host(flow)
        flow_class = self._classify_flow(flow)
        normalized_path = self._normalize_path(flow.get("path", ""))
        response_length = self._response_length(res)

        return {
            "flow_id": flow.get("id"),
            "method": req.get("method"),
            "path": flow.get("path"),
            "normalized_path": normalized_path,
            "status_code": status_code,
            "status_bucket": self._status_bucket(status_code),

            "request_content_type": request_content_type.split(";", 1)[0].strip(),
            "response_content_type": response_content_type.split(";", 1)[0].strip(),

            "request_shape": self._cap_with_overflow(request_shape_full, INLINE_SHAPE_KEYS),
            "request_shape_count": len(request_shape_full),

            "query_param_keys_full": query_param_keys_full,
            "request_shape_full": request_shape_full,
            "surfaces_full": surfaces_full,

            "response_length": response_length,
            "redirect_location": self._compact_redirect_location(redirect_location),
        
            "is_auth_related": is_auth_related,
            "has_set_cookie": has_set_cookie,

            "score": self._score_flow(flow),

            "host": host,
            "flow_class": flow_class,
            "suppressed_by_default": flow_class in {"telemetry", "csp_report"},
        }


    def _aggregate_similar_flows(self, summaries: List[Dict[str, Any]], *, top_n: int = 5) -> List[Dict[str, Any]]:
        grouped: Dict[str, Dict[str, Any]] = {}

        for summary in summaries:
            key = "::".join([
                str(summary.get("flow_class") or "unknown"),
                str(summary.get("method") or "UNKNOWN"),
                str(summary.get("host") or "unknown"),
                str(summary.get("normalized_path") or summary.get("path") or "unknown"),
                str(summary.get("status_code")),
            ])

            group = grouped.get(key)
            if group is None:
                grouped[key] = {
                    "flow_class": summary.get("flow_class"),
                    "method": summary.get("method"),
                    "host": summary.get("host"),
                    "path": summary.get("path"),
                    "normalized_path": summary.get("normalized_path"),
                    "status_code": summary.get("status_code"),
                    "count": 1,
                    "sample_flow_id": summary.get("flow_id"),
                    "query_param_keys": list(summary.get("query_param_keys", []))[:10],
                    "request_shape": list(summary.get("request_shape", []))[:8],
                    "surfaces": list(summary.get("surfaces", [])),
                    "max_score": summary.get("score", 0),
                    "has_error": bool(summary.get("is_error")),
                    "has_set_cookie": bool(summary.get("has_set_cookie")),
                }
                continue

            group["count"] += 1
            group["max_score"] = max(group.get("max_score", 0), summary.get("score", 0))
            group["has_error"] = group["has_error"] or bool(summary.get("is_error"))
            group["has_set_cookie"] = group["has_set_cookie"] or bool(summary.get("has_set_cookie"))

            merged_q = sorted(set(group.get("query_param_keys", [])) | set(summary.get("query_param_keys", [])))
            merged_shape = sorted(set(group.get("request_shape", [])) | set(summary.get("request_shape", [])))
            merged_surfaces = sorted(set(group.get("surfaces", [])) | set(summary.get("surfaces", [])))

            group["query_param_keys"] = merged_q[:10]
            group["request_shape"] = merged_shape[:8]
            group["surfaces"] = merged_surfaces

        return sorted(
            grouped.values(),
            key=lambda x: (x.get("max_score", 0), x.get("count", 0)),
            reverse=True,
        )[:top_n]

    def _build_suppressed_summary(self, summaries: List[Dict[str, Any]]) -> Dict[str, Any]:
        class_counter = Counter()
        host_counter = Counter()
        signature_counter = Counter()

        for summary in summaries:
            class_counter[summary.get("flow_class") or "unknown"] += 1
            host = summary.get("host") or "unknown"
            host_counter[host] += 1
            signature_counter[self._suppressed_group_key(summary)] += 1

        return {
            "suppressed_by_class": dict(class_counter),
            "top_suppressed_hosts": [host for host, _ in host_counter.most_common(5)],
            "top_suppressed_signatures": [
                {"signature": sig, "count": count}
                for sig, count in signature_counter.most_common(5)
            ],
        }

    def _surface_tags(self, flow: Dict[str, Any]) -> List[str]:
        req = flow.get("original_request", {}) or {}
        url = (req.get("url") or "").lower()
        body = req.get("body") or ""
        headers = {k.lower(): str(v).lower() for k, v in (req.get("headers") or {}).items()}
        content_type = headers.get("content-type", "")
        tags = []

        if any(x in url for x in ["admin", "role", "permission"]):
            tags.append("authz")
        if any(x in url for x in ["user", "account", "profile", "order", "invoice"]):
            tags.append("idor")
        if "application/json" in content_type:
            tags.append("json_api")
        if "multipart/form-data" in content_type:
            tags.append("upload")
        if re.search(r"\b(role|is_admin|permission|user_id|account_id)\b", body, re.IGNORECASE):
            tags.append("mass_assignment")
        if any(h in headers for h in ["x-forwarded-for", "x-forwarded-host", "x-original-url"]):
            tags.append("header_trust")

        return sorted(list(set(tags)))

    def _score_flow(self, flow: Dict[str, Any]) -> int:
        req = flow.get("original_request", {}) or {}
        method = (req.get("method") or "").upper()
        url = req.get("url") or ""
        headers = {k.lower(): str(v).lower() for k, v in (req.get("headers") or {}).items()}
        body = req.get("body") or ""
        score = 0.0

        flow_class = self._classify_flow(flow)
        if flow_class == "telemetry":
            score -= 5.0
        if flow_class == "csp_report":
            score -= 3.0

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            score += 3.0
        if "application/json" in headers.get("content-type", ""):
            score += 2.0
        if "multipart/form-data" in headers.get("content-type", ""):
            score += 2.0
        if any(x in url.lower() for x in ["admin", "api", "graphql", "upload", "export", "user", "role"]):
            score += 2.0
        if body:
            score += 1.0
        if flow.get("has_websocket"):
            score += 1.0
        if flow.get("intercepted") or flow.get("mutated"):
            score += 1.5
        score += 0.5 * len(self._surface_tags(flow))
        return int(round(score))

    def build_light_observation(self, *, consume: bool = True) -> Optional[Dict[str, Any]]:
        new_timeline = self.timeline[self._last_timeline_cursor :]
        flow_ids = list(self.flow_summary_by_id.keys())
        new_flow_ids = flow_ids[self._last_flow_count :]

        touched_signatures: List[str] = []
        suppressed_summaries: List[Dict[str, Any]] = []

        for ev in new_timeline:
            if ev.get("type") != "flow_matured":
                continue

            payload = ev.get("payload") or {}
            signature = payload.get("group_signature")
            if signature and signature not in touched_signatures:
                touched_signatures.append(signature)

            flow_id = payload.get("id")
            if flow_id:
                summary = self.flow_summary_by_id.get(flow_id)
                flow = self.flow_by_id.get(flow_id, {})
                if summary and not self._should_surface_flow(flow, summary):
                    suppressed_summaries.append(summary)

        for flow_id in new_flow_ids[-12:]:
            summary = self.flow_summary_by_id.get(flow_id)
            flow = self.flow_by_id.get(flow_id, {})
            signature = self.flow_signature_by_id.get(flow_id)

            if not summary or not signature:
                continue

            if self._should_surface_flow(flow, summary):
                if signature not in touched_signatures:
                    touched_signatures.append(signature)
            else:
                suppressed_summaries.append(summary)

        if not new_timeline and not touched_signatures:
            return None

        interesting_flows = []
        covered_flow_ids = set()

        for signature in touched_signatures:
            group = self.flow_groups.get(signature)
            if not group:
                continue

            public_group = self._public_flow_group(group)
            interesting_flows.append(public_group)
            covered_flow_ids.update(group.get("member_flow_ids", set()))

        interesting_flows = sorted(
            interesting_flows,
            key=lambda x: (x.get("s", 0), x.get("n", 0)),
            reverse=True,
        )[:INLINE_GROUPS_OBSERVE]

        compact_events = [self._compact_event(ev) for ev in new_timeline[-12:]]
        compact_events = self._filter_events_covered_by_groups(compact_events, covered_flow_ids)[-8:]

        payload = {
            "mode": "observe",
            "page": self._latest_page_summary(),
            "new_events": compact_events,
            "interesting_flows": interesting_flows,
            "suppressed_summary": self._build_suppressed_summary(suppressed_summaries),
            "llm_memory": self._working_memory_summary(),
        }

        payload = self._fit_payload_to_budget(payload, mode="observe")

        if consume:
            self._last_timeline_cursor = len(self.timeline)
            self._last_flow_count = len(flow_ids)

        return payload

    def build_finalize_report(self) -> Dict[str, Any]:
        method_counter = Counter()
        surfaces_counter = Counter()
        suppressed_flows = []

        for flow_id, summary in self.flow_summary_by_id.items():
            method_counter[summary.get("method") or "UNKNOWN"] += 1

            for tag in summary.get("surfaces_full", []):
                if isinstance(tag, str) and tag.startswith("...+"):
                    continue
                surfaces_counter[tag] += 1

            flow = self.flow_by_id.get(flow_id, {})
            if not self._should_surface_flow(flow, summary):
                suppressed_flows.append(summary)

        top_flows = []
        for group in self.flow_groups.values():
            sample_flow_id = group.get("sample_flow_id")
            if not sample_flow_id:
                continue

            sample_summary = self.flow_summary_by_id.get(sample_flow_id)
            sample_flow = self.flow_by_id.get(sample_flow_id, {})

            if not sample_summary:
                continue

            if self._should_surface_flow(sample_flow, sample_summary):
                top_flows.append(self._public_flow_group(group))

        top_flows = sorted(
            top_flows,
            key=lambda x: (x.get("s", 0), x.get("n", 0)),
            reverse=True,
        )[:INLINE_GROUPS_FINALIZE]

        payload = {
            "mode": "finalize",
            "suppressed_summary": self._build_suppressed_summary(suppressed_flows),
            "suppressed_flows_count": len(suppressed_flows),
            "session_summary": {
                "pages_captured": len(self.page_snapshots),
                "timeline_events": len(self.timeline),
                "flows_seen": len(self.flow_by_id),
                "method_distribution": dict(method_counter),
                "surface_distribution": dict(surfaces_counter),
                "latest_page": self._latest_page_summary(),
            },
            "top_flows": top_flows,
            "llm_memory": self._working_memory_summary(),
        }

        return self._fit_payload_to_budget(payload, mode="finalize")
