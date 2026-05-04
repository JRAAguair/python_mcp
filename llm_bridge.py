from inspect import indentsize
import json
import os
import re

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

@dataclass
class LlmConfig:
    base_url: str
    model: str
    api_key: str = ""
    timeout_s: int = 90


class OpenAICompatLLM:
    """
    Cliente mínimo para endpoint OpenAI-compatible em cloud própria.
    Exemplo de BASE_URL:
      http://127.0.0.1:8000/v1
      https://sua-api.exemplo.com/v1
    """

    def __init__(self, config: LlmConfig):
        self.config = config
        self.session = requests.Session()

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def _extract_json(self, text: str) -> Dict[str, Any]:
        text = text.strip()

        # bloco ```json ... ```
        fenced = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            return json.loads(fenced.group(1))

        # primeiro objeto json plausível
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            try:
                return json.loads(text[first:last + 1])
            except json.JSONDecodeError:
                pass

        return {"raw_text": text}

    def chat_json(
        self,
        system_prompt: str,
        user_payload: Dict[str, Any],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1400,
    ) -> Dict[str, Any]:
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(user_payload, ensure_ascii=False, separators=(",", ":")),
                },
            ],
        }

        resp = self.session.post(
            url,
            headers=self._headers(),
            json=payload,
            timeout=self.config.timeout_s,
        )
        resp.raise_for_status()

        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        return self._extract_json(content)
    
    def chat_text(self, system_prompt: str, user_text: str, *, temperature: float = 0.2, max_tokens: int = 1200,) ->str:
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content":system_prompt},
                {"role":"user", "content": user_text},
            ],
        }
        resp = self.session.post(
            url,
            headers= self._headers(),
            json=payload,
            timeout= self.config.timeout_s,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        if isinstance(content, str):
            return content.strip()
        if isinstance(content,list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    text_part = item.get("text")
                    if text_part:
                        parts.append(str(text_part))
            return "\n".join(parts).strip()
        return str(content).strip()
    
    def ask(
        self,
        prompt: str,
        *,
        system_prompt: str = "You are security research assistant. Reply clearly.",
        temperature: float = 0.2,
        max_tokens: int = 1200,
    ) -> str:
        return self.chat_text(
            system_prompt=system_prompt,
            user_text=prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def observe(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        system = """
You are assisting a security research session.
Mode: OBSERVE.
The human is manually browsing.
Do not perform deep analysis yet.
Return compact JSON only.

Schema:
{
  "notes": [string],
  "watch_for": [string],
  "interesting_flow_ids": [string],
  "should_capture_more": boolean,
  "capture_hints": [string]
}
""".strip()

        return self.chat_json(system, observation, temperature=0.15, max_tokens=700)


    def _clip_text(self, value: Any, max_len: int = 500) -> Any:
        if isinstance(value, str) and len(value) > max_len:
            return value[:max_len] + "...[truncated]"
        return value

    def _compact_for_llm(self, obj: Any, *, max_items: int = 20, max_str: int = 500) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in {
                    "html", "dom", "body", "response_body", "request_body",
                    "raw_body", "raw_text", "full_headers", "full_cookies"
                }:
                    continue
                out[k] = self._compact_for_llm(v, max_items=max_items, max_str=max_str)
            return out

        if isinstance(obj, list):
            return [
                self._compact_for_llm(x, max_items=max_items, max_str=max_str)
                for x in obj[:max_items]
            ]

        return self._clip_text(obj, max_len=max_str)



    def finalize(self, report: Dict[str, Any]) -> Dict[str, Any]:
        system = """
You are assisting a security research session.
Mode: FINALIZE.
The browsing phase is over.
Analyze the summarized session and return practical attack ideas.

Return JSON only.

Schema:
{
  "summary": string,
  "priority_vectors": [
    {
      "name": string,
      "why": string,
      "confidence": number,
      "related_flow_ids": [string],
      "suggested_mutations": [string]
    }
  ],
  "top_flow_ids": [string],
  "next_actions": [string]
}
""".strip()
        compact_report = self._compact_for_llm(report, max_items=25, max_str=400)
        return self.chat_json(system, compact_report, temperature=0.2, max_tokens=900)


def load_llm_from_env() -> OpenAICompatLLM:
    base_url = os.getenv("LLM_BASE_URL")
    if not base_url:
        raise RuntimeError("LLM_BASE_URL is not set")
    return OpenAICompatLLM(
        LlmConfig(
            base_url=base_url,
            model=os.getenv("LLM_MODEL", "Qwen2.5-7B-Instruct"),
            api_key=os.getenv("LLM_API_KEY", ""),
            timeout_s=int(os.getenv("LLM_TIMEOUT_S", "90")),
        )
    )
