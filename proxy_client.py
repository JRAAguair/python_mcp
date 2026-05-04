from typing import Any, Dict, List, Optional

import requests


class ProxyControlClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8765"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def health(self) -> Dict[str, Any]:
        resp = self.session.get(f"{self.base_url}/health", timeout=10)
        resp.raise_for_status()
        return resp.json()

    def get_flows(self) -> List[Dict[str, Any]]:
        resp = self.session.get(f"{self.base_url}/flows", timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return data.get("items", [])

    def get_flow(self, flow_id: str) -> Dict[str, Any]:
        resp = self.session.get(f"{self.base_url}/flows/{flow_id}", timeout=20)
        resp.raise_for_status()
        return resp.json().get("item", {})

    def replace_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        resp = self.session.post(
            f"{self.base_url}/rules/replace",
            json={"rules": rules},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()

    def clear_rules(self) -> Dict[str, Any]:
        resp = self.session.post(
            f"{self.base_url}/rules/clear",
            json={},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()
