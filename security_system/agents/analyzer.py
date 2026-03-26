"""
ANALYZER AGENT
──────────────
Takes raw payload results from the Attacker Agent and asks
Gemini to determine which responses are actual vulnerabilities.

Gemini reads the response body and decides:
  - Was the payload reflected unescaped?
  - Did the DB leak its structure via error messages?
  - Did we get data we should not have access to?
"""

import json

from security_system.ai_client import call_ai
from security_system.models import PayloadResult, Vulnerability, Severity


class AnalyzerAgent:
    """
    Analyses raw payload results using Gemini AI.

    For each group of results on the same endpoint+parameter, it sends
    Gemini the payload + response and asks: "Is this a real vulnerability?"
    """

    # ── Public ────────────────────────────────────────────────────────────────
    def run(self, results: list[PayloadResult]) -> list[Vulnerability]:
        """Analyse all payload results and return confirmed vulnerabilities."""
        print(f"\n[ANALYZER] Analysing {len(results)} payload results with Gemini...")

        vulnerabilities: list[Vulnerability] = []

        # Group by endpoint + parameter to reduce API calls
        batches = self._group_results(results)

        for (endpoint, param), batch in batches.items():
            print(f"[ANALYZER]   Checking {len(batch)} results — {endpoint}  param={param}")
            vulns = self._analyze_batch(endpoint, param, batch)
            vulnerabilities.extend(vulns)

        # Check for structural issues (admin panel, exposed API, etc.)
        structural = self._check_structural_issues(results)
        vulnerabilities.extend(structural)

        # Deduplicate by title + endpoint
        seen   = set()
        unique = []
        for v in vulnerabilities:
            key = (v.title, v.endpoint)
            if key not in seen:
                seen.add(key)
                unique.append(v)

        print(f"[ANALYZER] Found {len(unique)} unique vulnerabilities.\n")
        return unique

    # ── Private ───────────────────────────────────────────────────────────────
    def _group_results(
        self, results: list[PayloadResult]
    ) -> dict[tuple[str, str], list[PayloadResult]]:
        groups: dict = {}
        for r in results:
            key = (r.endpoint, r.parameter)
            groups.setdefault(key, []).append(r)
        return groups

    def _analyze_batch(
        self, endpoint: str, param: str, batch: list[PayloadResult]
    ) -> list[Vulnerability]:
        """Ask Gemini to analyse a batch of results for one endpoint+param."""

        results_summary = []
        for r in batch:
            results_summary.append({
                "payload":       r.payload,
                "type":          r.payload_type,
                "status":        r.response_status,
                "response_peek": r.response_body[:800],
            })

        prompt = f"""You are a security vulnerability analyzer for an educational pen-testing project.
Analyze these web application test results and identify real vulnerabilities.

Endpoint: {endpoint}
Parameter: {param}
Method: {batch[0].method if batch else 'GET'}

Test results:
{json.dumps(results_summary, indent=2)}

Signs of a REAL vulnerability:
- SQL injection: DB error messages, unexpected data returned, login bypassed with SQLi payload
- XSS: the exact script/payload is reflected back in the HTML without escaping
- Path traversal: actual file contents returned (e.g. /etc/passwd lines, Python source code)
- Auth bypass: HTTP 200 on a protected page reached without real credentials
- IDOR: another user's private data is returned when you change the ID
- Info disclosure: plaintext passwords, tokens, internal paths visible in response

For each CONFIRMED vulnerability create one finding.
If nothing is confirmed, return an empty array [].

Return ONLY a raw JSON array — no markdown, no explanation, no code fences:
[
  {{
    "title": "SQL Injection in Login Form",
    "severity": "CRITICAL",
    "vuln_type": "sqli",
    "endpoint": "{endpoint}",
    "method": "POST",
    "parameter": "{param}",
    "payload": "the_exact_payload_that_worked",
    "evidence": "Response contained sqlite3.OperationalError or returned admin row",
    "description": "Two or three sentences explaining what was found and the risk.",
    "remediation": "Specific steps to fix this vulnerability.",
    "cvss_score": 9.8
  }}
]

Severity scale: CRITICAL=9-10, HIGH=7-8.9, MEDIUM=4-6.9, LOW=1-3.9, INFO=0-0.9"""

        try:
            raw = call_ai(prompt, max_tokens=2048)
            raw = raw.replace("```json", "").replace("```", "").strip()
            findings = json.loads(raw)

            vulns = []
            for f in findings:
                try:
                    v = Vulnerability(
                        title        = f.get("title", "Unknown Vulnerability"),
                        severity     = Severity(f.get("severity", "MEDIUM")),
                        vuln_type    = f.get("vuln_type", "unknown"),
                        endpoint     = f.get("endpoint", endpoint),
                        method       = f.get("method", batch[0].method if batch else "GET"),
                        parameter    = f.get("parameter", param),
                        payload      = f.get("payload", ""),
                        evidence     = f.get("evidence", ""),
                        description  = f.get("description", ""),
                        remediation  = f.get("remediation", ""),
                        cvss_score   = float(f.get("cvss_score", 5.0)),
                    )
                    vulns.append(v)
                    print(f"[ANALYZER]   ✓ [{v.severity}] {v.title}")
                except Exception as e:
                    print(f"[ANALYZER]   ⚠ Could not parse finding: {e}")

            return vulns

        except json.JSONDecodeError as e:
            print(f"[ANALYZER]   ⚠ JSON parse error: {e}")
            return []
        except Exception as e:
            print(f"[ANALYZER]   ⚠ Gemini error: {e}")
            return []

    def _check_structural_issues(
        self, results: list[PayloadResult]
    ) -> list[Vulnerability]:
        """
        Check for vulnerabilities that don't need payloads:
        - Unauthenticated admin panel
        - /api/users leaking plaintext passwords
        """
        structural = []

        for r in results:
            if "/admin" in r.endpoint and r.response_status == 200:
                structural.append(Vulnerability(
                    title        = "Unauthenticated Admin Panel",
                    severity     = Severity.CRITICAL,
                    vuln_type    = "broken_access_control",
                    endpoint     = r.endpoint,
                    method       = "GET",
                    parameter    = "none",
                    payload      = "(no payload needed)",
                    evidence     = "HTTP 200 returned on /admin with no authentication at all",
                    description  = (
                        "The /admin endpoint is accessible to anyone without logging in. "
                        "An attacker can view all user records, passwords, and perform "
                        "admin actions with zero authentication."
                    ),
                    remediation  = (
                        "Add an authentication middleware that checks for a valid session token "
                        "or JWT before serving any /admin route. Use role-based access control "
                        "to ensure only admin-role users can access this endpoint."
                    ),
                    cvss_score   = 9.1,
                ))
                break

        for r in results:
            if "/api/users" in r.endpoint and "password" in r.response_body.lower() and r.response_status == 200:
                structural.append(Vulnerability(
                    title        = "Sensitive Data Exposure — Plaintext Passwords in API",
                    severity     = Severity.CRITICAL,
                    vuln_type    = "sensitive_data_exposure",
                    endpoint     = r.endpoint,
                    method       = "GET",
                    parameter    = "none",
                    payload      = "(no payload needed)",
                    evidence     = "API response contains 'password' field with plaintext values and no auth required",
                    description  = (
                        "The /api/users endpoint returns all users including their plaintext "
                        "passwords without requiring any authentication. This exposes every "
                        "user credential in the system to any visitor."
                    ),
                    remediation  = (
                        "1) Hash all passwords with bcrypt or argon2 — never store plaintext. "
                        "2) Never include password fields in API responses. "
                        "3) Require authentication (JWT/session) for any endpoint that returns user data."
                    ),
                    cvss_score   = 9.8,
                ))
                break

        return structural