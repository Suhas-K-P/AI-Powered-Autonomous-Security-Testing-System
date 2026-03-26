"""
REPORTER AGENT
──────────────
Takes confirmed vulnerabilities and asks Gemini to write
a professional security report in Markdown format.

The report includes:
  - Executive summary
  - Vulnerability table sorted by severity
  - Detailed write-up for each finding
  - Remediation roadmap
"""

import os
import json
from datetime import datetime

from security_system.ai_client import call_ai
from security_system.models import Vulnerability, ScanReport, Severity


# Sort order for severity levels
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


class ReporterAgent:
    """
    Generates a professional security report using Gemini AI.
    Saves the report as both Markdown (.md) and JSON (.json).
    """

    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)

    # ── Public ────────────────────────────────────────────────────────────────
    def run(
        self,
        target_url: str,
        vulnerabilities: list[Vulnerability],
        total_endpoints: int,
        total_tested: int,
    ) -> ScanReport:
        """Generate the full report and save it to disk."""
        print(f"\n[REPORTER] Generating report for {len(vulnerabilities)} vulnerabilities...")

        timestamp    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sorted_vulns = sorted(vulnerabilities, key=lambda v: SEVERITY_ORDER.get(v.severity, 99))

        # Ask Gemini for executive summary + recommendations
        summary, recommendations = self._generate_summary(target_url, sorted_vulns)

        # Build full markdown
        markdown = self._build_markdown(
            target_url, timestamp, sorted_vulns,
            summary, recommendations,
            total_endpoints, total_tested,
        )

        report = ScanReport(
            target_url       = target_url,
            scan_timestamp   = timestamp,
            total_endpoints  = total_endpoints,
            total_tested     = total_tested,
            vulnerabilities  = sorted_vulns,
            summary          = summary,
            recommendations  = recommendations,
            raw_markdown     = markdown,
        )

        self._save_report(report, timestamp)
        return report

    # ── Private ───────────────────────────────────────────────────────────────
    def _generate_summary(
        self, target_url: str, vulns: list[Vulnerability]
    ) -> tuple[str, list[str]]:
        """Ask Gemini for an executive summary and prioritised recommendations."""

        vuln_list = [
            {"title": v.title, "severity": v.severity, "type": v.vuln_type}
            for v in vulns
        ]

        prompt = f"""You are a senior security engineer writing an executive summary for a penetration test report.

Target application: {target_url}
Vulnerabilities discovered:
{json.dumps(vuln_list, indent=2)}

Write:
1. A concise executive summary (3-4 sentences) suitable for a non-technical manager.
2. A prioritised list of 5-7 remediation recommendations ordered by urgency.

Return ONLY raw JSON — no markdown, no code fences, no explanation:
{{
  "summary": "Executive summary text here...",
  "recommendations": [
    "First priority: fix this immediately because...",
    "Second priority: ..."
  ]
}}"""

        try:
            raw = call_ai(prompt, max_tokens=1024)
            raw = raw.replace("```json", "").replace("```", "").strip()
            data = json.loads(raw)
            return data.get("summary", ""), data.get("recommendations", [])

        except Exception as e:
            print(f"[REPORTER] ⚠ Gemini error: {e} — using fallback summary")
            counts: dict = {}
            for v in vulns:
                counts[str(v.severity)] = counts.get(str(v.severity), 0) + 1
            summary = (
                f"Security scan of {target_url} completed. "
                f"Found {len(vulns)} vulnerabilities: "
                + ", ".join(f"{k}: {val}" for k, val in counts.items()) + ". "
                "Immediate remediation is recommended for all critical and high findings."
            )
            return summary, [
                "Fix all CRITICAL vulnerabilities immediately",
                "Hash passwords using bcrypt or argon2",
                "Add authentication to all admin and API endpoints",
                "Use parameterised SQL queries everywhere",
                "Escape all user input before rendering in HTML",
                "Validate and sanitise file path parameters",
            ]

    def _build_markdown(
        self,
        target_url: str,
        timestamp: str,
        vulns: list[Vulnerability],
        summary: str,
        recommendations: list[str],
        total_endpoints: int,
        total_tested: int,
    ) -> str:
        """Build the complete Markdown report string."""

        critical = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
        high     = sum(1 for v in vulns if v.severity == Severity.HIGH)
        medium   = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
        low      = sum(1 for v in vulns if v.severity == Severity.LOW)

        lines = [
            "# 🔐 Security Assessment Report",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Target** | `{target_url}` |",
            f"| **Date** | {timestamp} |",
            f"| **Endpoints Discovered** | {total_endpoints} |",
            f"| **Payloads Fired** | {total_tested} |",
            f"| **Tool** | AI-Powered Autonomous Security Testing System |",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            summary,
            "",
            "---",
            "",
            "## Vulnerability Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {critical} |",
            f"| 🟠 High     | {high}     |",
            f"| 🟡 Medium   | {medium}   |",
            f"| 🟢 Low      | {low}      |",
            f"| **Total**   | **{len(vulns)}** |",
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ]

        for i, v in enumerate(vulns, 1):
            emoji = SEVERITY_EMOJI.get(str(v.severity), "⚪")
            lines += [
                f"### {i}. {emoji} {v.title}",
                "",
                "| Field | Details |",
                "|-------|---------|",
                f"| **Severity** | {v.severity} (CVSS: {v.cvss_score}) |",
                f"| **Type** | `{v.vuln_type}` |",
                f"| **Endpoint** | `{v.endpoint}` |",
                f"| **Method** | `{v.method}` |",
                f"| **Parameter** | `{v.parameter}` |",
                "",
                "**Description:**",
                "",
                v.description,
                "",
                "**Payload Used:**",
                "",
                "```",
                v.payload,
                "```",
                "",
                "**Evidence:**",
                "",
                f"> {v.evidence}",
                "",
                "**Remediation:**",
                "",
                v.remediation,
                "",
                "---",
                "",
            ]

        lines += [
            "## Recommendations",
            "",
        ]
        for r in recommendations:
            lines.append(f"- {r}")

        lines += [
            "",
            "---",
            "",
            "## Disclaimer",
            "",
            "> This test was conducted on a deliberately vulnerable demonstration application "
            "> running locally for educational purposes. No real systems were tested.",
            "",
            "_Generated by AI-Powered Autonomous Security Testing System_",
        ]

        return "\n".join(lines)

    def _save_report(self, report: ScanReport, timestamp: str):
        """Save report as both .md and .json files."""
        safe_ts   = timestamp.replace(":", "-").replace(" ", "_")
        md_path   = os.path.join(self.reports_dir, f"report_{safe_ts}.md")
        json_path = os.path.join(self.reports_dir, f"report_{safe_ts}.json")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(report.raw_markdown)
        print(f"[REPORTER]  Markdown report → {md_path}")

        with open(json_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        print(f"[REPORTER]  JSON report    → {json_path}")