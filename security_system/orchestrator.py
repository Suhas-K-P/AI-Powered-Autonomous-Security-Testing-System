"""
ORCHESTRATOR
────────────
The brain that runs the entire pipeline.

Flow:
  1.  CrawlerAgent   → discovers all endpoints
  2.  AttackerAgent  → generates + fires payloads
  3.  AnalyzerAgent  → finds real vulnerabilities in the responses
  4.  ReporterAgent  → writes the final report

No AI framework — just plain Python method calls.
"""

import time

from security_system.agents.crawler  import CrawlerAgent
from security_system.agents.attacker import AttackerAgent
from security_system.agents.analyzer import AnalyzerAgent
from security_system.agents.reporter import ReporterAgent
from security_system.models          import ScanReport


class Orchestrator:
    """
    Coordinates the four security agents.
    
    Usage:
        report = Orchestrator().run("http://localhost:9999")
    """

    def __init__(self, reports_dir: str = "reports"):
        self.crawler  = CrawlerAgent()
        self.attacker = AttackerAgent()
        self.analyzer = AnalyzerAgent()
        self.reporter = ReporterAgent(reports_dir=reports_dir)

    def run(self, target_url: str) -> ScanReport:
        start_time = time.time()

        print("=" * 60)
        print("  AI-POWERED SECURITY TESTING SYSTEM")
        print(f"  Target: {target_url}")
        print("=" * 60)

        # ── Phase 1: Crawl ────────────────────────────────────────────
        print("\n📡 PHASE 1 — Crawling target application...")
        endpoints = self.crawler.run(target_url)
        print(f"   → Discovered {len(endpoints)} endpoints")

        if not endpoints:
            print("❌ No endpoints found. Is the target app running?")
            raise RuntimeError(f"Could not reach {target_url}. Make sure the vulnerable app is running.")

        # ── Phase 2: Attack ───────────────────────────────────────────
        print("\n💥 PHASE 2 — Generating and firing payloads...")
        raw_results = self.attacker.run(endpoints)
        print(f"   → Fired {len(raw_results)} payloads")

        # ── Phase 3: Analyze ──────────────────────────────────────────
        print("\n🔬 PHASE 3 — Analyzing responses with Claude...")
        vulnerabilities = self.analyzer.run(raw_results)
        print(f"   → Found {len(vulnerabilities)} vulnerabilities")

        # ── Phase 4: Report ───────────────────────────────────────────
        print("\n📋 PHASE 4 — Generating security report...")
        report = self.reporter.run(
            target_url      = target_url,
            vulnerabilities = vulnerabilities,
            total_endpoints = len(endpoints),
            total_tested    = len(raw_results),
        )

        elapsed = time.time() - start_time
        print(f"\n{'=' * 60}")
        print(f"  ✅ Scan complete in {elapsed:.1f} seconds")
        print(f"  Found {len(vulnerabilities)} vulnerabilities")
        print(f"  Report saved in /reports/")
        print(f"{'=' * 60}\n")

        return report