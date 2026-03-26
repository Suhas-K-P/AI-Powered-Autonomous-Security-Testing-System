"""
CRAWLER AGENT
─────────────
Spiders the target app using requests + BeautifulSoup.
Returns a list of Endpoint objects describing every route,
HTTP method, query parameter, and form field it finds.

No AI is used here — pure deterministic crawling.
"""

import time
import re
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from security_system.models import Endpoint


class CrawlerAgent:
    """
    Crawls a web application and maps all reachable endpoints.
    
    Strategy:
      1.  Start at base_url
      2.  Parse every <a href>, <form action>
      3.  Record form fields and query params
      4.  BFS up to `max_depth` levels
    """

    def __init__(self, max_depth: int = 3, timeout: int = 5):
        self.max_depth   = max_depth
        self.timeout     = timeout
        self.visited: set[str] = set()
        self.session     = requests.Session()
        self.session.headers.update({"User-Agent": "SecurityTestBot/1.0 (educational)"})

    # ── Public ────────────────────────────────────────────────────────────────
    def run(self, base_url: str) -> list[Endpoint]:
        """Entry point. Returns list of discovered endpoints."""
        print(f"\n[CRAWLER] Starting crawl on: {base_url}")
        self.base_url = base_url.rstrip("/")
        self.base_host = urlparse(base_url).netloc

        endpoints: list[Endpoint] = []
        queue = [(base_url, 0)]   # (url, depth)

        while queue:
            url, depth = queue.pop(0)
            if depth > self.max_depth:
                continue
            if url in self.visited:
                continue
            self.visited.add(url)

            print(f"[CRAWLER]   GET {url} (depth {depth})")
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException as e:
                print(f"[CRAWLER]   ⚠ Could not reach {url}: {e}")
                continue

            # Record this GET endpoint
            parsed = urlparse(url)
            ep = Endpoint(
                url=url,
                method="GET",
                params=list(parse_qs(parsed.query).keys()),
                description=f"Discovered by crawler at depth {depth}",
            )
            endpoints.append(ep)

            # Parse the page
            if "text/html" not in resp.headers.get("content-type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract links
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                full = urljoin(url, href)
                if self._same_host(full) and full not in self.visited:
                    queue.append((full, depth + 1))

            # Extract forms
            for form in soup.find_all("form"):
                form_eps = self._parse_form(form, url)
                endpoints.extend(form_eps)

        # Also add known likely endpoints that may not be linked
        extra = self._probe_common_endpoints()
        for ep in extra:
            if ep.url not in {e.url for e in endpoints}:
                endpoints.append(ep)

        # Deduplicate
        seen    = set()
        unique  = []
        for ep in endpoints:
            key = (ep.url, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        print(f"[CRAWLER] Done. Found {len(unique)} unique endpoints.\n")
        return unique

    # ── Private ───────────────────────────────────────────────────────────────
    def _same_host(self, url: str) -> bool:
        """Only follow links on the same host."""
        return urlparse(url).netloc == self.base_host

    def _parse_form(self, form, page_url: str) -> list[Endpoint]:
        """Extract method, action, and field names from an HTML form."""
        action = form.get("action") or page_url
        full_action = urljoin(page_url, action)

        if not self._same_host(full_action):
            return []

        method      = (form.get("method") or "get").upper()
        form_fields = []

        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                form_fields.append(name)

        ep = Endpoint(
            url         = full_action,
            method      = method,
            form_fields = form_fields,
            description = f"Form on page: {page_url}",
        )
        print(f"[CRAWLER]   FORM {method} {full_action} fields={form_fields}")
        return [ep]

    def _probe_common_endpoints(self) -> list[Endpoint]:
        """
        Actively probe common paths that might not be linked
        (admin panels, API endpoints, etc.)
        """
        common_paths = [
            "/admin",
            "/api/users",
            "/api/users/1",
            "/api/users/2",
            "/files",
            "/dashboard",
            "/config",
            "/backup",
            "/debug",
            "/status",
            "/health",
        ]

        probed = []
        for path in common_paths:
            url = self.base_url + path
            if url in self.visited:
                continue
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code not in (404, 410):
                    ep = Endpoint(
                        url         = url,
                        method      = "GET",
                        description = f"Probed common path — status {resp.status_code}",
                    )
                    probed.append(ep)
                    print(f"[CRAWLER]   PROBE {url} → {resp.status_code}")
            except requests.RequestException:
                pass

        # Also add the /files endpoint with a param hint
        files_url = self.base_url + "/files"
        probed.append(Endpoint(
            url         = files_url,
            method      = "GET",
            params      = ["filename"],
            description = "File read endpoint — param: filename",
        ))

        return probed