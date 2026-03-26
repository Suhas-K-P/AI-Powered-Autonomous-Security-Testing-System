"""
SECURITY TESTING API  —  api/main.py
─────────────────────────────────────
This is the FastAPI server you start in Terminal 2.
It exposes your multi-agent system via HTTP endpoints.

Start it with:
    uvicorn api.main:app --port 8000 --reload

Then open:
    http://localhost:8000/docs   ← interactive Swagger UI to run scans

Available endpoints:
    POST /scan              → run a full scan (returns the complete report)
    POST /scan?background   → run in background, returns job_id
    GET  /scan/{job_id}     → check status of a background scan
    GET  /reports           → list all saved report files
    GET  /reports/{file}    → download a specific report
    GET  /health            → confirm the API is running
"""

import os
import sys
import uuid
import asyncio
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

# ── Make sure Python can find the security_system package ─────────────────────
# api/main.py is inside the api/ folder.
# The project root (one level up) must be on sys.path so that
# "from security_system.orchestrator import Orchestrator" works.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from security_system.orchestrator import Orchestrator
from security_system.models       import ScanReport


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "AI-Powered Security Testing System",
    description = (
        "Multi-agent autonomous security scanner using Gemini AI.\n\n"
        "**How to use:**\n"
        "1. Make sure the vulnerable app is running on port 9999\n"
        "2. Use `POST /scan` with `{\"target_url\": \"http://localhost:9999\"}`\n"
        "3. The 4 AI agents will run and return a full security report\n\n"
        "⚠️ For educational use only. Only test your own local apps."
    ),
    version     = "1.0.0",
)

# In-memory store for background scan jobs
# { job_id: { status, target_url, started_at, finished_at, error, report } }
jobs: dict[str, dict] = {}

REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")


# ── Request / Response models ─────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str
    background: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "target_url": "http://localhost:9999",
                "background": False
            }
        }


class ScanStatusResponse(BaseModel):
    job_id:      str
    status:      str
    target_url:  str
    started_at:  str
    finished_at: Optional[str] = None
    error:       Optional[str] = None
    report:      Optional[dict] = None


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health():
    """Check that the API is running."""
    return {
        "status":  "ok",
        "service": "AI Security Testing System",
        "ai":      "Google Gemini (free tier)"
    }


@app.post("/scan", tags=["Scanning"])
async def run_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Trigger a full security scan against the target URL.

    Runs all 4 agents in sequence:
    1. **Crawler** — discovers all endpoints and form fields
    2. **Attacker** — generates payloads with Gemini and fires them
    3. **Analyzer** — asks Gemini if any responses prove a vulnerability
    4. **Reporter** — writes the professional security report

    **Important:** Only localhost targets are allowed.

    Set `background: true` to run async and get a `job_id` immediately.
    Then poll `GET /scan/{job_id}` for results.
    """
    # ── Safety guard — only allow localhost ──────────────────────────────────
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    if parsed.hostname not in ("localhost", "127.0.0.1", "0.0.0.0"):
        raise HTTPException(
            status_code=400,
            detail=(
                "⛔ Only localhost targets are allowed. "
                "This tool is for testing your own local vulnerable app only. "
                "Never point this at a real website."
            ),
        )

    job_id = str(uuid.uuid4())[:8]

    if req.background:
        # ── Background mode: return job_id immediately ────────────────────────
        jobs[job_id] = {
            "status":      "pending",
            "target_url":  req.target_url,
            "started_at":  datetime.now().isoformat(),
            "finished_at": None,
            "error":       None,
            "report":      None,
        }
        background_tasks.add_task(_run_scan_background, job_id, req.target_url)
        return {
            "job_id":   job_id,
            "status":   "pending",
            "message":  f"Scan started. Poll GET /scan/{job_id} for status.",
        }

    else:
        # ── Synchronous mode: block until done, return full report ────────────
        try:
            orchestrator = Orchestrator(reports_dir=REPORTS_DIR)
            report       = orchestrator.run(req.target_url)
            return _report_to_dict(report)
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/scan/{job_id}", response_model=ScanStatusResponse, tags=["Scanning"])
def get_scan_status(job_id: str):
    """
    Get the status of a background scan.

    Possible statuses: `pending` → `running` → `complete` | `error`
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    job = jobs[job_id]
    return ScanStatusResponse(
        job_id      = job_id,
        status      = job["status"],
        target_url  = job["target_url"],
        started_at  = job["started_at"],
        finished_at = job["finished_at"],
        error       = job["error"],
        report      = job["report"],
    )


@app.get("/reports", tags=["Reports"])
def list_reports():
    """List all saved report files in the reports/ folder."""
    if not os.path.exists(REPORTS_DIR):
        return {"reports": [], "count": 0}
    files = sorted(
        [f for f in os.listdir(REPORTS_DIR) if f.endswith(".md") or f.endswith(".json")],
        reverse=True,
    )
    return {"reports": files, "count": len(files)}


@app.get("/reports/{filename}", tags=["Reports"])
def get_report(filename: str):
    """
    Download a specific report file.

    Use `GET /reports` first to see available filenames.
    """
    # Prevent path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(path)


# ── Background task ───────────────────────────────────────────────────────────
async def _run_scan_background(job_id: str, target_url: str):
    """Runs the orchestrator in the background and updates the jobs dict."""
    jobs[job_id]["status"] = "running"
    try:
        loop = asyncio.get_event_loop()
        orchestrator = Orchestrator(reports_dir=REPORTS_DIR)
        report = await loop.run_in_executor(None, orchestrator.run, target_url)
        jobs[job_id]["status"]      = "complete"
        jobs[job_id]["finished_at"] = datetime.now().isoformat()
        jobs[job_id]["report"]      = _report_to_dict(report)
    except Exception as e:
        jobs[job_id]["status"]      = "error"
        jobs[job_id]["finished_at"] = datetime.now().isoformat()
        jobs[job_id]["error"]       = str(e)


# ── Helper ────────────────────────────────────────────────────────────────────
def _report_to_dict(report: ScanReport) -> dict:
    """Convert a ScanReport to a plain dict for JSON serialisation."""
    return {
        "target_url":          report.target_url,
        "scan_timestamp":      report.scan_timestamp,
        "total_endpoints":     report.total_endpoints,
        "total_tested":        report.total_tested,
        "vulnerability_count": len(report.vulnerabilities),
        "summary":             report.summary,
        "recommendations":     report.recommendations,
        "vulnerabilities": [
            {
                "title":       v.title,
                "severity":    str(v.severity),
                "vuln_type":   v.vuln_type,
                "endpoint":    v.endpoint,
                "method":      v.method,
                "parameter":   v.parameter,
                "payload":     v.payload,
                "evidence":    v.evidence,
                "description": v.description,
                "remediation": v.remediation,
                "cvss_score":  v.cvss_score,
            }
            for v in report.vulnerabilities
        ],
        "report_markdown_preview": (
            report.raw_markdown[:600] + "\n...[truncated]"
            if len(report.raw_markdown) > 600
            else report.raw_markdown
        ),
    }