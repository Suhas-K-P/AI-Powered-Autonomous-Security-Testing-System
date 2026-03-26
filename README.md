# 🔐 AI-Powered Autonomous Security Testing System

> Multi-agent security testing system built with FastAPI + Anthropic Claude.  
> **For educational and portfolio use only. Only tests your own local vulnerable app.**

---

## 📁 Project Structure

```
security_project/
│
├── .env                          ← Your API key goes here (never commit this)
├── .gitignore
├── requirements.txt
│
├── vulnerable_app/               ← PHASE 1: The intentionally vulnerable target
│   ├── main.py                   ← FastAPI app with 8 vulnerabilities built in
│   ├── database.py               ← SQLite setup + seed data
│   └── templates/                ← HTML pages
│       ├── home.html
│       ├── login.html            ← SQL Injection here
│       ├── search.html           ← XSS + SQLi here
│       ├── comments.html         ← Stored XSS here
│       ├── dashboard.html
│       └── admin.html            ← No auth here
│
├── security_system/              ← PHASE 2-4: The AI agent system
│   ├── config.py                 ← Loads .env, sets constants
│   ├── models.py                 ← Pydantic schemas shared between agents
│   ├── orchestrator.py           ← Coordinates all 4 agents
│   └── agents/
│       ├── crawler.py            ← Agent 1: Discovers endpoints
│       ├── attacker.py           ← Agent 2: Generates + fires payloads (uses Claude)
│       ├── analyzer.py           ← Agent 3: Confirms vulnerabilities (uses Claude)
│       └── reporter.py           ← Agent 4: Writes the report (uses Claude)
│
├── api/
│   └── main.py                   ← FastAPI server: POST /scan triggers the pipeline
│
└── reports/                      ← Auto-created. Scan reports saved here
    ├── report_2024-01-01_...md
    └── report_2024-01-01_...json
```

---

## ⚙️ Setup

### Step 1 — Clone / download the project

```bash
cd Desktop
# If you used git:
# git clone <your-repo>
# cd security_project

# Or just navigate to the folder:
cd security_project
```

### Step 2 — Create a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Add your Anthropic API key

Open the `.env` file in any text editor and replace the placeholder:

```
ANTHROPIC_API_KEY=sk-ant-your-real-key-here
```

👉 Get your key at: https://console.anthropic.com  
👉 **Never share your API key or commit it to GitHub.**

---

## 🚀 Running the Project

You need **two terminal windows** open at the same time.

---

### Terminal 1 — Start the Vulnerable Target App

```bash
# Make sure your venv is activated first
cd security_project

# Windows
venv\Scripts\activate

# Mac/Linux  
source venv/bin/activate

# Run the vulnerable app on port 9999
uvicorn vulnerable_app.main:app --port 9999 --reload
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:9999
[DB] Database initialised at vulnerable_app.db
[APP] Vulnerable app is running
```

Open your browser → http://localhost:9999 to confirm it's working.  
Try logging in with: `admin' --` as username, anything as password.

---

### Terminal 2 — Start the Security Testing API

```bash
# Open a NEW terminal window
cd security_project

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate

# Run the security API on port 8000
uvicorn api.main:app --port 8000 --reload
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

---

## 🧪 Running a Scan

### Option A — Use the browser (Swagger UI)

Open: http://localhost:8000/docs

1. Click `POST /scan` → `Try it out`
2. Paste this body:
```json
{
  "target_url": "http://localhost:9999",
  "background": false
}
```
3. Click **Execute**
4. Watch the terminal output as agents run
5. Get the full report in the response

---

### Option B — Use curl

```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:9999", "background": false}'
```

---

### Option C — Use Python

```python
import requests

response = requests.post(
    "http://localhost:8000/scan",
    json={"target_url": "http://localhost:9999", "background": False}
)

report = response.json()
print(f"Found {report['vulnerability_count']} vulnerabilities")
for v in report['vulnerabilities']:
    print(f"  [{v['severity']}] {v['title']} — {v['endpoint']}")
```

---

### Option D — Background scan (non-blocking)

```bash
# Start scan, get job_id immediately
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:9999", "background": true}'

# Returns: {"job_id": "abc123", "message": "..."}

# Poll for status
curl "http://localhost:8000/scan/abc123"
```

---

## 📋 Viewing Reports

Reports are automatically saved in the `reports/` folder as both `.md` and `.json`.

```bash
# List all saved reports
curl http://localhost:8000/reports

# Download a specific report
curl http://localhost:8000/reports/report_2024-01-01_12-00-00.md
```

Or just open the `reports/` folder — the `.md` files are readable in VS Code or any Markdown viewer.

---

## 🐛 Vulnerabilities Built Into the Target App

| # | Vulnerability | Endpoint | How to test manually |
|---|---------------|----------|----------------------|
| 1 | SQL Injection | `POST /login` | Username: `admin' --` |
| 2 | SQL Injection | `GET /search?q=` | Query: `' UNION SELECT username,password,role,email,id FROM users --` |
| 3 | Reflected XSS | `GET /search?q=` | Query: `<script>alert('XSS')</script>` |
| 4 | Stored XSS | `POST /comments` | Comment body: `<img src=x onerror=alert('Stored XSS')>` |
| 5 | Broken Auth | `GET /admin` | Just visit the URL — no login needed |
| 6 | Sensitive Data | `GET /api/users` | Returns all users + plaintext passwords |
| 7 | IDOR | `GET /api/users/{id}` | Change the ID number — no ownership check |
| 8 | Path Traversal | `GET /files?filename=` | filename: `../vulnerable_app/database.py` |

---

## 🏗️ How the Agents Work

```
User sends POST /scan
        ↓
  Orchestrator starts
        ↓
  ┌─ CrawlerAgent ──────────────────────────────────────────┐
  │  Uses requests + BeautifulSoup                          │
  │  Spiders all links, parses all forms                    │
  │  Probes common paths (/admin, /api/users, /files...)    │
  │  Returns: list of Endpoint objects                      │
  └─────────────────────────────────────────────────────────┘
        ↓
  ┌─ AttackerAgent ─────────────────────────────────────────┐
  │  For each endpoint + parameter:                         │
  │    → Asks Claude: "Generate payloads for this input"    │
  │    → Fires each payload using requests                  │
  │    → Records raw HTTP response                          │
  │  Returns: list of PayloadResult objects                 │
  └─────────────────────────────────────────────────────────┘
        ↓
  ┌─ AnalyzerAgent ─────────────────────────────────────────┐
  │  Groups results by endpoint + parameter                 │
  │  For each group:                                        │
  │    → Sends payload + response to Claude                 │
  │    → Asks: "Is this a real vulnerability?"              │
  │    → Claude returns structured JSON findings            │
  │  Returns: list of Vulnerability objects                 │
  └─────────────────────────────────────────────────────────┘
        ↓
  ┌─ ReporterAgent ─────────────────────────────────────────┐
  │  Asks Claude for executive summary + recommendations    │
  │  Builds professional Markdown report                    │
  │  Saves .md and .json files to /reports/                 │
  │  Returns: ScanReport object                             │
  └─────────────────────────────────────────────────────────┘
        ↓
  Full report returned via API
```

---

## 🔧 Troubleshooting

**"ANTHROPIC_API_KEY not set" error**
→ Open `.env` and add your real key from https://console.anthropic.com

**"Could not reach target" error**
→ Make sure Terminal 1 (vulnerable app on port 9999) is running first

**"ModuleNotFoundError"**
→ Make sure your venv is activated: `venv\Scripts\activate` (Windows)

**Scan takes too long**
→ Claude API calls take 2-5 seconds each. A full scan takes ~2-4 minutes.

**Port already in use**
→ Change port: `uvicorn api.main:app --port 8001`

---

## 📌 Resume Description

> **AI-Powered Autonomous Security Testing System** | Python, FastAPI, Anthropic Claude API  
> Built a multi-agent system where AI agents autonomously crawl a web application, generate context-aware attack payloads using Claude, analyse HTTP responses to confirm vulnerabilities, and produce professional security reports. Agents communicate via Pydantic schemas; no LangChain used. Tested against a custom-built vulnerable FastAPI application including SQL injection, XSS, IDOR, and path traversal vulnerabilities.

---

*⚠️ This project is for educational purposes only. Never test applications you don't own.*