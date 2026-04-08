# 🔐 AI-Powered Autonomous Security Testing System

> Multi-agent autonomous security scanner built with **FastAPI + Google Gemini AI (free)**.  
> 4 AI agents collaborate to crawl, attack, analyze, and report vulnerabilities.  
> **For educational and portfolio use only. Only tests your own local app.**

---

## 🌐 URLs — Open These In Your Browser

| What | URL | Description |
|------|-----|-------------|
| 🎯 Vulnerable Target App | **http://localhost:9999** | The fake app your agents will hack |
| 📋 Login page (SQLi) | http://localhost:9999/login | Try: username `admin' --` password `anything` |
| 🔍 Search page (XSS) | http://localhost:9999/search | Try: `<script>alert('XSS')</script>` |
| 💬 Comments (Stored XSS) | http://localhost:9999/comments | Try: `<img src=x onerror=alert('hi')>` |
| 🔧 Admin panel (no auth) | http://localhost:9999/admin | Just visit — no login needed |
| 👥 Users API (leaks passwords) | http://localhost:9999/api/users | Returns all users + plaintext passwords |
| 🤖 Security API Swagger UI | **http://localhost:8000/docs** | Run your AI scan from here |
| ❤️ Health check | http://localhost:8000/health | Confirm security API is running |

---

## 📁 Project Structure

```
security_project/
│
├── .env                              ← ⚠️ Your Gemini API key goes here
├── .gitignore                        ← Ignores .env so key never leaks to GitHub
├── requirements.txt                  ← All Python dependencies
├── test_setup.py                     ← Run this to verify everything works
├── start_windows.bat                 ← Double-click to start both servers (Windows)
├── start_unix.sh                     ← Run to start both servers (Mac/Linux)
│
├── vulnerable_app/                   ← The intentionally hackable target website
│   ├── main.py                       ← FastAPI app with 8 real vulnerabilities
│   ├── database.py                   ← SQLite setup + seed users/products
│   └── templates/
│       ├── home.html
│       ├── login.html                ← SQL Injection vulnerability
│       ├── search.html               ← Reflected XSS + SQL Injection
│       ├── comments.html             ← Stored XSS vulnerability
│       ├── dashboard.html
│       └── admin.html                ← No authentication at all
│
├── security_system/                  ← The multi-agent AI system
│   ├── config.py                     ← Loads .env, sets Gemini model name
│   ├── models.py                     ← Pydantic schemas: Endpoint, Vulnerability, ScanReport
│   ├── ai_client.py                  ← Single file that talks to Gemini API
│   ├── orchestrator.py               ← Runs all 4 agents in sequence
│   └── agents/
│       ├── crawler.py                ← Agent 1: Spiders the app, finds all routes
│       ├── attacker.py               ← Agent 2: Asks Gemini for payloads, fires them
│       ├── analyzer.py               ← Agent 3: Asks Gemini if responses = vulnerabilities
│       └── reporter.py               ← Agent 4: Asks Gemini to write the full report
│
├── api/
│   └── main.py                       ← FastAPI server — POST /scan runs everything
│
└── reports/                          ← Auto-created after first scan
    ├── report_2024-xx-xx.md          ← Human-readable Markdown report
    └── report_2024-xx-xx.json        ← Machine-readable JSON report
```

---

## ⚙️ First Time Setup

### Step 1 — Get your FREE Gemini API key

1. Go to **https://aistudio.google.com**
2. Click **"Get API Key"**
3. Click **"Create API Key"**
4. Copy the key (starts with `AIzaSy...`)

No credit card. No payment. Completely free. 1,500 requests/day.

---

### Step 2 — Add your key to the .env file

Open `security_project/.env` in any text editor (Notepad, VS Code, etc.) and replace:

```
GEMINI_API_KEY=your-gemini-key-here
```

with your real key:

```
GEMINI_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

⚠️ Never share this key. Never commit it to GitHub. The `.gitignore` already protects it.

---

### Step 3 — Create virtual environment and install dependencies

Open **Git Bash** or terminal inside the `security_project` folder and run:

```bash
# Create the virtual environment
python -m venv venv

# Activate it (Git Bash on Windows)
source venv/Scripts/activate

# You should now see (venv) at the start of your prompt

# Install all packages
pip install -r requirements.txt
```

> **Every time you open a new terminal, run `source venv/Scripts/activate` first.**

---

## 🚀 Running the Project

You need **two terminal windows** open at the same time.

---

### Terminal 1 — Start the Vulnerable Target App (port 9999)

```bash
cd security_project
source venv/Scripts/activate
uvicorn vulnerable_app.main:app --port 9999 --reload
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:9999
[DB] Database initialised at vulnerable_app.db
[APP] Vulnerable app is running — DO NOT expose to the internet!
INFO:     Application startup complete.
```

✅ Open **http://localhost:9999** in your browser to confirm it works.

---

### Terminal 2 — Start the Security Testing API (port 8000)

```bash
cd security_project
source venv/Scripts/activate
uvicorn api.main:app --port 8000 --reload
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

✅ Open **http://localhost:8000/docs** in your browser to confirm it works.

---

## 🧪 Running an AI Security Scan

### Option A — Swagger UI (easiest, recommended)

1. Open **http://localhost:8000/docs**
2. Click **`POST /scan`**
3. Click **"Try it out"**
4. Paste this into the request body box:
```json
{
  "target_url": "http://localhost:9999",
  "background": false
}
```
5. Click **Execute**
6. Watch **both terminals** — you'll see agents printing live progress
7. Scroll down to see the full security report in the response

The scan takes **2–4 minutes**. You'll see output like:
```
[CRAWLER] Starting crawl on: http://localhost:9999
[CRAWLER] Found 12 unique endpoints

[ATTACKER] Testing: GET http://localhost:9999/search
[ATTACKER]   Gemini generated 5 payloads for 'q'

[ANALYZER] Analysing 47 payload results with Gemini...
[ANALYZER]   ✓ [CRITICAL] SQL Injection in Search

[REPORTER] ✅ Markdown report → reports/report_2024-xx-xx.md
```

---

### Option B — curl (from terminal)

```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d "{\"target_url\": \"http://localhost:9999\", \"background\": false}"
```

---

### Option C — Background scan (returns immediately, poll for results)

```bash
# Start scan — returns job_id right away
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d "{\"target_url\": \"http://localhost:9999\", \"background\": true}"

# Returns: {"job_id": "abc12345", "status": "pending", ...}

# Check status
curl "http://localhost:8000/scan/abc12345"
```

---

## 📋 Viewing Saved Reports

After a scan, reports are saved in the `reports/` folder automatically.

```bash
# List all reports via API
curl http://localhost:8000/reports

# Download a specific report
curl http://localhost:8000/reports/report_2024-01-01_12-00-00.md
```

Or just open the `reports/` folder in File Explorer — the `.md` files open nicely in **VS Code** (install the Markdown Preview extension).

---

## 🐛 8 Vulnerabilities Built Into the Target App

| # | Type | Endpoint | How to test manually |
|---|------|----------|----------------------|
| 1 | SQL Injection | `POST /login` | Username: `admin' --` · Password: `anything` |
| 2 | SQL Injection | `GET /search?q=` | Query: `' UNION SELECT username,password,role,email,id FROM users --` |
| 3 | Reflected XSS | `GET /search?q=` | Query: `<script>alert('XSS')</script>` |
| 4 | Stored XSS | `POST /comments` | Comment: `<img src=x onerror=alert('Stored XSS')>` |
| 5 | Broken Authentication | `GET /admin` | Just visit the URL — no password needed |
| 6 | Sensitive Data Exposure | `GET /api/users` | Returns all users with plaintext passwords |
| 7 | IDOR | `GET /api/users/{id}` | Change the number — sees anyone's data |
| 8 | Path Traversal | `GET /files?filename=` | `../vulnerable_app/database.py` reads source code |

---

## 🏗️ How the 4 AI Agents Work

```
You → POST /scan → Orchestrator
                        │
                        ▼
        ┌─────────────────────────────────────┐
        │  AGENT 1: CrawlerAgent              │
        │  Tool: requests + BeautifulSoup     │
        │  • Visits every link on the site    │
        │  • Parses all HTML forms            │
        │  • Probes /admin, /api, /files...   │
        │  Output: list of Endpoints          │
        └──────────────┬──────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │  AGENT 2: AttackerAgent             │
        │  Tool: Gemini AI + requests         │
        │  • Asks Gemini: what payloads to    │
        │    try on this specific parameter?  │
        │  • Fires every payload via HTTP     │
        │  • Records every response           │
        │  Output: list of PayloadResults     │
        └──────────────┬──────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │  AGENT 3: AnalyzerAgent             │
        │  Tool: Gemini AI                    │
        │  • Sends payload + response to AI  │
        │  • Asks: is this a real vuln?       │
        │  • AI returns structured findings  │
        │  Output: list of Vulnerabilities   │
        └──────────────┬──────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │  AGENT 4: ReporterAgent             │
        │  Tool: Gemini AI                    │
        │  • Asks AI for executive summary    │
        │  • Builds professional Markdown     │
        │  • Saves .md and .json to disk      │
        │  Output: ScanReport                 │
        └──────────────┬──────────────────────┘
                       │
                       ▼
              Full report returned
```

**Why no LangChain?** Each agent is a plain Python class that calls `call_ai()` from `ai_client.py`. No framework magic — every line is readable and explainable in interviews.

---

## 🔧 Troubleshooting

**`uvicorn: command not found`**
```bash
source venv/Scripts/activate   # activate the venv first
```

**`GEMINI_API_KEY not set` error**
```
→ Open .env and paste your key from https://aistudio.google.com
```

**`ModuleNotFoundError: No module named 'fastapi'`**
```bash
source venv/Scripts/activate
pip install -r requirements.txt
```

**`Could not reach http://localhost:9999`**
```
→ Terminal 1 must be running the vulnerable app first
→ Check that you see "Application startup complete" in Terminal 1
```

**`Address already in use` on port 8000 or 9999**
```bash
uvicorn api.main:app --port 8001 --reload          # use a different port
uvicorn vulnerable_app.main:app --port 9998 --reload
```

**Scan takes too long / Gemini timeout**
```
→ Gemini free tier: 15 requests/minute
→ A full scan fires ~50 API calls — takes 3-5 minutes, this is normal
→ Watch the terminal to see live progress
```

**Verify everything is working**
```bash
python test_setup.py
```

---

## 🤖 AI Stack

| Component | Technology | Cost |
|-----------|-----------|------|
| AI model | Google Gemini 1.5 Flash | **Free** (1,500 req/day) |
| API client | `google-generativeai` Python SDK | Free |
| Web framework | FastAPI | Free |
| HTTP requests | `requests` library | Free |
| HTML parsing | BeautifulSoup4 | Free |
| Data validation | Pydantic v2 | Free |
| Database | SQLite (built into Python) | Free |

---



## ⚠️ Disclaimer

This project is for **educational and portfolio purposes only**.  
The vulnerable app is intentionally insecure — never deploy it on a public server.  
Only test applications that you own and have permission to test.

---

*Built with ❤️ for learning ethical security testing*
