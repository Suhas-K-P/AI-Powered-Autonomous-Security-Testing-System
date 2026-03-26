"""
=============================================================
  VULNERABLE TARGET APPLICATION
  !! FOR EDUCATIONAL / PORTFOLIO USE ONLY !!
  !! NEVER DEPLOY THIS ON A PUBLIC SERVER  !!

  Intentional vulnerabilities included:
    1.  SQL Injection   — /login  and  /search
    2.  Reflected XSS   — /search
    3.  Stored XSS      — /comments  (POST + GET)
    4.  Broken Auth     — /dashboard  (no real session check)
    5.  IDOR            — /api/users/{id}  (no ownership check)
    6.  Sensitive Data  — /api/users       (returns all users)
    7.  Missing Auth    — /admin           (no protection)
    8.  Path Traversal  — /files           (reads arbitrary files)
=============================================================
"""

import os
import sys

# Make sure we can import database.py from this same folder
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from database import get_connection, init_db

# ── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Vulnerable Demo App",
    description="Intentionally insecure app for security testing practice",
    version="1.0.0",
)

BASE_DIR   = os.path.dirname(__file__)
templates  = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Initialise DB on startup
@app.on_event("startup")
def startup():
    init_db()
    print("[APP] Vulnerable app is running — DO NOT expose to the internet!")


# ── HOME ─────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})


# ── VULNERABILITY 1 & 4: SQL Injection + Broken Auth on Login ────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn   = get_connection()
    cursor = conn.cursor()

    # !! SQL INJECTION VULNERABILITY !!
    # Input is NOT sanitised — attacker can use:  admin' --
    # which becomes: SELECT * FROM users WHERE username='admin' --' AND password='...'
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"[VULN] Executing query: {query}")

    try:
        result = cursor.execute(query).fetchone()
    except Exception as e:
        # !! Error messages leak query structure !!
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": f"Database error: {str(e)} | Query was: {query}"},
        )
    finally:
        conn.close()

    if result:
        return templates.TemplateResponse(
            "dashboard.html",
            {"request": request, "user": dict(result), "username": username},
        )

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid credentials"},
    )


# ── VULNERABILITY 2: Reflected XSS on Search ─────────────────────────────────
@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: str = ""):
    conn    = get_connection()
    cursor  = conn.cursor()
    results = []

    if q:
        # !! SQL INJECTION in search !!
        query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
        print(f"[VULN] Search query: {query}")
        try:
            results = [dict(r) for r in cursor.execute(query).fetchall()]
        except Exception as e:
            results = []
        conn.close()

    # !! REFLECTED XSS !!
    # The value of `q` is rendered directly into the page without escaping.
    # Payload: <script>alert('XSS')</script>
    return templates.TemplateResponse(
        "search.html",
        {"request": request, "query": q, "results": results},
    )


# ── VULNERABILITY 3: Stored XSS via Comments ─────────────────────────────────
@app.get("/comments", response_class=HTMLResponse)
def comments_page(request: Request):
    conn     = get_connection()
    comments = [dict(r) for r in conn.execute("SELECT * FROM comments ORDER BY created_at DESC").fetchall()]
    conn.close()
    return templates.TemplateResponse("comments.html", {"request": request, "comments": comments})


@app.post("/comments", response_class=HTMLResponse)
def post_comment(request: Request, username: str = Form(...), comment: str = Form(...)):
    conn = get_connection()
    # !! STORED XSS — comment is saved raw, then rendered without escaping !!
    conn.execute("INSERT INTO comments (username, comment) VALUES (?, ?)", (username, comment))
    conn.commit()
    comments = [dict(r) for r in conn.execute("SELECT * FROM comments ORDER BY created_at DESC").fetchall()]
    conn.close()
    return templates.TemplateResponse(
        "comments.html",
        {"request": request, "comments": comments, "message": "Comment posted!"},
    )


# ── VULNERABILITY 5 & 6: IDOR + Sensitive Data Exposure ──────────────────────
@app.get("/api/users")
def get_all_users():
    """!! No auth required — exposes ALL user data including passwords !!"""
    conn  = get_connection()
    users = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
    conn.close()
    return JSONResponse(content={"users": users})


@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    """!! IDOR — no check that the requester owns this user_id !!"""
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not user:
        return JSONResponse(status_code=404, content={"error": "User not found"})
    return JSONResponse(content=dict(user))


# ── VULNERABILITY 7: Unauthenticated Admin Panel ─────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request):
    """!! No authentication whatsoever on the admin panel !!"""
    conn  = get_connection()
    users = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
    conn.close()
    return templates.TemplateResponse("admin.html", {"request": request, "users": users})


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    """!! Admin action with zero authentication !!"""
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"User {user_id} deleted"}


# ── VULNERABILITY 8: Path Traversal ──────────────────────────────────────────
@app.get("/files")
def read_file(filename: str = Query(...)):
    """
    !! PATH TRAVERSAL !!
    Intended use: /files?filename=readme.txt
    Attack:       /files?filename=../../etc/passwd
                  /files?filename=../vulnerable_app/database.py
    """
    try:
        with open(filename, "r") as f:
            content = f.read()
        return JSONResponse(content={"filename": filename, "content": content})
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "File not found"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# ── Dashboard (reached after login) ──────────────────────────────────────────
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, username: str = "guest"):
    """!! No real session — username passed as query param (easy to spoof) !!"""
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": dict(user) if user else {}, "username": username},
    )