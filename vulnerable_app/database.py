import sqlite3
import os

DB_PATH = "vulnerable_app.db"


def get_connection():
    """Return a raw sqlite3 connection — intentionally no ORM."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and seed demo data."""
    conn = get_connection()
    cursor = conn.cursor()

    # Users table — passwords stored in plain text ON PURPOSE (vulnerability)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user',
            email    TEXT
        )
    """)

    # Products table — used to demonstrate SQL injection in search
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT,
            price       REAL,
            secret_note TEXT
        )
    """)

    # Comments table — used to demonstrate stored XSS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            comment    TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Seed users
    cursor.execute("DELETE FROM users")
    cursor.executemany(
        "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
        [
            ("admin",   "admin123",   "admin", "admin@company.com"),
            ("alice",   "password1",  "user",  "alice@company.com"),
            ("bob",     "letmein",    "user",  "bob@company.com"),
            ("charlie", "qwerty",     "user",  "charlie@company.com"),
        ],
    )

    # Seed products
    cursor.execute("DELETE FROM products")
    cursor.executemany(
        "INSERT INTO products (name, description, price, secret_note) VALUES (?, ?, ?, ?)",
        [
            ("Laptop",     "High performance laptop",  999.99,  "internal-sku: LAP-001"),
            ("Phone",      "Latest smartphone",        699.99,  "internal-sku: PHN-002"),
            ("Headphones", "Noise cancelling",          199.99, "internal-sku: AUD-003"),
        ],
    )

    conn.commit()
    conn.close()
    print("[DB] Database initialised at", DB_PATH)