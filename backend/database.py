import sqlite3
from datetime import datetime

DB_PATH = "threats.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT, prediction TEXT, risk_score INTEGER,
            confidence REAL, reasons TEXT, detected_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_scan(result: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scans (url, prediction, risk_score, confidence, reasons, detected_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (result["url"], result["prediction"], result["risk_score"],
         result["confidence"], ", ".join(result["reasons"]), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

def get_history(limit: int = 100):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]