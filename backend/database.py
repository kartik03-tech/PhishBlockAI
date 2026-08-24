import os
import psycopg2
import psycopg2.extras
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_connection():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            url TEXT,
            prediction TEXT,
            risk_score INTEGER,
            confidence REAL,
            reasons TEXT,
            detected_at TEXT
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

def save_scan(result: dict):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (url, prediction, risk_score, confidence, reasons, detected_at) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (result["url"], result["prediction"], result["risk_score"],
         result["confidence"], ", ".join(result["reasons"]), datetime.utcnow().isoformat())
    )
    conn.commit()
    cur.close()
    conn.close()

def get_history(limit: int = 100):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT %s", (limit,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]
