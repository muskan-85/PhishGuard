"""SQLite storage for live scans (NOT the training dataset)."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta

import config

# Columns added after the original schema. Added with ALTER TABLE so an existing
# phishguard.db keeps all its old rows.
_NEW_COLUMNS = {
    "probability": "REAL",
    "heuristic_count": "INTEGER",
    "details": "TEXT",
}


def get_connection():
    connection = sqlite3.connect(config.DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Create the table if needed and migrate older databases safely."""
    with closing(get_connection()) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )
        existing = {row["name"] for row in con.execute("PRAGMA table_info(scans)")}
        for name, sql_type in _NEW_COLUMNS.items():
            if name not in existing:
                con.execute(f"ALTER TABLE scans ADD COLUMN {name} {sql_type}")
        con.commit()


def save_scan(result):
    """Store one analysis result (the dict returned by predict_url). Returns the new row id."""
    details = json.dumps({
        "indicators": result["indicators"],
        "ngrams_phishing": result["ngrams_phishing"],
        "ngrams_legitimate": result["ngrams_legitimate"],
        "structure": result["structure"],
        "model_name": result["model_name"],
    })
    with closing(get_connection()) as con:
        cur = con.execute(
            """
            INSERT INTO scans (url, result, risk_score, risk_level, scanned_at,
                               probability, heuristic_count, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (result["url"], result["verdict"], result["risk_score"], result["risk_level"],
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             result["probability"], len(result["indicators"]), details),
        )
        con.commit()
        return cur.lastrowid


def get_scan(scan_id):
    with closing(get_connection()) as con:
        row = con.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def get_history(page=1, per_page=20, result_filter=None):
    """Return (rows, total_matching) for one page of history, newest first."""
    where, params = "", []
    if result_filter in ("Phishing", "Legitimate"):
        where, params = "WHERE result = ?", [result_filter]
    with closing(get_connection()) as con:
        total = con.execute(f"SELECT COUNT(*) FROM scans {where}", params).fetchone()[0]
        rows = con.execute(
            f"""SELECT id, url, result, risk_score, risk_level, scanned_at
                FROM scans {where} ORDER BY id DESC LIMIT ? OFFSET ?""",
            params + [per_page, (max(page, 1) - 1) * per_page],
        ).fetchall()
    return [dict(r) for r in rows], total


def get_dashboard_stats():
    """All numbers come from the scans table - nothing is hardcoded."""
    with closing(get_connection()) as con:
        s = con.execute(
            """
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(result = 'Phishing'), 0) AS phishing,
                   COALESCE(SUM(result = 'Legitimate'), 0) AS legitimate,
                   COALESCE(SUM(risk_level = 'Critical Risk'), 0) AS critical,
                   COALESCE(SUM(risk_level = 'High Risk'), 0) AS high,
                   COALESCE(SUM(risk_level = 'Medium Risk'), 0) AS medium,
                   COALESCE(SUM(risk_level = 'Low Risk'), 0) AS low
            FROM scans
            """
        ).fetchone()
        recent = [dict(r) for r in con.execute(
            """SELECT id, url, result, risk_score, risk_level, scanned_at
               FROM scans ORDER BY id DESC LIMIT 6""")]

        # Scans per day for the last 7 days (rows saved by this version use ISO timestamps).
        today = datetime.now().date()
        days = [today - timedelta(days=i) for i in range(6, -1, -1)]
        counts = {r["day"]: r["n"] for r in con.execute(
            """SELECT substr(scanned_at, 1, 10) AS day, COUNT(*) AS n FROM scans
               WHERE substr(scanned_at, 1, 10) >= ? GROUP BY day""", (days[0].isoformat(),))}

    total = s["total"]
    return {
        "total": total,
        "phishing": s["phishing"],
        "legitimate": s["legitimate"],
        "phishing_rate": round(100 * s["phishing"] / total, 1) if total else 0,
        "bands": {"Low": s["low"], "Medium": s["medium"], "High": s["high"], "Critical": s["critical"]},
        "recent": recent,
        "daily": [{"label": d.strftime("%a"), "date": d.isoformat(), "count": counts.get(d.isoformat(), 0)}
                  for d in days],
    }
