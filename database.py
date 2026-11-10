"""SQLite storage for scan history.
All queries use '?' placeholders (parameterised queries) so user input can
never be executed as SQL - this prevents SQL injection."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type   TEXT    NOT NULL CHECK (scan_type IN ('url','domain','ip','hash','file')),
    target      TEXT    NOT NULL,
    risk_score  INTEGER NOT NULL,
    risk_level  TEXT    NOT NULL,
    vt_malicious  INTEGER NOT NULL DEFAULT 0,
    vt_suspicious INTEGER NOT NULL DEFAULT 0,
    source      TEXT    NOT NULL DEFAULT 'web',
    result_json TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_type    ON scans (scan_type);
"""


def db_path():
    path = os.getenv("DATABASE_PATH", "threatlens.db")
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)


@contextmanager
def connect():
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)


def save_scan(scan_type, target, assessment, vt_stats, source, result):
    stats = vt_stats or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO scans (scan_type, target, risk_score, risk_level,
                                  vt_malicious, vt_suspicious, source, result_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_type, target[:2048], assessment["score"], assessment["level"],
             int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)),
             source, json.dumps(result), now),
        )
        return cur.lastrowid, now


def get_scan(scan_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    data["result"] = json.loads(data.pop("result_json"))
    return data


def list_scans(limit=50, offset=0, scan_type=None):
    sql = ("SELECT id, scan_type, target, risk_score, risk_level, vt_malicious, "
           "vt_suspicious, source, created_at FROM scans")
    params = []
    if scan_type:
        sql += " WHERE scan_type = ?"
        params.append(scan_type)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def summary():
    """Counts for the dashboard cards."""
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_level = conn.execute(
            "SELECT risk_level, COUNT(*) AS n FROM scans GROUP BY risk_level").fetchall()
    return {"total": total, "by_level": {r["risk_level"]: r["n"] for r in by_level}}


def delete_scan(scan_id):
    with connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0
