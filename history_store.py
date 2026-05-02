"""SQLite-backed scan history store.

Stdlib only — works in both the Railway FastAPI backend and the stdlib
Vercel handler. The DB file lives under DATA_DIR (default: repo root;
overridden to /tmp on Vercel because the rest of the FS is read-only).

On Vercel the file is wiped between cold starts — that's a known
limitation called out in README.md → 'Persistence on Vercel'. For
durable history use the Railway deployment.

Public API:
    init_db()                 -> idempotent CREATE TABLEs
    record_scan(...)          -> int (new scan id)
    list_scans(limit=50)      -> [dict]   most recent first
    get_scan(scan_id)         -> dict | None
    purge_old(keep=500)       -> rows deleted
"""

import json
import os
import sqlite3
from datetime import datetime, timezone


def _data_dir():
    explicit = os.environ.get("DATA_DIR")
    if explicit:
        return explicit
    if os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV"):
        return "/tmp"
    return os.path.dirname(os.path.abspath(__file__))


def _db_path():
    return os.path.join(_data_dir(), "scans.db")


def _connect():
    conn = sqlite3.connect(_db_path(), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url      TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    risk_level      TEXT,
    score           INTEGER,
    findings_total  INTEGER NOT NULL DEFAULT 0,
    counts_json     TEXT,
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category        TEXT,
    title           TEXT,
    severity        TEXT,
    evidence        TEXT,
    remediation_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def init_db():
    with _connect() as conn:
        conn.executescript(SCHEMA)


def record_scan(target_url, summary):
    """Insert a scan row + its findings. Returns the new scan id.

    'summary' matches the dict returned by scanner._summary():
        {status, risk_level, score, counts, findings_total, findings[]}
    For rejected/error cases pass {'status': 'rejected', ...} with
    findings=[] — the row is still written for audit purposes.
    """
    init_db()
    findings = summary.get("findings") or []
    counts = summary.get("counts") or {}
    now = datetime.now(timezone.utc).isoformat()

    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO scans
               (target_url, status, risk_level, score, findings_total,
                counts_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                (target_url or "")[:2000],
                summary.get("status", "unknown"),
                summary.get("risk_level"),
                summary.get("score"),
                summary.get("findings_total", len(findings)),
                json.dumps(counts),
                now,
            ),
        )
        scan_id = cur.lastrowid
        if findings:
            conn.executemany(
                """INSERT INTO findings
                   (scan_id, category, title, severity, evidence, remediation_key)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    (
                        scan_id,
                        f.get("category"),
                        f.get("title"),
                        f.get("severity"),
                        (f.get("evidence") or "")[:2000],
                        f.get("remediation_key"),
                    )
                    for f in findings
                ],
            )
        return scan_id


def list_scans(limit=50):
    init_db()
    limit = max(1, min(int(limit), 200))
    with _connect() as conn:
        rows = conn.execute(
            """SELECT id, target_url, status, risk_level, score,
                      findings_total, counts_json, created_at
               FROM scans
               ORDER BY id DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    return [_row_to_scan(r) for r in rows]


def get_scan(scan_id):
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (int(scan_id),)
        ).fetchone()
        if not row:
            return None
        scan = _row_to_scan(row)
        finds = conn.execute(
            """SELECT category, title, severity, evidence, remediation_key
               FROM findings WHERE scan_id = ? ORDER BY id""",
            (int(scan_id),),
        ).fetchall()
        scan["findings"] = [dict(f) for f in finds]
        return scan


def purge_old(keep=500):
    init_db()
    with _connect() as conn:
        cur = conn.execute(
            """DELETE FROM scans WHERE id NOT IN (
                   SELECT id FROM scans ORDER BY id DESC LIMIT ?
               )""",
            (max(1, int(keep)),),
        )
        return cur.rowcount


def _row_to_scan(row):
    d = dict(row)
    raw = d.pop("counts_json", None)
    try:
        d["counts"] = json.loads(raw) if raw else {}
    except Exception:
        d["counts"] = {}
    return d
