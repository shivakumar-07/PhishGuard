"""SQLite persistence for scan history (stdlib only, thread-safe)."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

from phishguard import config

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type   TEXT NOT NULL,
    input_text  TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    risk_score  REAL NOT NULL,
    ml_prob     REAL NOT NULL,
    heur_score  REAL NOT NULL,
    detail_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
"""


def _connect() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


_conn = _connect()
with _lock:
    _conn.executescript(_SCHEMA)
    _conn.commit()


def insert_scan(result: dict) -> int:
    detail = {k: v for k, v in result.items()
              if k in ("per_model", "reasons", "top_tokens", "signals",
                       "trusted_domain", "latency_ms")}
    with _lock:
        cur = _conn.execute(
            "INSERT INTO scans (scan_type, input_text, verdict, risk_score,"
            " ml_prob, heur_score, detail_json, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (result["type"], result["input"][:500], result["verdict"],
             result["risk_score"], result["ml_probability"],
             result["heuristic_score"], json.dumps(detail),
             datetime.now(timezone.utc).isoformat()))
        _conn.commit()
        return int(cur.lastrowid)


def recent_scans(limit: int = 50) -> list[dict]:
    with _lock:
        rows = _conn.execute(
            "SELECT id, scan_type, input_text, verdict, risk_score, ml_prob,"
            " heur_score, created_at FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    return [dict(r) for r in rows]


def stats() -> dict:
    with _lock:
        total = _conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        by_verdict = {r["verdict"]: r["c"] for r in _conn.execute(
            "SELECT verdict, COUNT(*) c FROM scans GROUP BY verdict")}
        by_type = {r["scan_type"]: r["c"] for r in _conn.execute(
            "SELECT scan_type, COUNT(*) c FROM scans GROUP BY scan_type")}
        avg_risk = _conn.execute(
            "SELECT AVG(risk_score) a FROM scans").fetchone()["a"] or 0.0
        timeline = [dict(r) for r in _conn.execute(
            "SELECT substr(created_at, 1, 16) minute,"
            "       SUM(CASE WHEN verdict='phishing' THEN 1 ELSE 0 END) phishing,"
            "       SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) suspicious,"
            "       SUM(CASE WHEN verdict='safe' THEN 1 ELSE 0 END) safe"
            " FROM scans GROUP BY minute ORDER BY minute DESC LIMIT 60")]
    timeline.reverse()
    return {"total": total, "by_verdict": by_verdict, "by_type": by_type,
            "avg_risk": round(avg_risk, 2), "timeline": timeline}
