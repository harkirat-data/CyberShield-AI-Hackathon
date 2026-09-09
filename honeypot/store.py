"""SQLite/WAL-backed telemetry storage for ARGUS."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .models import DecoySession, TelemetryEvent, utc_now


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    destination_port INTEGER NOT NULL,
    service TEXT NOT NULL,
    protocol TEXT NOT NULL,
    persona TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    interactions INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'info',
    intent TEXT NOT NULL DEFAULT 'Reconnaissance',
    intent_confidence REAL NOT NULL DEFAULT 0.35,
    client_fingerprint TEXT NOT NULL DEFAULT 'unknown',
    username TEXT,
    contained INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    direction TEXT NOT NULL,
    content TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    byte_count INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER,
    sha256 TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS investigations (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_confidence REAL NOT NULL,
    mitre_json TEXT NOT NULL,
    rationale TEXT NOT NULL,
    investigation_json TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source_ip, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_session ON telemetry(session_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry(timestamp DESC);
CREATE TABLE IF NOT EXISTS analyst_reports (
    session_id TEXT PRIMARY KEY REFERENCES sessions(session_id),
    report_json TEXT NOT NULL
);
"""


class TelemetryStore:
    """Small durable event store safe for async handlers and API threads."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            check_same_thread=False,
            timeout=10,
        )
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.executescript(SCHEMA)
            # Upgrade historical counters without removing evidence. An action is
            # one inbound request, login attempt, command, query, or client hello.
            self._connection.execute("""UPDATE sessions SET interactions = (
                SELECT COUNT(*) FROM telemetry t WHERE t.session_id = sessions.session_id
                AND t.direction = 'inbound'
            )""")
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def create_session(self, session: DecoySession) -> Dict[str, Any]:
        values = session.to_dict()
        values["contained"] = int(session.contained)
        columns = ", ".join(values)
        placeholders = ", ".join(f":{key}" for key in values)
        with self._lock:
            self._connection.execute(
                f"INSERT INTO sessions ({columns}) VALUES ({placeholders})", values
            )
            self._connection.commit()
        return session.to_dict()

    def end_session(self, session_id: str, status: str = "closed") -> None:
        with self._lock:
            self._connection.execute(
                """UPDATE sessions
                   SET ended_at = COALESCE(ended_at, ?), status = ?
                   WHERE session_id = ?""",
                (utc_now(), status, session_id),
            )
            self._connection.commit()

    def contain_session(self, session_id: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE sessions
                   SET contained = 1, status = 'contained', ended_at = COALESCE(ended_at, ?)
                   WHERE session_id = ?""",
                (utc_now(), session_id),
            )
            self._connection.commit()
        return cursor.rowcount > 0

    def set_fingerprint(
        self,
        session_id: str,
        fingerprint: str,
        username: Optional[str] = None,
    ) -> None:
        with self._lock:
            self._connection.execute(
                """UPDATE sessions
                   SET client_fingerprint = ?, username = COALESCE(?, username)
                   WHERE session_id = ?""",
                (fingerprint[:240], username, session_id),
            )
            self._connection.commit()

    def record_event(self, event: TelemetryEvent) -> Dict[str, Any]:
        content = event.content
        metadata_json = json.dumps(event.metadata, sort_keys=True, default=str)
        with self._lock:
            self._connection.execute(
                """INSERT INTO telemetry (
                    event_id, session_id, timestamp, event_type, severity,
                    direction, content, metadata_json, byte_count, latency_ms, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    event.session_id,
                    event.timestamp,
                    event.event_type,
                    event.severity,
                    event.direction,
                    content,
                    metadata_json,
                    event.byte_count,
                    event.latency_ms,
                    event.sha256,
                ),
            )
            inbound = event.byte_count if event.direction == "inbound" else 0
            outbound = event.byte_count if event.direction == "outbound" else 0
            # Server banners, prompts, Gemini replies, and SOC annotations remain
            # telemetry, but only inbound peer activity is an attacker action.
            interaction = int(event.direction == "inbound")
            self._connection.execute(
                """UPDATE sessions
                   SET bytes_in = bytes_in + ?, bytes_out = bytes_out + ?,
                       interactions = interactions + ?
                   WHERE session_id = ?""",
                (inbound, outbound, interaction, event.session_id),
            )
            self._connection.commit()
        return self._event_dict(event)

    def save_investigation(
        self,
        *,
        event_id: str,
        session_id: str,
        risk_score: int,
        risk_level: str,
        intent: str,
        intent_confidence: float,
        mitre: Iterable[str],
        rationale: str,
        investigation: Dict[str, Any],
    ) -> None:
        mitre_list = list(dict.fromkeys(mitre))
        with self._lock:
            self._connection.execute(
                """INSERT OR REPLACE INTO investigations (
                    event_id, session_id, created_at, risk_score, risk_level,
                    intent, intent_confidence, mitre_json, rationale, investigation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event_id,
                    session_id,
                    utc_now(),
                    int(risk_score),
                    risk_level,
                    intent,
                    float(intent_confidence),
                    json.dumps(mitre_list),
                    rationale,
                    json.dumps(investigation, default=str),
                ),
            )
            self._connection.execute(
                """UPDATE sessions
                   SET risk_score = MAX(risk_score, ?),
                       risk_level = CASE WHEN ? >= risk_score THEN ? ELSE risk_level END,
                       intent = CASE WHEN ? >= intent_confidence THEN ? ELSE intent END,
                       intent_confidence = MAX(intent_confidence, ?)
                   WHERE session_id = ?""",
                (
                    int(risk_score),
                    int(risk_score),
                    risk_level,
                    float(intent_confidence),
                    intent,
                    float(intent_confidence),
                    session_id,
                ),
            )
            self._connection.commit()

    def list_sessions(
        self,
        limit: int = 100,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM sessions"
        parameters: List[Any] = []
        if status:
            query += " WHERE status = ?"
            parameters.append(status)
        query += " ORDER BY started_at DESC LIMIT ?"
        parameters.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [self._session_dict(row) for row in rows]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            analyses = self._connection.execute(
                """SELECT * FROM investigations
                   WHERE session_id = ? ORDER BY created_at DESC""",
                (session_id,),
            ).fetchall()
        if row is None:
            return None
        result = self._session_dict(row)
        result["analyst_report"] = self.get_analyst_report(session_id)
        if analyses:
            latest = self._investigation_dict(analyses[0])
            aggregate_mitre: List[str] = []
            for analysis in analyses:
                try:
                    techniques = json.loads(analysis["mitre_json"])
                except (json.JSONDecodeError, TypeError):
                    techniques = []
                for technique in techniques:
                    if technique not in aggregate_mitre:
                        aggregate_mitre.append(technique)
            latest["mitre"] = aggregate_mitre
            result["analysis"] = latest
        else:
            result["analysis"] = None
        return result

    def list_events(
        self,
        session_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        parameters: List[Any] = []
        query = "SELECT * FROM telemetry"
        if session_id:
            query += " WHERE session_id = ?"
            parameters.append(session_id)
        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(max(1, min(limit, 2_000)))
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [self._row_event_dict(row) for row in rows]

    def recent_destination_ports(
        self,
        source_ip: str,
        limit: int = 12,
        within_seconds: int = 60,
    ) -> List[int]:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=within_seconds)).isoformat()
        with self._lock:
            rows = self._connection.execute(
                """SELECT destination_port FROM sessions
                   WHERE source_ip = ? AND started_at >= ?
                   ORDER BY started_at DESC LIMIT ?""",
                (source_ip, cutoff, limit),
            ).fetchall()
        return [int(row["destination_port"]) for row in rows]

    def metrics(self) -> Dict[str, Any]:
        with self._lock:
            session_rows = self._connection.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT 1000"
            ).fetchall()
            event_count = self._connection.execute(
                "SELECT COUNT(*) AS count FROM telemetry"
            ).fetchone()["count"]
            totals = self._connection.execute("""SELECT COUNT(*) AS sessions,
                COALESCE(SUM(interactions), 0) AS interactions,
                COALESCE(SUM(status = 'active'), 0) AS active,
                COALESCE(SUM(risk_level = 'critical'), 0) AS critical FROM sessions""").fetchone()
            sources = self._connection.execute(
                "SELECT COUNT(DISTINCT source_ip) AS count FROM sessions"
            ).fetchone()["count"]
            service_rows = self._connection.execute(
                """SELECT service, COUNT(*) AS count FROM sessions
                   GROUP BY service ORDER BY count DESC"""
            ).fetchall()

        now = datetime.now(timezone.utc)
        durations = []
        for row in session_rows:
            started = self._parse_time(row["started_at"])
            ended = self._parse_time(row["ended_at"]) if row["ended_at"] else now
            if started and ended:
                durations.append(max(0.0, (ended - started).total_seconds()))
        mean_dwell = sum(durations) / len(durations) if durations else 0.0
        return {
            "active_sessions": int(totals["active"]),
            "interactions_captured": int(totals["interactions"]),
            "telemetry_events": int(event_count),
            "unique_sources": int(sources),
            "mean_dwell_seconds": round(mean_dwell, 1),
            "critical_sessions": int(totals["critical"]),
            "total_sessions": int(totals["sessions"]),
            "service_distribution": {
                str(row["service"]): int(row["count"]) for row in service_rows
            },
        }

    def save_analyst_report(self, session_id: str, report: Dict[str, Any]) -> None:
        with self._lock:
            self._connection.execute(
                """INSERT OR REPLACE INTO analyst_reports (session_id, report_json)
                   VALUES (?, ?)""",
                (session_id, json.dumps(report, default=str)),
            )
            self._connection.commit()

    def get_analyst_report(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._connection.execute(
                "SELECT report_json FROM analyst_reports WHERE session_id = ?", (session_id,)
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def export_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        session = self.get_session(session_id)
        if session is None:
            return None
        return {
            "exported_at": utc_now(),
            "classification": "ARGUS DECOY TELEMETRY",
            "session": session,
            "events": list(reversed(self.list_events(session_id=session_id, limit=2_000))),
        }

    @staticmethod
    def _parse_time(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def _session_dict(row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        result["contained"] = bool(result.get("contained"))
        return result

    @staticmethod
    def _row_event_dict(row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        try:
            result["metadata"] = json.loads(result.pop("metadata_json"))
        except (json.JSONDecodeError, TypeError):
            result["metadata"] = {}
            result.pop("metadata_json", None)
        return result

    @staticmethod
    def _event_dict(event: TelemetryEvent) -> Dict[str, Any]:
        result = event.to_dict()
        result.pop("metadata_json", None)
        return result

    @staticmethod
    def _investigation_dict(row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        for source, target in (
            ("mitre_json", "mitre"),
            ("investigation_json", "investigation"),
        ):
            try:
                result[target] = json.loads(result.pop(source))
            except (json.JSONDecodeError, TypeError):
                result[target] = [] if target == "mitre" else {}
                result.pop(source, None)
        return result
