import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

DB_FILE = os.getenv("NMPL_DB_FILE", "nmpl_analytics.db")
EPHEMERAL_METRICS = os.getenv("NMPL_EPHEMERAL_METRICS", "true").lower() == "true"
METRICS_RETENTION = int(os.getenv("NMPL_METRICS_RETENTION", "200"))
DB_BUSY_TIMEOUT_MS = int(os.getenv("NMPL_DB_BUSY_TIMEOUT_MS", "5000"))


def _timestamp_value() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class DatabaseLockedError(Exception):
    pass


class StorageManager:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else Path(DB_FILE)
        self.db_file = str(self.db_path)

    def _connect(self):
        conn = sqlite3.connect(self.db_file)
        conn.execute(f"PRAGMA busy_timeout = {DB_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def init_storage(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics_timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    target TEXT,
                    summary TEXT,
                    status_flag TEXT,
                    latency_ms REAL,
                    loss_pct REAL,
                    jitter_ms REAL,
                    source TEXT
                )
            """)

            if EPHEMERAL_METRICS:
                conn.execute("DROP TRIGGER IF EXISTS trim_metrics_timeline")
                conn.execute(f"""
                    CREATE TRIGGER trim_metrics_timeline
                    AFTER INSERT ON metrics_timeline
                    BEGIN
                        DELETE FROM metrics_timeline
                        WHERE id <= (
                            SELECT id FROM metrics_timeline
                            ORDER BY id DESC
                            LIMIT 1 OFFSET {METRICS_RETENTION}
                        );
                    END
                """)
            else:
                conn.execute("DROP TRIGGER IF EXISTS trim_metrics_timeline")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    target TEXT,
                    structural_fault_summary TEXT,
                    bottleneck_hop INTEGER,
                    bottleneck_host TEXT,
                    bottleneck_loss_pct REAL,
                    raw_telemetry_json TEXT,
                    resolved_flag INTEGER DEFAULT 0,
                    resolved_at DATETIME,
                    last_updated_at DATETIME,
                    source TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS active_targets (
                    target TEXT PRIMARY KEY,
                    registered_at DATETIME
                )
            """)

            metrics_cols = {row[1] for row in conn.execute("PRAGMA table_info(metrics_timeline)")}
            if "source" not in metrics_cols:
                conn.execute("ALTER TABLE metrics_timeline ADD COLUMN source TEXT")

            incident_cols = {row[1] for row in conn.execute("PRAGMA table_info(network_incidents)")}
            if "resolved_at" not in incident_cols:
                conn.execute("ALTER TABLE network_incidents ADD COLUMN resolved_at DATETIME")
            if "last_updated_at" not in incident_cols:
                conn.execute("ALTER TABLE network_incidents ADD COLUMN last_updated_at DATETIME")
            if "source" not in incident_cols:
                conn.execute("ALTER TABLE network_incidents ADD COLUMN source TEXT")

    def close(self):
        pass

    def _execute_write(self, fn):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                raise DatabaseLockedError(str(e)) from e
            raise

    def log_heartbeat(self, target, summary, status_flag, metrics, source=None):
        def _write():
            with self._connect() as conn:
                conn.execute("""
                    INSERT INTO metrics_timeline
                    (timestamp, target, summary, status_flag, latency_ms, loss_pct, jitter_ms, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    _timestamp_value(),
                    target,
                    summary,
                    status_flag,
                    metrics["latency_ms"],
                    metrics["loss_pct"],
                    metrics["jitter_ms"],
                    source
                ))
        return self._execute_write(_write)

    def log_incident(self, target, incident_payload, source=None):
        def _write():
            bottleneck = incident_payload.get("bottleneck", {}) or {}
            now = _timestamp_value()
            with self._connect() as conn:
                cur = conn.execute("""
                    INSERT INTO network_incidents
                    (timestamp, target, structural_fault_summary, bottleneck_hop, bottleneck_host,
                     bottleneck_loss_pct, raw_telemetry_json, resolved_flag, last_updated_at, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """, (
                    now,
                    target,
                    incident_payload.get("summary", ""),
                    bottleneck.get("hop"),
                    bottleneck.get("host"),
                    bottleneck.get("loss"),
                    json.dumps(incident_payload, indent=2),
                    now,
                    source
                ))
                return cur.lastrowid
        return self._execute_write(_write)

    def get_open_incident(self, target):
        with self._connect() as conn:
            return conn.execute("""
                SELECT id, timestamp, target, structural_fault_summary,
                       bottleneck_hop, bottleneck_host, bottleneck_loss_pct, raw_telemetry_json
                FROM network_incidents
                WHERE target = ? AND resolved_flag = 0
                ORDER BY timestamp DESC
                LIMIT 1
            """, (target,)).fetchone()

    def update_incident(self, incident_id, incident_payload, source=None):
        def _write():
            bottleneck = incident_payload.get("bottleneck", {}) or {}
            with self._connect() as conn:
                conn.execute("""
                    UPDATE network_incidents
                    SET structural_fault_summary = ?,
                        bottleneck_hop = ?,
                        bottleneck_host = ?,
                        bottleneck_loss_pct = ?,
                        raw_telemetry_json = ?,
                        last_updated_at = ?,
                        source = COALESCE(?, source)
                    WHERE id = ?
                """, (
                    incident_payload.get("summary", ""),
                    bottleneck.get("hop"),
                    bottleneck.get("host"),
                    bottleneck.get("loss"),
                    json.dumps(incident_payload, indent=2),
                    _timestamp_value(),
                    source,
                    incident_id
                ))
        return self._execute_write(_write)

    def resolve_incident(self, incident_id):
        def _write():
            now = _timestamp_value()
            with self._connect() as conn:
                conn.execute("""
                    UPDATE network_incidents
                    SET resolved_flag = 1, resolved_at = ?, last_updated_at = ?
                    WHERE id = ?
                """, (now, now, incident_id))
        return self._execute_write(_write)

    def delete_incident(self, incident_id: int) -> bool:
        def _write():
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM network_incidents WHERE id = ?", (incident_id,))
                return cur.rowcount > 0
        return self._execute_write(_write)

    def get_incident(self, incident_id):
        with self._connect() as conn:
            return conn.execute("""
                SELECT id, timestamp, target, structural_fault_summary,
                       bottleneck_hop, bottleneck_host, bottleneck_loss_pct, raw_telemetry_json,
                       resolved_flag, resolved_at, source
                FROM network_incidents
                WHERE id = ?
            """, (incident_id,)).fetchone()

    def get_metrics_timeline(self, target=None, limit=100):
        with self._connect() as conn:
            if target:
                return conn.execute("""
                    SELECT id, timestamp, target, summary, status_flag, latency_ms, loss_pct, jitter_ms, source
                    FROM metrics_timeline
                    WHERE target = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (target, limit)).fetchall()

            return conn.execute("""
                SELECT id, timestamp, target, summary, status_flag, latency_ms, loss_pct, jitter_ms, source
                FROM metrics_timeline
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,)).fetchall()

    def get_all_incidents(self, limit=100, open_only=False):
        query = """
            SELECT id, timestamp, target, structural_fault_summary,
                   bottleneck_hop, bottleneck_host, bottleneck_loss_pct, raw_telemetry_json,
                   resolved_flag, resolved_at, source
            FROM network_incidents
        """
        if open_only:
            query += " WHERE resolved_flag = 0"
        query += " ORDER BY timestamp DESC LIMIT ?"

        with self._connect() as conn:
            return conn.execute(query, (limit,)).fetchall()

    def register_active_target(self, target: str):
        def _write():
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO active_targets (target, registered_at)
                    VALUES (?, ?)
                """, (target, _timestamp_value()))
        return self._execute_write(_write)

    def remove_active_target(self, target: str):
        def _write():
            with self._connect() as conn:
                conn.execute("DELETE FROM active_targets WHERE target = ?", (target,))
        return self._execute_write(_write)

    def get_active_targets(self):
        with self._connect() as conn:
            return [
                row[0]
                for row in conn.execute("""
                    SELECT target FROM active_targets
                """).fetchall()
            ]