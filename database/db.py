
import sqlite3
from contextlib import contextmanager

from config.settings import DATABASE_PATH


@contextmanager
def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT,
                success INTEGER NOT NULL DEFAULT 0,
                attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS file_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL UNIQUE,
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                last_modified TEXT NOT NULL,
                scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'UNCHANGED'
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source TEXT,
                status TEXT NOT NULL DEFAULT 'OPEN',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Individual open ports discovered during scans.
        # One record for every scan, including scans with zero open ports.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS network_scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                total_open_ports INTEGER NOT NULL DEFAULT 0,
                scanned_at TEXT NOT NULL
            )
        """)

        # Each discovered port is linked to its exact scan run. The nullable
        # column also allows older database records to be migrated safely.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS network_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER REFERENCES network_scan_runs(id),
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service TEXT,
                state TEXT NOT NULL,
                scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Upgrade databases created before scan_run_id was introduced.
        network_scan_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(network_scans)")
        }

        if "scan_run_id" not in network_scan_columns:
            connection.execute("""
                ALTER TABLE network_scans
                ADD COLUMN scan_run_id INTEGER REFERENCES network_scan_runs(id)
            """)

        # Best-effort migration for existing rows. New rows always use the
        # exact run ID and do not rely on timestamp matching.
        connection.execute("""
            UPDATE network_scans
            SET scan_run_id = (
                SELECT runs.id
                FROM network_scan_runs AS runs
                WHERE runs.target = network_scans.target
                  AND runs.scanned_at = network_scans.scanned_at
                ORDER BY runs.id DESC
                LIMIT 1
            )
            WHERE scan_run_id IS NULL
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                resolved_at TEXT
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_username
            ON login_attempts(username)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_severity
            ON security_events(severity)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_created
            ON security_events(created_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_scan_target
            ON network_scans(target)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_scan_runs_date
            ON network_scan_runs(scanned_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_scans_run_id
            ON network_scans(scan_run_id)
        """)


def log_security_event(event_type, severity, description, source=None):
    allowed_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    if severity not in allowed_severities:
        raise ValueError("Invalid security severity")

    with get_connection() as connection:
        connection.execute("""
            INSERT INTO security_events (
                event_type,
                severity,
                description,
                source
            )
            VALUES (?, ?, ?, ?)
        """, (event_type, severity, description, source))


def fetch_all(query, parameters=()):
    normalized = query.lstrip().upper()

    if not (
        normalized.startswith("SELECT")
        or normalized.startswith("PRAGMA")
    ):
        raise ValueError("Only read-only queries are allowed")

    with get_connection() as connection:
        cursor = connection.execute(query, parameters)
        return cursor.fetchall()
