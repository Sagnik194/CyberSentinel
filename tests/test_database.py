
import pytest

import database.db as database
from database.db import (
    get_connection,
    init_db,
    log_security_event,
    fetch_all
)


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    test_database = tmp_path / "database_test.db"
    monkeypatch.setattr(database, "DATABASE_PATH", test_database)
    init_db()
    yield


def test_database_tables_exist(isolated_database):

    init_db()

    rows = fetch_all(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        """
    )

    tables = {
        row["name"]
        for row in rows
    }

    expected_tables = {
        "users",
        "login_attempts",
        "file_snapshots",
        "security_events",
        "network_scans",
        "network_scan_runs",
        "incidents"
    }

    assert expected_tables.issubset(tables)


def test_security_event_insertion(isolated_database):

    init_db()

    log_security_event(
        event_type="TEST_EVENT",
        severity="LOW",
        description="CyberSentinel database test",
        source="pytest"
    )

    rows = fetch_all(
        """
        SELECT *
        FROM security_events
        WHERE event_type = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        ("TEST_EVENT",)
    )

    assert len(rows) == 1
    assert rows[0]["severity"] == "LOW"


def test_invalid_severity(isolated_database):

    with pytest.raises(ValueError):

        log_security_event(
            event_type="TEST",
            severity="INVALID",
            description="Testing invalid severity"
        )


def test_fetch_all_rejects_write_queries(isolated_database):

    with pytest.raises(ValueError):

        fetch_all(
            "DELETE FROM users"
        )


def test_network_scans_have_scan_run_id(isolated_database):
    init_db()

    columns = fetch_all("PRAGMA table_info(network_scans)")
    column_names = {row["name"] for row in columns}

    assert "scan_run_id" in column_names


def test_init_db_migrates_legacy_network_scan_rows(tmp_path, monkeypatch):
    import sqlite3

    legacy_database = tmp_path / "legacy_cybersentinel.db"
    monkeypatch.setattr(database, "DATABASE_PATH", legacy_database)

    with sqlite3.connect(legacy_database) as connection:
        connection.execute(
            """
            CREATE TABLE network_scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                total_open_ports INTEGER NOT NULL DEFAULT 0,
                scanned_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE network_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service TEXT,
                state TEXT NOT NULL,
                scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            INSERT INTO network_scan_runs (target, total_open_ports, scanned_at)
            VALUES ('127.0.0.1', 1, '2026-11-13 10:00:00')
            """
        )
        connection.execute(
            """
            INSERT INTO network_scans
                (target, port, protocol, service, state, scanned_at)
            VALUES ('127.0.0.1', 22, 'tcp', 'ssh', 'open', '2026-11-13 10:00:00')
            """
        )

    init_db()

    migrated = fetch_all(
        "SELECT scan_run_id FROM network_scans WHERE port = 22"
    )
    assert migrated[0]["scan_run_id"] == 1
