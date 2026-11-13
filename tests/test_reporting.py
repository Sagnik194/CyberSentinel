
import csv
import io
import zipfile

import pytest

import database.db as database

from database.db import (
    init_db,
    get_connection,
)

from modules.reporting.service import (
    generate_csv_report,
    generate_complete_report_zip,
)


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):

    test_database = tmp_path / "reporting_test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        test_database,
    )

    init_db()

    yield


def test_generate_empty_incident_report(isolated_database):

    report = generate_csv_report("incidents")

    rows = list(csv.reader(io.StringIO(report)))

    assert rows[0][0] == "id"
    assert rows[0][1] == "title"
    assert len(rows) == 1


def test_generate_incident_report(isolated_database):

    with get_connection() as connection:

        connection.execute(
            """
            INSERT INTO incidents (
                title, description, severity, status
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                "Suspicious Login",
                "Multiple failed login attempts.",
                "HIGH",
                "OPEN",
            ),
        )

    report = generate_csv_report("incidents")

    rows = list(csv.DictReader(io.StringIO(report)))

    assert len(rows) == 1
    assert rows[0]["title"] == "Suspicious Login"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["status"] == "OPEN"


def test_generate_security_events_report(isolated_database):

    with get_connection() as connection:

        connection.execute(
            """
            INSERT INTO security_events (
                event_type, severity, description, source
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                "FAILED_LOGIN",
                "HIGH",
                "Repeated failed login attempts.",
                "Authentication Module",
            ),
        )

    report = generate_csv_report("security_events")

    rows = list(csv.DictReader(io.StringIO(report)))

    assert len(rows) == 1
    assert rows[0]["event_type"] == "FAILED_LOGIN"
    assert rows[0]["severity"] == "HIGH"


def test_generate_file_integrity_report(isolated_database):

    with get_connection() as connection:

        connection.execute(
            """
            INSERT INTO file_snapshots (
                file_path,
                file_hash,
                file_size,
                last_modified,
                status
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "data/monitored/test.txt",
                "abc123",
                100,
                "2026-11-13 10:00:00",
                "CREATED",
            ),
        )

    report = generate_csv_report("file_integrity")

    rows = list(csv.DictReader(io.StringIO(report)))

    assert len(rows) == 1
    assert rows[0]["file_hash"] == "abc123"
    assert rows[0]["status"] == "CREATED"


def test_generate_network_scan_report(isolated_database):

    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO network_scan_runs (
                target, total_open_ports, scanned_at
            )
            VALUES (?, ?, ?)
            """,
            (
                "127.0.0.1",
                1,
                "2026-11-13 10:00:00",
            ),
        )

        connection.execute(
            """
            INSERT INTO network_scans (
                scan_run_id, target, port, protocol, service, state, scanned_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cursor.lastrowid,
                "127.0.0.1",
                80,
                "tcp",
                "http",
                "open",
                "2026-11-13 10:00:00",
            ),
        )

    report = generate_csv_report("network_scans")

    rows = list(csv.DictReader(io.StringIO(report)))

    assert len(rows) == 1
    assert rows[0]["target"] == "127.0.0.1"
    assert rows[0]["total_open_ports"] == "1"
    assert "80/tcp" in rows[0]["open_ports"]


def test_reject_invalid_report_type(isolated_database):

    with pytest.raises(ValueError):
        generate_csv_report("invalid_report")


def test_generate_complete_report_zip(isolated_database):

    archive_content = generate_complete_report_zip()

    with zipfile.ZipFile(
        io.BytesIO(archive_content),
        "r",
    ) as archive:

        filenames = archive.namelist()

        assert "security_events.csv" in filenames
        assert "incidents.csv" in filenames
        assert "network_scans.csv" in filenames
        assert "file_integrity.csv" in filenames

        assert len(filenames) == 4


def test_network_report_keeps_scan_runs_separate(isolated_database):
    with get_connection() as connection:
        first = connection.execute(
            """
            INSERT INTO network_scan_runs (target, total_open_ports, scanned_at)
            VALUES (?, ?, ?)
            """,
            ("127.0.0.1", 1, "2026-11-13 10:00:00"),
        ).lastrowid

        second = connection.execute(
            """
            INSERT INTO network_scan_runs (target, total_open_ports, scanned_at)
            VALUES (?, ?, ?)
            """,
            ("127.0.0.1", 1, "2026-11-13 10:00:00"),
        ).lastrowid

        connection.execute(
            """
            INSERT INTO network_scans
                (scan_run_id, target, port, protocol, service, state, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (first, "127.0.0.1", 80, "tcp", "http", "open", "2026-11-13 10:00:00"),
        )
        connection.execute(
            """
            INSERT INTO network_scans
                (scan_run_id, target, port, protocol, service, state, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (second, "127.0.0.1", 443, "tcp", "https", "open", "2026-11-13 10:00:00"),
        )

    rows = list(csv.DictReader(io.StringIO(generate_csv_report("network_scans"))))
    by_id = {row["scan_id"]: row["open_ports"] for row in rows}

    assert by_id[str(first)] == "80/tcp"
    assert by_id[str(second)] == "443/tcp"
