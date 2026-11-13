
import pytest

import database.db as database
from database.db import get_connection, init_db
from modules.file_integrity.service import (
    calculate_sha256,
    scan_directory,
    get_file_snapshots
)


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    test_database = tmp_path / "file_integrity_test.db"
    monkeypatch.setattr(database, "DATABASE_PATH", test_database)
    init_db()
    yield


def test_sha256_calculation(tmp_path):

    test_file = tmp_path / "sample.txt"
    test_file.write_text("CyberSentinel security test")

    result = calculate_sha256(test_file)

    assert len(result) == 64
    assert result == calculate_sha256(test_file)


def test_file_integrity_detection(tmp_path, isolated_database):

    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()
    test_file = monitored_dir / "monitored.txt"
    test_file.write_text("Original content")

    file_path = str(test_file.resolve())

    try:
        # First scan: new file.
        first = scan_directory(monitored_dir)

        assert first["created"] == 1

        # Second scan: unchanged file.
        second = scan_directory(monitored_dir)

        assert second["unchanged"] == 1

        # Modify the file.
        test_file.write_text("Modified content")

        third = scan_directory(monitored_dir)

        assert third["modified"] == 1

        # Delete the file.
        test_file.unlink()

        fourth = scan_directory(monitored_dir)

        assert fourth["deleted"] == 1

        # Verify the final database status.
        rows = get_file_snapshots()

        matching = [
            row for row in rows
            if row["file_path"] == file_path
        ]

        assert matching
        assert matching[0]["status"] == "DELETED"

    finally:

        with get_connection() as connection:

            connection.execute(
                "DELETE FROM file_snapshots WHERE file_path = ?",
                (file_path,)
            )

            connection.execute(
                "DELETE FROM security_events WHERE source = ?",
                (file_path,)
            )
