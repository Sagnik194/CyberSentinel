from datetime import datetime
import hashlib
from pathlib import Path

from database.db import get_connection, fetch_all, log_security_event


def calculate_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_directory(directory):
    """
    Scan a directory and detect created, modified,
    unchanged and deleted files.
    """

    root = Path(directory).resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError("The monitoring directory does not exist.")

    current_files = {}

    # Discover files and calculate their hashes.
    for file_path in root.rglob("*"):

        if file_path.is_symlink() or not file_path.is_file():
            continue

        try:
            resolved_path = file_path.resolve()

            if not resolved_path.is_relative_to(root):
                continue

            file_hash = calculate_sha256(resolved_path)
            file_stat = resolved_path.stat()

            current_files[str(resolved_path)] = {
                "hash": file_hash,
                "size": file_stat.st_size,
                "modified": datetime.fromtimestamp(
                    file_stat.st_mtime
                ).isoformat(timespec="seconds")
            }

        except OSError:
            continue

    # Retrieve existing file snapshots.
    existing_rows = fetch_all(
        "SELECT * FROM file_snapshots"
    )

    existing_files = {
        row["file_path"]: dict(row)
        for row in existing_rows
        if Path(row["file_path"]).is_relative_to(root)
    }

    summary = {
        "created": 0,
        "modified": 0,
        "unchanged": 0,
        "deleted": 0
    }

    # Process discovered files.
    for file_path, details in current_files.items():

        previous = existing_files.get(file_path)

        if previous is None or previous["status"] == "DELETED":

            status = "CREATED"
            summary["created"] += 1

            log_security_event(
                event_type="FILE_CREATED",
                severity="LOW",
                description=f"New file detected: {file_path}",
                source=file_path
            )

        elif previous["file_hash"] != details["hash"]:

            status = "MODIFIED"
            summary["modified"] += 1

            log_security_event(
                event_type="FILE_MODIFIED",
                severity="HIGH",
                description=f"File modification detected: {file_path}",
                source=file_path
            )

        else:

            status = "UNCHANGED"
            summary["unchanged"] += 1

        # Insert or update the snapshot.
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

                ON CONFLICT(file_path) DO UPDATE SET
                    file_hash = excluded.file_hash,
                    file_size = excluded.file_size,
                    last_modified = excluded.last_modified,
                    scanned_at = CURRENT_TIMESTAMP,
                    status = excluded.status
                """,
                (
                    file_path,
                    details["hash"],
                    details["size"],
                    details["modified"],
                    status
                )
            )

    # Detect deleted files.
    for file_path, previous in existing_files.items():

        if file_path not in current_files:

            if previous["status"] != "DELETED":

                summary["deleted"] += 1

                log_security_event(
                    event_type="FILE_DELETED",
                    severity="HIGH",
                    description=f"File deletion detected: {file_path}",
                    source=file_path
                )

                with get_connection() as connection:

                    connection.execute(
                        """
                        UPDATE file_snapshots
                        SET status = 'DELETED',
                            scanned_at = CURRENT_TIMESTAMP
                        WHERE file_path = ?
                        """,
                        (file_path,)
                    )

    return summary


def get_file_snapshots():
    """Return all monitored file snapshots."""

    return fetch_all(
        """
        SELECT file_path, file_hash, file_size,
               last_modified, scanned_at, status
        FROM file_snapshots
        ORDER BY scanned_at DESC
        """
    )
