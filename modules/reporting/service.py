
import csv
import io
import zipfile

from database.db import fetch_all


REPORT_QUERIES = {
    "security_events": {
        "filename": "security_events.csv",
        "headers": [
            "id",
            "event_type",
            "severity",
            "description",
            "source",
            "status",
            "created_at",
        ],
        "query": """
            SELECT id, event_type, severity, description,
                   source, status, created_at
            FROM security_events
            ORDER BY id DESC
        """,
    },

    "incidents": {
        "filename": "incidents.csv",
        "headers": [
            "id",
            "title",
            "description",
            "severity",
            "status",
            "created_at",
            "resolved_at",
        ],
        "query": """
            SELECT id, title, description, severity,
                   status, created_at, resolved_at
            FROM incidents
            ORDER BY id DESC
        """,
    },

    "network_scans": {
        "filename": "network_scans.csv",
        "headers": [
            "scan_id",
            "target",
            "total_open_ports",
            "open_ports",
            "scanned_at",
        ],
        "query": """
            SELECT
                runs.id AS scan_id,
                runs.target,
                runs.total_open_ports,
                COALESCE(
                    GROUP_CONCAT(
                        scans.port || '/' || scans.protocol,
                        ', '
                    ),
                    ''
                ) AS open_ports,
                runs.scanned_at
            FROM network_scan_runs AS runs
            LEFT JOIN network_scans AS scans
                ON scans.scan_run_id = runs.id
            GROUP BY
                runs.id,
                runs.target,
                runs.total_open_ports,
                runs.scanned_at
            ORDER BY runs.id DESC
        """,
    },

    "file_integrity": {
        "filename": "file_integrity.csv",
        "headers": [
            "id",
            "file_path",
            "file_hash",
            "file_size",
            "last_modified",
            "scanned_at",
            "status",
        ],
        "query": """
            SELECT id, file_path, file_hash, file_size,
                   last_modified, scanned_at, status
            FROM file_snapshots
            ORDER BY id DESC
        """,
    },
}


def generate_csv_report(report_type):
    """
    Generate a CSV report and return its content as text.
    """

    if report_type not in REPORT_QUERIES:
        raise ValueError("Unsupported report type.")

    configuration = REPORT_QUERIES[report_type]

    rows = fetch_all(configuration["query"])

    output = io.StringIO(newline="")

    writer = csv.DictWriter(
        output,
        fieldnames=configuration["headers"],
        extrasaction="ignore",
    )

    writer.writeheader()

    for row in rows:
        writer.writerow(dict(row))

    return output.getvalue()


def generate_complete_report_zip():
    """
    Generate all four CSV reports inside a ZIP archive.
    """

    output = io.BytesIO()

    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:

        for report_type, configuration in REPORT_QUERIES.items():

            csv_content = generate_csv_report(report_type)

            archive.writestr(
                configuration["filename"],
                csv_content,
            )

    output.seek(0)

    return output.getvalue()
