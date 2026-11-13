
from database.db import get_connection, log_security_event


ALLOWED_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

ALLOWED_STATUSES = {
    "OPEN",
    "INVESTIGATING",
    "RESOLVED",
}

MAX_TITLE_LENGTH = 150
MAX_DESCRIPTION_LENGTH = 5000

# Explicitly supported incident status transitions.
ALLOWED_TRANSITIONS = {
    "OPEN": {"INVESTIGATING", "RESOLVED"},
    "INVESTIGATING": {"OPEN", "RESOLVED"},
    "RESOLVED": {"OPEN", "INVESTIGATING"},
}


def create_incident(title, description, severity):

    # Validate title
    if not isinstance(title, str):
        raise ValueError("Incident title must be text.")

    title = title.strip()

    if not title:
        raise ValueError("Incident title is required.")

    if len(title) > MAX_TITLE_LENGTH:
        raise ValueError(
            f"Incident title cannot exceed {MAX_TITLE_LENGTH} characters."
        )

    # Validate description
    if description is None:
        description = ""

    if not isinstance(description, str):
        raise ValueError("Incident description must be text.")

    description = description.strip()

    if len(description) > MAX_DESCRIPTION_LENGTH:
        raise ValueError(
            f"Incident description cannot exceed "
            f"{MAX_DESCRIPTION_LENGTH} characters."
        )

    # Validate severity
    if not isinstance(severity, str):
        raise ValueError("Incident severity must be text.")

    severity = severity.strip().upper()

    if severity not in ALLOWED_SEVERITIES:
        raise ValueError("Invalid incident severity.")

    # Insert incident
    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO incidents (
                title,
                description,
                severity,
                status
            )
            VALUES (?, ?, ?, 'OPEN')
            """,
            (
                title,
                description,
                severity,
            ),
        )

        incident_id = cursor.lastrowid

    # Record security event
    log_security_event(
        event_type="INCIDENT_CREATED",
        severity=severity,
        description=f"Incident #{incident_id} created: {title}",
        source="Incident Response Module",
    )

    return incident_id


def update_incident_status(incident_id, new_status):

    # Validate incident ID
    if (
        isinstance(incident_id, bool)
        or not isinstance(incident_id, int)
        or incident_id <= 0
    ):
        raise ValueError("Invalid incident ID.")

    # Validate new status
    if not isinstance(new_status, str):
        raise ValueError("Incident status must be text.")

    new_status = new_status.strip().upper()

    if new_status not in ALLOWED_STATUSES:
        raise ValueError("Invalid incident status.")

    with get_connection() as connection:

        incident = connection.execute(
            """
            SELECT id, title, status
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        ).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        current_status = incident["status"]

        # No update needed
        if current_status == new_status:
            return False

        # Validate status transition
        if new_status not in ALLOWED_TRANSITIONS[current_status]:
            raise ValueError(
                f"Cannot change incident status "
                f"from {current_status} to {new_status}."
            )

        if new_status == "RESOLVED":

            connection.execute(
                """
                UPDATE incidents
                SET status = ?,
                    resolved_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (new_status, incident_id),
            )

        else:

            connection.execute(
                """
                UPDATE incidents
                SET status = ?,
                    resolved_at = NULL
                WHERE id = ?
                """,
                (new_status, incident_id),
            )

    # Record status change
    log_security_event(
        event_type="INCIDENT_STATUS_UPDATED",
        severity="MEDIUM",
        description=(
            f"Incident #{incident_id} "
            f"status changed from {current_status} to {new_status}"
        ),
        source="Incident Response Module",
    )

    return True


def get_all_incidents():

    with get_connection() as connection:

        incidents = connection.execute(
            """
            SELECT
                id,
                title,
                description,
                severity,
                status,
                created_at,
                resolved_at
            FROM incidents
            ORDER BY id DESC
            """
        ).fetchall()

    return incidents


def get_incident_summary():

    with get_connection() as connection:

        summary = connection.execute(
            """
            SELECT
                COUNT(*) AS total,

                COALESCE(
                    SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END),
                    0
                ) AS open_count,

                COALESCE(
                    SUM(CASE WHEN status = 'INVESTIGATING' THEN 1 ELSE 0 END),
                    0
                ) AS investigating_count,

                COALESCE(
                    SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END),
                    0
                ) AS resolved_count,

                COALESCE(
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END),
                    0
                ) AS critical_count

            FROM incidents
            """
        ).fetchone()

    return dict(summary)
