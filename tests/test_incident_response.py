
import pytest

import database.db as database

from database.db import init_db

from modules.incident_response.service import (
    create_incident,
    update_incident_status,
    get_all_incidents,
    get_incident_summary,
)


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):

    test_database = tmp_path / "incident_test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        test_database,
    )

    init_db()

    yield


# --------------------------------------------------
# INCIDENT CREATION TESTS
# --------------------------------------------------

def test_create_incident(isolated_database):

    incident_id = create_incident(
        "Suspicious Login Activity",
        "Multiple failed login attempts detected.",
        "HIGH",
    )

    incidents = get_all_incidents()

    assert incident_id == 1
    assert len(incidents) == 1
    assert incidents[0]["title"] == "Suspicious Login Activity"
    assert incidents[0]["severity"] == "HIGH"
    assert incidents[0]["status"] == "OPEN"


def test_reject_empty_title(isolated_database):

    with pytest.raises(ValueError):
        create_incident(
            "",
            "Test description",
            "LOW",
        )


def test_reject_invalid_severity(isolated_database):

    with pytest.raises(ValueError):
        create_incident(
            "Test Incident",
            "Test description",
            "UNKNOWN",
        )


def test_reject_title_over_150_characters(isolated_database):

    with pytest.raises(ValueError):
        create_incident(
            "A" * 151,
            "Test description",
            "LOW",
        )


def test_reject_non_string_title(isolated_database):

    with pytest.raises(ValueError):
        create_incident(
            None,
            "Test description",
            "LOW",
        )


def test_reject_non_string_description(isolated_database):

    with pytest.raises(ValueError):
        create_incident(
            "Test Incident",
            12345,
            "LOW",
        )


def test_reject_description_over_5000_characters(isolated_database):

    with pytest.raises(ValueError):
        create_incident(
            "Test Incident",
            "A" * 5001,
            "LOW",
        )


def test_accept_empty_description(isolated_database):

    incident_id = create_incident(
        "Test Incident",
        None,
        "LOW",
    )

    incidents = get_all_incidents()

    assert incident_id == 1
    assert incidents[0]["description"] == ""


def test_normalize_incident_input(isolated_database):

    create_incident(
        "  Test Incident  ",
        "  Test Description  ",
        "  high  ",
    )

    incidents = get_all_incidents()

    assert incidents[0]["title"] == "Test Incident"
    assert incidents[0]["description"] == "Test Description"
    assert incidents[0]["severity"] == "HIGH"


# --------------------------------------------------
# INCIDENT STATUS TESTS
# --------------------------------------------------

def test_update_incident_status(isolated_database):

    incident_id = create_incident(
        "Unauthorized Access",
        "Suspicious access detected.",
        "CRITICAL",
    )

    result = update_incident_status(
        incident_id,
        "INVESTIGATING",
    )

    incidents = get_all_incidents()

    assert result is True
    assert incidents[0]["status"] == "INVESTIGATING"


def test_resolve_incident(isolated_database):

    incident_id = create_incident(
        "Malware Alert",
        "Suspicious file detected.",
        "HIGH",
    )

    update_incident_status(
        incident_id,
        "RESOLVED",
    )

    incidents = get_all_incidents()

    assert incidents[0]["status"] == "RESOLVED"
    assert incidents[0]["resolved_at"] is not None


def test_reopen_resolved_incident(isolated_database):

    incident_id = create_incident(
        "Malware Alert",
        "Suspicious file detected.",
        "HIGH",
    )

    update_incident_status(
        incident_id,
        "RESOLVED",
    )

    result = update_incident_status(
        incident_id,
        "OPEN",
    )

    incidents = get_all_incidents()

    assert result is True
    assert incidents[0]["status"] == "OPEN"
    assert incidents[0]["resolved_at"] is None


def test_reject_invalid_status(isolated_database):

    incident_id = create_incident(
        "Test Incident",
        "Test description",
        "LOW",
    )

    with pytest.raises(ValueError):
        update_incident_status(
            incident_id,
            "CLOSED",
        )


def test_reject_invalid_incident_id(isolated_database):

    for invalid_id in [0, -1, None, "1", True]:

        with pytest.raises(ValueError):
            update_incident_status(
                invalid_id,
                "RESOLVED",
            )


def test_reject_nonexistent_incident(isolated_database):

    with pytest.raises(ValueError):
        update_incident_status(
            999,
            "RESOLVED",
        )


def test_same_status_does_not_create_update(isolated_database):

    incident_id = create_incident(
        "Test Incident",
        "Test description",
        "LOW",
    )

    result = update_incident_status(
        incident_id,
        "OPEN",
    )

    assert result is False


# --------------------------------------------------
# INCIDENT SUMMARY TESTS
# --------------------------------------------------

def test_incident_summary(isolated_database):

    create_incident("Incident One", "Test", "HIGH")
    create_incident("Incident Two", "Test", "CRITICAL")

    incidents = get_all_incidents()

    update_incident_status(
        incidents[0]["id"],
        "RESOLVED",
    )

    summary = get_incident_summary()

    assert summary["total"] == 2
    assert summary["open_count"] == 1
    assert summary["resolved_count"] == 1
    assert summary["critical_count"] == 1


def test_empty_incident_summary(isolated_database):

    summary = get_incident_summary()

    assert summary["total"] == 0
    assert summary["open_count"] == 0
    assert summary["investigating_count"] == 0
    assert summary["resolved_count"] == 0
    assert summary["critical_count"] == 0
