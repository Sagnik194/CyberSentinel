
import uuid

import pytest

import database.db as database
from database.db import get_connection, init_db
from modules.authentication.service import (
    register_user,
    authenticate_user
)


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    test_database = tmp_path / "authentication_test.db"
    monkeypatch.setattr(database, "DATABASE_PATH", test_database)
    init_db()
    yield


@pytest.fixture
def test_username(isolated_database):
    username = f"test_{uuid.uuid4().hex[:10]}"

    yield username

    with get_connection() as connection:
        connection.execute(
            "DELETE FROM login_attempts WHERE username = ?",
            (username,)
        )
        connection.execute(
            "DELETE FROM users WHERE username = ?",
            (username,)
        )


def test_user_registration(test_username):
    success, message = register_user(
        test_username,
        "SecurePass123"
    )

    assert success is True
    assert message == "User registered successfully."

    from database.db import fetch_all
    rows = fetch_all(
        "SELECT role FROM users WHERE username = ?",
        (test_username,),
    )
    assert rows[0]["role"] == "analyst"


def test_duplicate_registration(test_username):
    register_user(test_username, "SecurePass123")

    success, message = register_user(
        test_username,
        "AnotherPass123"
    )

    assert success is False
    assert message == "Username already exists."


def test_successful_login(test_username):
    register_user(test_username, "SecurePass123")

    success, message, user = authenticate_user(
        test_username,
        "SecurePass123"
    )

    assert success is True
    assert message == "Login successful."
    assert user["username"] == test_username
    assert user["role"] == "analyst"


def test_brute_force_detection(test_username):
    register_user(test_username, "SecurePass123")

    for _ in range(5):
        success, message, user = authenticate_user(
            test_username,
            "WrongPassword123"
        )

        assert success is False

    success, message, user = authenticate_user(
        test_username,
        "SecurePass123"
    )

    assert success is False
    assert "locked" in message.lower()


def test_registration_rejects_non_text_username():
    success, message = register_user(None, "SecurePass123")

    assert success is False
    assert message == "Username must be text."


def test_registration_rejects_non_text_password():
    success, message = register_user("valid_user", None)

    assert success is False
    assert message == "Password must be text."
