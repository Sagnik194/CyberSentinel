import sqlite3

import bcrypt

from database.db import get_connection, fetch_all, log_security_event


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 10
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 64
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 72


def register_user(username: str, password: str):
    """Register a public account as an analyst.

    Public registration cannot assign privileged roles. Administrative
    provisioning must be performed separately by a trusted operator.
    """

    if not isinstance(username, str):
        return False, "Username must be text."

    if not isinstance(password, str):
        return False, "Password must be text."

    username = username.strip().lower()

    if not MIN_USERNAME_LENGTH <= len(username) <= MAX_USERNAME_LENGTH:
        return (
            False,
            f"Username must contain between {MIN_USERNAME_LENGTH} and "
            f"{MAX_USERNAME_LENGTH} characters.",
        )

    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must contain at least {MIN_PASSWORD_LENGTH} characters."

    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False, f"Password must not exceed {MAX_PASSWORD_BYTES} bytes."

    existing = fetch_all(
        "SELECT id FROM users WHERE username = ?",
        (username,),
    )

    if existing:
        return False, "Username already exists."

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12),
    ).decode("utf-8")

    try:
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, 'analyst')
                """,
                (username, password_hash),
            )
    except sqlite3.IntegrityError:
        return False, "Username already exists."

    return True, "User registered successfully."


def get_recent_failed_attempts(username: str) -> int:
    """Count failed logins in the configured lockout window."""

    rows = fetch_all(
        """
        SELECT COUNT(*) AS total
        FROM login_attempts
        WHERE username = ?
          AND success = 0
          AND attempted_at >= datetime('now', ?)
        """,
        (username, f"-{LOCKOUT_WINDOW_MINUTES} minutes"),
    )

    return rows[0]["total"]


def record_login_attempt(username: str, ip_address: str, success: bool):
    """Save a login attempt in the database."""

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO login_attempts (username, ip_address, success)
            VALUES (?, ?, ?)
            """,
            (username, ip_address, int(success)),
        )


def authenticate_user(
    username: str,
    password: str,
    ip_address: str = "127.0.0.1",
):
    """Verify credentials and detect repeated failed logins."""

    if not isinstance(username, str) or not isinstance(password, str):
        return False, "Username and password are required.", None

    username = username.strip().lower()

    if not username or not password:
        return False, "Username and password are required.", None

    failed_attempts = get_recent_failed_attempts(username)

    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        return (
            False,
            "Account temporarily locked due to repeated failed login attempts.",
            None,
        )

    users = fetch_all(
        """
        SELECT id, username, password_hash, role, is_active
        FROM users
        WHERE username = ?
        """,
        (username,),
    )

    authenticated = False
    user = None

    if users:
        user = users[0]

        if user["is_active"]:
            try:
                authenticated = bcrypt.checkpw(
                    password.encode("utf-8"),
                    user["password_hash"].encode("utf-8"),
                )
            except (ValueError, TypeError):
                authenticated = False

    record_login_attempt(username, ip_address, authenticated)

    if authenticated:
        return (
            True,
            "Login successful.",
            {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
        )

    new_failed_count = get_recent_failed_attempts(username)

    if new_failed_count == MAX_FAILED_ATTEMPTS:
        log_security_event(
            event_type="BRUTE_FORCE_DETECTED",
            severity="HIGH",
            description=(
                f"Five failed login attempts detected for username: {username}"
            ),
            source=ip_address,
        )

    return False, "Invalid username or password.", None
