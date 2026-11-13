import re
from collections import Counter
from pathlib import Path

from database.db import log_security_event


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

FAILED_LOGIN_PATTERNS = [
    r"failed password",
    r"authentication failure",
    r"failed login",
    r"invalid user",
    r"login incorrect",
]

SUCCESS_LOGIN_PATTERNS = [
    r"accepted password",
    r"accepted publickey",
    r"successful login",
]

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

BRUTE_FORCE_THRESHOLD = 5

MAX_LOG_FILE_SIZE = 5 * 1024 * 1024
MAX_EVENTS = 10000

ALLOWED_EXTENSIONS = {
    ".log",
    ".txt",
}

ALLOWED_EVENT_TYPES = {
    "FAILED_LOGIN",
    "SUCCESSFUL_LOGIN",
    "PRIVILEGE_USAGE",
    "APPLICATION_CRASH",
    "PERMISSION_DENIED",
    "BRUTE_FORCE_DETECTED",
}

ALLOWED_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


# --------------------------------------------------
# IP EXTRACTION
# --------------------------------------------------

def extract_ip_address(log_line: str):

    if not isinstance(log_line, str):
        return None

    match = IP_PATTERN.search(log_line)

    if not match:
        return None

    ip = match.group()

    parts = ip.split(".")

    if not all(0 <= int(part) <= 255 for part in parts):
        return None

    return ip


# --------------------------------------------------
# LOG CLASSIFICATION
# --------------------------------------------------

def classify_log_line(log_line: str):

    if not isinstance(log_line, str):
        raise ValueError("Log line must be text.")

    normalized = log_line.lower()

    if any(
        pattern in normalized
        for pattern in FAILED_LOGIN_PATTERNS
    ):
        return "FAILED_LOGIN"

    if any(
        pattern in normalized
        for pattern in SUCCESS_LOGIN_PATTERNS
    ):
        return "SUCCESSFUL_LOGIN"

    if "sudo:" in normalized and "command=" in normalized:
        return "PRIVILEGE_USAGE"

    if "segmentation fault" in normalized:
        return "APPLICATION_CRASH"

    if "permission denied" in normalized:
        return "PERMISSION_DENIED"

    return "NORMAL"


# --------------------------------------------------
# SAFE EVENT APPENDING
# --------------------------------------------------

def _append_event(results, event):

    if len(results["events"]) < MAX_EVENTS:
        results["events"].append(event)
    else:
        results["events_truncated"] = True


# --------------------------------------------------
# LOG FILE ANALYSIS
# --------------------------------------------------

def analyze_log_file(file_path):

    if not isinstance(file_path, (str, Path)):
        raise ValueError("Invalid log file path.")

    path = Path(file_path)

    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Only .log and .txt files are supported."
        )

    try:
        resolved_path = path.resolve(strict=True)

        if not resolved_path.is_file():
            raise ValueError(
                "The specified path is not a regular file."
            )

        file_size = resolved_path.stat().st_size

    except FileNotFoundError:
        raise ValueError(
            "The specified log file does not exist."
        )

    except OSError as error:
        raise ValueError(
            f"Unable to access log file: {error}"
        )

    if file_size == 0:
        raise ValueError("The log file is empty.")

    if file_size > MAX_LOG_FILE_SIZE:
        raise ValueError(
            "Log file cannot exceed 5 MB."
        )

    results = {
        "total_lines": 0,
        "failed_logins": 0,
        "successful_logins": 0,
        "suspicious_ips": [],
        "events": [],
        "errors": [],
        "events_truncated": False,
    }

    failed_ip_counts = Counter()

    try:

        with resolved_path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:

            for line_number, line in enumerate(file, start=1):

                line = line.strip()

                if not line:
                    continue

                results["total_lines"] += 1

                event_type = classify_log_line(line)

                ip_address = extract_ip_address(line)

                if event_type == "FAILED_LOGIN":

                    results["failed_logins"] += 1

                    if ip_address:
                        failed_ip_counts[ip_address] += 1

                    _append_event(
                        results,
                        {
                            "line_number": line_number,
                            "event_type": event_type,
                            "severity": "MEDIUM",
                            "description": line,
                            "source": ip_address or "Unknown",
                        },
                    )

                elif event_type == "SUCCESSFUL_LOGIN":

                    results["successful_logins"] += 1

                    _append_event(
                        results,
                        {
                            "line_number": line_number,
                            "event_type": event_type,
                            "severity": "LOW",
                            "description": line,
                            "source": ip_address or "Unknown",
                        },
                    )

                elif event_type == "PRIVILEGE_USAGE":

                    _append_event(
                        results,
                        {
                            "line_number": line_number,
                            "event_type": event_type,
                            "severity": "MEDIUM",
                            "description": line,
                            "source": ip_address or "Local system",
                        },
                    )

                elif event_type == "APPLICATION_CRASH":

                    _append_event(
                        results,
                        {
                            "line_number": line_number,
                            "event_type": event_type,
                            "severity": "MEDIUM",
                            "description": line,
                            "source": ip_address or "Local system",
                        },
                    )

                elif event_type == "PERMISSION_DENIED":

                    _append_event(
                        results,
                        {
                            "line_number": line_number,
                            "event_type": event_type,
                            "severity": "LOW",
                            "description": line,
                            "source": ip_address or "Unknown",
                        },
                    )

    except OSError as error:

        raise ValueError(
            f"Unable to read log file: {error}"
        )

    # --------------------------------------------------
    # BRUTE-FORCE DETECTION
    # --------------------------------------------------

    for ip_address, count in failed_ip_counts.items():

        if count >= BRUTE_FORCE_THRESHOLD:

            results["suspicious_ips"].append(
                {
                    "ip_address": ip_address,
                    "failed_attempts": count,
                    "severity": "HIGH",
                }
            )

            _append_event(
                results,
                {
                    "line_number": None,
                    "event_type": "BRUTE_FORCE_DETECTED",
                    "severity": "HIGH",
                    "description": (
                        f"{count} failed login attempts "
                        f"detected from IP address {ip_address}."
                    ),
                    "source": ip_address,
                },
            )

    return results


# --------------------------------------------------
# SAVE SECURITY EVENTS
# --------------------------------------------------

def save_analysis_events(results):

    if not isinstance(results, dict):
        raise ValueError("Invalid analysis results.")

    events = results.get("events")

    if not isinstance(events, list):
        raise ValueError("Invalid security events list.")

    if len(events) > MAX_EVENTS:
        raise ValueError("Too many security events.")

    saved_count = 0

    for event in events:

        if not isinstance(event, dict):
            raise ValueError("Invalid security event.")

        event_type = event.get("event_type")
        severity = event.get("severity")
        description = event.get("description")
        source = event.get("source")

        if event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError("Invalid security event type.")

        if severity not in ALLOWED_SEVERITIES:
            raise ValueError("Invalid security event severity.")

        if not isinstance(description, str):
            raise ValueError("Invalid event description.")

        if not isinstance(source, str):
            raise ValueError("Invalid event source.")

        log_security_event(
            event_type=event_type,
            severity=severity,
            description=description,
            source=source,
        )

        saved_count += 1

    return saved_count