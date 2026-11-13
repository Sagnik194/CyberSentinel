
from modules.log_analyzer.service import (
    extract_ip_address,
    classify_log_line,
    analyze_log_file
)


def test_ip_extraction():

    result = extract_ip_address(
        "Failed password from 203.0.113.45 port 51231"
    )

    assert result == "203.0.113.45"


def test_log_classification():

    assert classify_log_line(
        "Failed password for root"
    ) == "FAILED_LOGIN"

    assert classify_log_line(
        "Accepted password for admin"
    ) == "SUCCESSFUL_LOGIN"

    assert classify_log_line(
        "Normal system activity"
    ) == "NORMAL"


def test_brute_force_detection(tmp_path):

    log_file = tmp_path / "test.log"

    log_file.write_text(
        "\n".join([
            "Failed password from 203.0.113.45",
            "Failed password from 203.0.113.45",
            "Failed password from 203.0.113.45",
            "Failed password from 203.0.113.45",
            "Failed password from 203.0.113.45",
            "Accepted password from 192.168.1.10"
        ])
    )

    results = analyze_log_file(log_file)

    assert results["total_lines"] == 6
    assert results["failed_logins"] == 5
    assert results["successful_logins"] == 1

    assert len(results["suspicious_ips"]) == 1

    assert (
        results["suspicious_ips"][0]["ip_address"]
        == "203.0.113.45"
    )

    assert (
        results["suspicious_ips"][0]["severity"]
        == "HIGH"
    )
