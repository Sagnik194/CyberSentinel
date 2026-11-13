
import pytest

import database.db as database
from database.db import init_db, fetch_all
from modules.network_scanner.service import (
    validate_target,
    parse_nmap_output,
    save_scan_results,
)


# --------------------------------------------------
# TEST 1: VALIDATE LOCALHOST
# --------------------------------------------------

def test_validate_localhost():

    result = validate_target("127.0.0.1")

    assert result == "127.0.0.1"


# --------------------------------------------------
# TEST 2: VALIDATE PRIVATE IP
# --------------------------------------------------

def test_validate_private_ip():

    result = validate_target("192.168.1.10")

    assert result == "192.168.1.10"


# --------------------------------------------------
# TEST 3: REJECT PUBLIC IP
# --------------------------------------------------

def test_reject_public_ip():

    with pytest.raises(ValueError):

        validate_target("8.8.8.8")


# --------------------------------------------------
# TEST 4: REJECT INVALID TARGET
# --------------------------------------------------

def test_reject_invalid_target():

    with pytest.raises(ValueError):

        validate_target("invalid-address")


# --------------------------------------------------
# TEST 5: PARSE NMAP XML
# --------------------------------------------------

def test_parse_nmap_output():

    xml_output = """
    <?xml version="1.0"?>
    <nmaprun>
        <host>
            <ports>
                <port protocol="tcp" portid="3306">
                    <state state="open"/>
                    <service
                        name="mysql"
                        product="MySQL"
                        version="8.0"
                    />
                </port>

                <port protocol="tcp" portid="8080">
                    <state state="closed"/>
                    <service name="http"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """

    results = parse_nmap_output(xml_output)

    assert len(results) == 1

    assert results[0]["port"] == 3306

    assert results[0]["protocol"] == "tcp"

    assert results[0]["service"] == "mysql"

    assert results[0]["version"] == "MySQL 8.0"

    assert results[0]["state"] == "open"


# --------------------------------------------------
# TEST 6: EMPTY SCAN RESULTS
# --------------------------------------------------

def test_parse_empty_nmap_output():

    xml_output = """
    <nmaprun>
        <host>
            <ports></ports>
        </host>
    </nmaprun>
    """

    results = parse_nmap_output(xml_output)

    assert results == []


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    test_database = tmp_path / "network_scanner_test.db"
    monkeypatch.setattr(database, "DATABASE_PATH", test_database)
    init_db()
    yield


def test_save_scan_results_links_ports_to_exact_run(isolated_database):
    scan = {
        "target": "127.0.0.1",
        "started_at": "2026-11-13T10:00:00+00:00",
        "total_open_ports": 1,
        "ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "state": "open",
            }
        ],
    }

    saved = save_scan_results(scan)
    rows = fetch_all(
        "SELECT scan_run_id, port FROM network_scans"
    )

    assert saved["saved_ports"] == 1
    assert rows[0]["scan_run_id"] == saved["scan_run_id"]
    assert rows[0]["port"] == 22


def test_save_scan_results_rejects_invalid_port(isolated_database):
    scan = {
        "target": "127.0.0.1",
        "started_at": "2026-11-13T10:00:00+00:00",
        "total_open_ports": 1,
        "ports": [
            {
                "port": 70000,
                "protocol": "tcp",
                "service": "unknown",
                "state": "open",
            }
        ],
    }

    with pytest.raises(ValueError):
        save_scan_results(scan)


def test_reject_non_text_target():
    with pytest.raises(ValueError):
        validate_target(None)


def test_reject_unspecified_target():
    with pytest.raises(ValueError):
        validate_target("0.0.0.0")


def test_reject_multicast_target():
    with pytest.raises(ValueError):
        validate_target("224.0.0.1")
