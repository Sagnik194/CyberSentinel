
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

from pathlib import Path
from datetime import datetime, timezone


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

NMAP_FALLBACK_PATH = Path(
    r"C:\Program Files (x86)\Nmap\nmap.exe"
)

SCAN_TIMEOUT = 180

TOP_PORTS = 1000


# --------------------------------------------------
# 1. LOCATE NMAP
# --------------------------------------------------

def get_nmap_path():

    nmap_path = shutil.which("nmap")

    if nmap_path:
        return nmap_path

    if NMAP_FALLBACK_PATH.exists():
        return str(NMAP_FALLBACK_PATH)

    raise FileNotFoundError(
        "Nmap was not found. Install Nmap or configure its PATH."
    )


# --------------------------------------------------
# 2. VALIDATE TARGET
# --------------------------------------------------

def validate_target(target):

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Enter a valid IPv4 or IPv6 address.")

    try:
        ip = ipaddress.ip_address(target.strip())

    except ValueError:
        raise ValueError(
            "Enter a valid IPv4 or IPv6 address."
        )

    is_allowed_private = (
        ip.is_private
        and not ip.is_link_local
        and not ip.is_reserved
        and not ip.is_multicast
        and not ip.is_unspecified
    )

    if not (ip.is_loopback or is_allowed_private):
        raise ValueError(
            "Only localhost or private network IP addresses "
            "are allowed."
        )

    return str(ip)


# --------------------------------------------------
# 3. PARSE NMAP XML OUTPUT
# --------------------------------------------------


def parse_nmap_output(xml_output):
    try:
        # Remove whitespace before the XML declaration.
        xml_output = xml_output.strip()

        root = ET.fromstring(xml_output)

    except ET.ParseError as error:
        raise RuntimeError(
            f"Could not parse Nmap output: {error}"
        )

    results = []

    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state_element = port.find("state")

            if state_element is None:
                continue

            state = state_element.get("state", "unknown")

            # Store only open ports.
            if state != "open":
                continue

            service_element = port.find("service")

            service_name = "unknown"
            product = None
            version = None

            if service_element is not None:
                service_name = service_element.get(
                    "name", "unknown"
                )
                product = service_element.get("product")
                version = service_element.get("version")

            service_details = " ".join(
                value
                for value in [product, version]
                if value
            )

            results.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol", "tcp"),
                "service": service_name,
                "version": service_details or None,
                "state": state,
            })

    return results


# --------------------------------------------------
# 4. RUN NETWORK SCAN
# --------------------------------------------------

def scan_network(target):

    validated_target = validate_target(target)

    nmap_path = get_nmap_path()

    command = [
        nmap_path,
        "-sT",
        "-sV",
        "-T3",
        "--top-ports",
        str(TOP_PORTS),
        "-oX",
        "-",
        validated_target,
    ]

    started_at = datetime.now(timezone.utc).isoformat()

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            check=False,
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Network scan timed out. Try again later."
        )

    except OSError as error:
        raise RuntimeError(
            f"Could not execute Nmap: {error}"
        )

    if process.returncode != 0:

        raise RuntimeError(
            process.stderr.strip() or
            "Nmap scan failed."
        )

    ports = parse_nmap_output(process.stdout)

    return {
        "target": validated_target,
        "started_at": started_at,
        "total_open_ports": len(ports),
        "ports": ports,
    }


# --------------------------------------------------
# 5. SAVE SCAN RESULTS TO SQLITE
# --------------------------------------------------


def save_scan_results(scan_results):
    """Persist one scan run and all its discovered open ports."""

    from database.db import get_connection

    if not isinstance(scan_results, dict):
        raise ValueError("Invalid scan results.")

    target = scan_results.get("target")
    started_at = scan_results.get("started_at")
    ports = scan_results.get("ports")

    validated_target = validate_target(target)

    if not isinstance(started_at, str) or not started_at.strip() or len(started_at) > 64:
        raise ValueError("Invalid scan timestamp.")

    total_open_ports = scan_results.get("total_open_ports")
    if (
        isinstance(total_open_ports, bool)
        or not isinstance(total_open_ports, int)
        or total_open_ports < 0
    ):
        raise ValueError("Invalid open-port count.")

    if not isinstance(ports, list):
        raise ValueError("Invalid scan port list.")

    if total_open_ports != len(ports):
        raise ValueError("Open-port count does not match scan results.")

    validated_ports = []

    for port_info in ports:
        if not isinstance(port_info, dict):
            raise ValueError("Invalid port result.")

        port_number = port_info.get("port")
        protocol = port_info.get("protocol", "tcp")
        service = port_info.get("service", "unknown")
        state = port_info.get("state")

        if (
            isinstance(port_number, bool)
            or not isinstance(port_number, int)
            or not 1 <= port_number <= 65535
        ):
            raise ValueError("Invalid network port number.")

        if not isinstance(protocol, str) or protocol not in {"tcp", "udp"}:
            raise ValueError("Invalid network protocol.")

        if state != "open":
            raise ValueError("Only open ports can be saved.")

        if not isinstance(service, str) or len(service) > 100:
            raise ValueError("Invalid network service name.")

        validated_ports.append({
            "port": port_number,
            "protocol": protocol,
            "service": service,
            "state": state,
        })

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO network_scan_runs (
                target,
                total_open_ports,
                scanned_at
            )
            VALUES (?, ?, ?)
            """,
            (validated_target, len(validated_ports), started_at),
        )

        scan_run_id = cursor.lastrowid

        for port_info in validated_ports:
            connection.execute(
                """
                INSERT INTO network_scans (
                    scan_run_id,
                    target,
                    port,
                    protocol,
                    service,
                    state,
                    scanned_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_run_id,
                    validated_target,
                    port_info["port"],
                    port_info["protocol"],
                    port_info["service"],
                    port_info["state"],
                    started_at,
                ),
            )

    return {
        "scan_run_id": scan_run_id,
        "saved_ports": len(validated_ports),
    }
