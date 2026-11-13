
import hashlib
import tempfile
from pathlib import Path
import plotly.graph_objects as go
import streamlit as st

from config.settings import (
    APP_NAME,
    APP_VERSION,
    MONITORED_DIR,
    LOG_DIR,
)

from database.db import init_db, fetch_all

from modules.authentication.service import (
    register_user,
    authenticate_user,
)

from modules.file_integrity.service import (
    scan_directory,
    get_file_snapshots,
)

from modules.log_analyzer.service import (
    analyze_log_file,
    save_analysis_events,
)

from modules.network_scanner.service import (
    scan_network,
    save_scan_results,
)

from modules.incident_response.service import (
    create_incident,
    update_incident_status,
    get_all_incidents,
    get_incident_summary,
)

from modules.reporting.service import (
    generate_csv_report,
    generate_complete_report_zip,
)


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "last_file_scan" not in st.session_state:
    st.session_state.last_file_scan = None

if "log_analysis_results" not in st.session_state:
    st.session_state.log_analysis_results = None

if "log_analysis_hash" not in st.session_state:
    st.session_state.log_analysis_hash = None

if "last_network_scan" not in st.session_state:
    st.session_state.last_network_scan = None


# --------------------------------------------------
# AUTHENTICATION PAGE
# --------------------------------------------------

def show_authentication_page():

    st.title("🛡️ CyberSentinel")

    st.caption(
        "Security Monitoring & Threat Detection Platform"
    )

    st.divider()

    login_tab, register_tab = st.tabs(
        ["Login", "Create Account"]
    )

    # ---------------- LOGIN ----------------

    with login_tab:

        st.subheader("Welcome Back")

        with st.form("login_form"):

            username = st.text_input("Username")

            password = st.text_input(
                "Password",
                type="password",
            )

            submitted = st.form_submit_button(
                "Login",
                use_container_width=True,
            )

            if submitted:

                if not username or not password:

                    st.error(
                        "Enter both username and password."
                    )

                else:

                    success, message, user = authenticate_user(
                        username,
                        password,
                    )

                    if success:

                        st.session_state.authenticated = True
                        st.session_state.current_user = user

                        st.success(message)

                        st.rerun()

                    else:

                        st.error(message)

    # ---------------- REGISTRATION ----------------

    with register_tab:

        st.subheader("Create a New Account")

        st.caption(
            "New accounts are automatically registered "
            "with the Analyst role."
        )

        with st.form("register_form"):

            new_username = st.text_input(
                "Choose Username"
            )

            new_password = st.text_input(
                "Choose Password",
                type="password",
            )

            confirm_password = st.text_input(
                "Confirm Password",
                type="password",
            )

            submitted = st.form_submit_button(
                "Create Account",
                use_container_width=True,
            )

            if submitted:

                if not new_username or not new_password:

                    st.error("All fields are required.")

                elif new_password != confirm_password:

                    st.error("Passwords do not match.")

                else:

                    success, message = register_user(
                        new_username,
                        new_password,
                    )

                    if success:

                        st.success(message)

                    else:

                        st.error(message)


# --------------------------------------------------
# DASHBOARD OVERVIEW
# --------------------------------------------------


def show_dashboard_overview():

    st.title("🛡️ Security Dashboard")

    st.caption(
        "Centralized overview of security activities, "
        "incidents and network assessments."
    )

    st.divider()

    # --------------------------------------------------
    # 1. FETCH DASHBOARD METRICS
    # --------------------------------------------------

    users = fetch_all(
        "SELECT COUNT(*) AS total FROM users"
    )

    events = fetch_all(
        "SELECT COUNT(*) AS total FROM security_events"
    )

    incidents = fetch_all(
        "SELECT COUNT(*) AS total FROM incidents"
    )

    high_events = fetch_all(
        """
        SELECT COUNT(*) AS total
        FROM security_events
        WHERE severity IN ('HIGH', 'CRITICAL')
        """
    )

    network_scans = fetch_all(
        "SELECT COUNT(*) AS total FROM network_scan_runs"
    )

    file_records = fetch_all(
        "SELECT COUNT(*) AS total FROM file_snapshots"
    )

    # --------------------------------------------------
    # 2. DISPLAY KEY METRICS
    # --------------------------------------------------

    st.subheader("Security Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Registered Users",
        users[0]["total"]
    )

    col2.metric(
        "Security Events",
        events[0]["total"]
    )

    col3.metric(
        "High/Critical Events",
        high_events[0]["total"]
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Incidents",
        incidents[0]["total"]
    )

    col2.metric(
        "Network Scans",
        network_scans[0]["total"]
    )

    col3.metric(
        "File Records",
        file_records[0]["total"]
    )

    st.divider()

    # --------------------------------------------------
    # 3. SECURITY EVENT ANALYSIS
    # --------------------------------------------------

    st.subheader("Security Event Analysis")

    severity_data = fetch_all(
        """
        SELECT severity, COUNT(*) AS total
        FROM security_events
        GROUP BY severity
        ORDER BY total DESC
        """
    )

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:

        st.markdown("**Security Events by Severity**")

        if severity_data:

            severity_chart = go.Figure(
                data=[
                    go.Pie(
                        labels=[
                            row["severity"]
                            for row in severity_data
                        ],
                        values=[
                            row["total"]
                            for row in severity_data
                        ],
                        hole=0.5,
                    )
                ]
            )

            severity_chart.update_layout(
                margin=dict(
                    t=20,
                    b=20,
                    l=20,
                    r=20,
                ),
            )

            st.plotly_chart(
                severity_chart,
                width="stretch",
            )

        else:

            st.info(
                "No security event data available yet."
            )

    # --------------------------------------------------
    # 4. INCIDENT STATUS ANALYSIS
    # --------------------------------------------------

    with chart_col2:

        st.markdown("**Incidents by Status**")

        incident_data = fetch_all(
            """
            SELECT status, COUNT(*) AS total
            FROM incidents
            GROUP BY status
            ORDER BY total DESC
            """
        )

        if incident_data:

            incident_chart = go.Figure(
                data=[
                    go.Bar(
                        x=[
                            row["status"]
                            for row in incident_data
                        ],
                        y=[
                            row["total"]
                            for row in incident_data
                        ],
                    )
                ]
            )

            incident_chart.update_layout(
                xaxis_title="Incident Status",
                yaxis_title="Number of Incidents",
                margin=dict(
                    t=20,
                    b=20,
                    l=20,
                    r=20,
                ),
            )

            st.plotly_chart(
                incident_chart,
                width="stretch",
            )

        else:

            st.info(
                "No incident data available yet."
            )

    st.divider()

    # --------------------------------------------------
    # 5. SECURITY MODULES
    # --------------------------------------------------

    st.subheader("Security Modules")

    col1, col2 = st.columns(2)

    with col1:

        with st.container(border=True):

            st.subheader("🔐 Authentication Security")

            st.write(
                "Secure login, password hashing and "
                "brute-force detection."
            )

        with st.container(border=True):

            st.subheader("📁 File Integrity Monitoring")

            st.write(
                "Monitor files using SHA-256 hashes "
                "and detect unauthorized changes."
            )

        with st.container(border=True):

            st.subheader("📋 Security Log Analyzer")

            st.write(
                "Analyze uploaded logs and identify "
                "suspicious login activity."
            )

    with col2:

        with st.container(border=True):

            st.subheader("🌐 Network Security Assessment")

            st.write(
                "Assess authorized network targets "
                "and identify open ports and services."
            )

        with st.container(border=True):

            st.subheader("🚨 Incident Response")

            st.write(
                "Create, investigate, track and resolve "
                "security incidents."
            )

        with st.container(border=True):

            st.subheader("📊 Security Reports")

            st.write(
                "Export security events, incidents, "
                "network assessments and file integrity reports."
            )

    st.divider()

    # --------------------------------------------------
    # 6. RECENT SECURITY EVENTS
    # --------------------------------------------------

    st.subheader("Recent Security Events")

    recent_events = fetch_all(
        """
        SELECT event_type, severity, description,
               source, created_at
        FROM security_events
        ORDER BY id DESC
        LIMIT 5
        """
    )

    if not recent_events:

        st.info(
            "No security events recorded yet."
        )

    else:

        for event in recent_events:

            with st.container(border=True):

                st.write(
                    f"**{event['event_type']}** "
                    f"— {event['severity']}"
                )

                st.write(
                    event["description"]
                )

                st.caption(
                    f"Source: {event['source'] or 'Unknown'} "
                    f"| Time: {event['created_at']}"
                )
# --------------------------------------------------
# FILE INTEGRITY MONITORING
# --------------------------------------------------

def show_file_integrity_page():

    st.title("📁 File Integrity Monitoring")

    st.write(
        "Detect file creation, modification and deletion "
        "using SHA-256 hashing."
    )

    st.divider()

    if st.button("🔍 Scan Monitored Files"):

        try:

            summary = scan_directory(MONITORED_DIR)

            st.session_state.last_file_scan = summary

            st.success(
                "File integrity scan completed."
            )

        except Exception as error:

            st.error(
                f"Scan failed: {error}"
            )

    summary = st.session_state.last_file_scan

    if summary:

        st.subheader("Latest Scan Results")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Created",
            summary.get("created", 0),
        )

        col2.metric(
            "Modified",
            summary.get("modified", 0),
        )

        col3.metric(
            "Deleted",
            summary.get("deleted", 0),
        )

        col4.metric(
            "Unchanged",
            summary.get("unchanged", 0),
        )

    st.divider()

    st.subheader("File Snapshots")

    snapshots = get_file_snapshots()

    monitored_root = Path(MONITORED_DIR).resolve()

    visible_snapshots = []

    for snapshot in snapshots:

        try:

            file_path = Path(
                snapshot["file_path"]
            ).resolve()

            if file_path.is_relative_to(monitored_root):

                visible_snapshots.append(snapshot)

        except (ValueError, OSError):

            continue

    if not visible_snapshots:

        st.info(
            "No file snapshots available. "
            "Add a file to the monitored folder and scan it."
        )

    else:

        for snapshot in visible_snapshots:

            with st.container(border=True):

                st.write(
                    f"**{Path(snapshot['file_path']).name}**"
                )

                st.caption(
                    f"Status: {snapshot['status']} "
                    f"| Size: {snapshot['file_size']} bytes"
                )

                st.code(
                    snapshot["file_hash"],
                    language=None,
                )

                st.caption(
                    f"Last scanned: {snapshot['scanned_at']}"
                )


# --------------------------------------------------
# SECURITY LOG ANALYZER
# --------------------------------------------------

def show_log_analyzer_page():

    st.title("📋 Security Log Analyzer")

    st.write(
        "Upload a .log or .txt file to identify failed logins, "
        "successful logins and suspicious IP addresses."
    )

    st.info(
        "This is an offline log analyzer. "
        "It analyzes uploaded files and does not monitor "
        "live system logs."
    )

    st.divider()

    uploaded_file = st.file_uploader(
        "Upload a security log file",
        type=["log", "txt"],
        help="Maximum file size: 5 MB.",
    )

    if uploaded_file is None:

        st.session_state.log_analysis_results = None
        st.session_state.log_analysis_hash = None

        st.info(
            "Upload a log file to begin analysis."
        )

        return

    # --------------------------------------------------
    # 1. VALIDATE FILE NAME AND EXTENSION
    # --------------------------------------------------

    original_name = Path(uploaded_file.name).name

    file_extension = Path(original_name).suffix.lower()

    if file_extension not in {".log", ".txt"}:

        st.error(
            "Only .log and .txt files are supported."
        )

        return

    # --------------------------------------------------
    # 2. CHECK FILE SIZE
    # --------------------------------------------------

    file_size = uploaded_file.size

    st.write(
        f"**Selected file:** {original_name}"
    )

    st.write(
        f"**File size:** {file_size:,} bytes"
    )

    MAX_FILE_SIZE = 5 * 1024 * 1024

    if file_size > MAX_FILE_SIZE:

        st.error(
            "File exceeds the 5 MB upload limit."
        )

        return

    if file_size == 0:

        st.error(
            "The uploaded file is empty."
        )

        return

    # --------------------------------------------------
    # 3. READ AND VERIFY FILE CONTENT
    # --------------------------------------------------

    file_content = uploaded_file.getvalue()

    if not file_content:

        st.error(
            "The uploaded file contains no data."
        )

        return

    if len(file_content) > MAX_FILE_SIZE:

        st.error(
            "File exceeds the 5 MB upload limit."
        )

        return

    file_hash = hashlib.sha256(
        file_content
    ).hexdigest()

    # --------------------------------------------------
    # 4. ANALYZE LOG FILE
    # --------------------------------------------------

    if st.button(
        "🔍 Analyze Log File",
        width="stretch",
    ):

        temporary_path = None

        try:

            LOG_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            with tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=file_extension,
                prefix="analysis_",
                dir=LOG_DIR,
                delete=False,
            ) as temporary_file:

                temporary_file.write(file_content)

                temporary_path = Path(
                    temporary_file.name
                )

            results = analyze_log_file(
                temporary_path
            )

            # Save events only once per file hash
            if st.session_state.log_analysis_hash != file_hash:

                saved_count = save_analysis_events(
                    results
                )

                st.session_state.log_analysis_hash = file_hash

                st.success(
                    f"Analysis completed. "
                    f"{saved_count} events saved to the database."
                )

            else:

                st.info(
                    "This file has already been analyzed "
                    "in this session. Events were not saved again."
                )

            st.session_state.log_analysis_results = results

        except (ValueError, OSError) as error:

            st.error(
                f"Log analysis failed: {error}"
            )

        except Exception as error:

            st.error(
                f"Unexpected analysis error: {error}"
            )

        finally:

            if temporary_path is not None:

                try:

                    if temporary_path.exists():
                        temporary_path.unlink()

                except OSError:

                    st.warning(
                        "Temporary log file could not be deleted. "
                        "Please check the application's log directory."
                    )

    # --------------------------------------------------
    # 5. DISPLAY ANALYSIS RESULTS
    # --------------------------------------------------

    results = st.session_state.log_analysis_results

    if not results:
        return

    st.divider()

    st.subheader("Analysis Summary")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Log Lines",
        results["total_lines"],
    )

    col2.metric(
        "Failed Logins",
        results["failed_logins"],
    )

    col3.metric(
        "Successful Logins",
        results["successful_logins"],
    )

    col4.metric(
        "Suspicious IPs",
        len(results["suspicious_ips"]),
    )

    if results.get("events_truncated"):

        st.warning(
            "The event display limit of 10,000 was reached. "
            "Login counts and suspicious IP analysis still "
            "include the entire file."
        )

    st.divider()

    # --------------------------------------------------
    # 6. SUSPICIOUS IP ADDRESSES
    # --------------------------------------------------

    st.subheader("🚨 Suspicious IP Addresses")

    if not results["suspicious_ips"]:

        st.success(
            "No suspicious IP addresses detected."
        )

    else:

        for suspicious_ip in results["suspicious_ips"]:

            with st.container(border=True):

                st.write(
                    f"**IP Address:** "
                    f"{suspicious_ip['ip_address']}"
                )

                st.write(
                    f"Failed attempts: "
                    f"{suspicious_ip['failed_attempts']}"
                )

                st.error(
                    f"Severity: {suspicious_ip['severity']}"
                )

    st.divider()

    # --------------------------------------------------
    # 7. DETECTED SECURITY EVENTS
    # --------------------------------------------------

    st.subheader("Detected Security Events")

    if not results["events"]:

        st.info(
            "No security events detected."
        )

    else:

        for event in results["events"]:

            with st.container(border=True):

                st.write(
                    f"**{event['event_type']}** "
                    f"— {event['severity']}"
                )

                st.write(
                    event["description"]
                )

                st.caption(
                    f"Source: {event['source']} "
                    f"| Log line: "
                    f"{event['line_number'] or 'Summary'}"
                )
# --------------------------------------------------
# NETWORK SECURITY ASSESSMENT
# --------------------------------------------------

def show_network_scanner_page():

    st.title("🌐 Network Security Assessment")

    st.write(
        "Perform authorized TCP port scanning and "
        "service detection using Nmap."
    )

    st.warning(
        "Only scan systems you own or have explicit "
        "permission to assess. This module restricts "
        "targets to localhost and private IP addresses."
    )

    st.divider()

    st.subheader("Start Network Scan")

    target = st.text_input(
        "Target IP Address",
        value="127.0.0.1",
        help="Example: 127.0.0.1 or 192.168.1.10",
    )

    st.caption(
        "Scan configuration: TCP connect scan, "
        "top 1,000 ports, service/version detection."
    )

    if st.button(
        "🔍 Start Network Scan",
        use_container_width=True,
    ):

        try:

            with st.spinner(
                f"Scanning {target.strip()}... Please wait."
            ):

                results = scan_network(target)

                saved_info = save_scan_results(results)

                results["scan_run_id"] = saved_info["scan_run_id"]

                st.session_state.last_network_scan = results

            st.success(
                f"Scan completed. "
                f"{saved_info['saved_ports']} open port records saved."
            )

        except (
            ValueError,
            FileNotFoundError,
            RuntimeError,
        ) as error:

            st.error(
                f"Network scan failed: {error}"
            )

        except Exception as error:

            st.error(
                f"Unexpected error: {error}"
            )

    results = st.session_state.last_network_scan

    if results:

        st.divider()

        st.subheader("Latest Scan Results")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Target",
            results["target"],
        )

        col2.metric(
            "Open Ports",
            results["total_open_ports"],
        )

        col3.metric(
            "Scan ID",
            results.get("scan_run_id", "N/A"),
        )

        st.caption(
            f"Scan started: {results['started_at']}"
        )

        st.divider()

        st.subheader("Detected Open Ports")

        if not results["ports"]:

            st.success(
                "No open TCP ports were detected "
                "among the scanned ports."
            )

        else:

            for port_info in results["ports"]:

                with st.container(border=True):

                    st.write(
                        f"**Port {port_info['port']} / "
                        f"{port_info['protocol'].upper()}**"
                    )

                    st.write(
                        f"Service: {port_info['service']}"
                    )

                    st.write(
                        f"Version: "
                        f"{port_info['version'] or 'Not identified'}"
                    )

                    st.success(
                        f"State: {port_info['state'].upper()}"
                    )

        st.caption(
            "An open port is not automatically a vulnerability. "
            "Review the service, configuration and exposure "
            "before drawing security conclusions."
        )

    st.divider()

    st.subheader("📜 Network Scan History")

    history = fetch_all(
        """
        SELECT id, target, total_open_ports, scanned_at
        FROM network_scan_runs
        ORDER BY id DESC
        LIMIT 10
        """
    )

    if not history:

        st.info(
            "No network scans have been recorded yet."
        )

    else:

        for scan in history:

            with st.container(border=True):

                col1, col2, col3 = st.columns(3)

                col1.write(
                    f"**Target:** {scan['target']}"
                )

                col2.write(
                    f"**Open Ports:** {scan['total_open_ports']}"
                )

                col3.write(
                    f"**Scan ID:** {scan['id']}"
                )

                st.caption(
                    f"Scanned at: {scan['scanned_at']}"
                )

                if st.button(
                    "View Scan Details",
                    key=f"view_network_scan_{scan['id']}",
                ):

                    port_history = fetch_all(
                        """
                        SELECT port, protocol, service, state
                        FROM network_scans
                        WHERE scan_run_id = ?
                        ORDER BY port
                        """,
                        (scan["id"],),
                    )

                    if not port_history:

                        st.info(
                            "This scan did not detect any open ports."
                        )

                    else:

                        for port in port_history:

                            st.write(
                                f"Port {port['port']}/"
                                f"{port['protocol']} — "
                                f"{port['service']} — "
                                f"{port['state']}"
                            )


# --------------------------------------------------
# INCIDENT RESPONSE & MANAGEMENT
# --------------------------------------------------

def show_incident_response_page():

    st.title("🚨 Incident Response & Management")

    st.write(
        "Create, investigate, track and resolve "
        "security incidents."
    )

    st.divider()

    summary = get_incident_summary()

    total = summary.get("total") or 0
    open_count = summary.get("open_count") or 0
    investigating_count = summary.get("investigating_count") or 0
    resolved_count = summary.get("resolved_count") or 0
    critical_count = summary.get("critical_count") or 0

    st.subheader("Incident Overview")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total", total)
    col2.metric("Open", open_count)
    col3.metric("Investigating", investigating_count)
    col4.metric("Resolved", resolved_count)
    col5.metric("Critical", critical_count)

    st.divider()

    st.subheader("➕ Create New Incident")

    with st.form("create_incident_form"):

        incident_title = st.text_input(
            "Incident Title",
            max_chars=150,
            placeholder="Example: Suspicious Login Activity",
        )

        incident_description = st.text_area(
            "Incident Description",
            placeholder="Describe what happened...",
        )

        incident_severity = st.selectbox(
            "Severity",
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            index=1,
        )

        submitted = st.form_submit_button(
            "Create Incident",
            use_container_width=True,
        )

        if submitted:

            if not incident_title.strip():

                st.error(
                    "Incident title is required."
                )

            else:

                try:

                    incident_id = create_incident(
                        incident_title,
                        incident_description,
                        incident_severity,
                    )

                    st.success(
                        f"Incident #{incident_id} created successfully."
                    )

                    st.rerun()

                except Exception as error:

                    st.error(
                        f"Could not create incident: {error}"
                    )

    st.divider()

    st.subheader("📋 Incident Management")

    incidents = get_all_incidents()

    if not incidents:

        st.info(
            "No incidents found. Create your first incident above."
        )

        return

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:

        status_filter = st.selectbox(
            "Filter by Status",
            ["ALL", "OPEN", "INVESTIGATING", "RESOLVED"],
            key="incident_status_filter",
        )

    with filter_col2:

        severity_filter = st.selectbox(
            "Filter by Severity",
            ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            key="incident_severity_filter",
        )

    filtered_incidents = []

    for incident in incidents:

        if (
            status_filter != "ALL"
            and incident["status"] != status_filter
        ):

            continue

        if (
            severity_filter != "ALL"
            and incident["severity"] != severity_filter
        ):

            continue

        filtered_incidents.append(incident)

    st.caption(
        f"Showing {len(filtered_incidents)} "
        f"of {len(incidents)} incidents."
    )

    if not filtered_incidents:

        st.info(
            "No incidents match the selected filters."
        )

        return

    for incident in filtered_incidents:

        with st.container(border=True):

            st.write(
                f"### Incident #{incident['id']} — "
                f"{incident['title']}"
            )

            col1, col2 = st.columns(2)

            col1.write(
                f"**Severity:** {incident['severity']}"
            )

            col2.write(
                f"**Status:** {incident['status']}"
            )

            st.write(
                incident["description"]
                or "No description provided."
            )

            st.caption(
                f"Created: {incident['created_at']}"
            )

            if incident["resolved_at"]:

                st.caption(
                    f"Resolved: {incident['resolved_at']}"
                )

            st.divider()

            status_col, button_col = st.columns([3, 1])

            with status_col:

                new_status = st.selectbox(
                    "Update Incident Status",
                    ["OPEN", "INVESTIGATING", "RESOLVED"],
                    index=[
                        "OPEN",
                        "INVESTIGATING",
                        "RESOLVED",
                    ].index(incident["status"]),
                    key=f"incident_status_{incident['id']}",
                )

            with button_col:

                st.write("")

                if st.button(
                    "Update",
                    key=f"update_incident_{incident['id']}",
                    use_container_width=True,
                ):

                    try:

                        changed = update_incident_status(
                            incident["id"],
                            new_status,
                        )

                        if changed:

                            st.success(
                                f"Incident #{incident['id']} "
                                f"updated to {new_status}."
                            )

                        else:

                            st.info(
                                "Incident status is already "
                                "set to this value."
                            )

                        st.rerun()

                    except Exception as error:

                        st.error(
                            f"Could not update incident: {error}"
                        )


# --------------------------------------------------
# SECURITY REPORTING
# --------------------------------------------------

def show_reporting_page():

    st.title("📊 Security Reports & Export")

    st.write(
        "Download security monitoring data as CSV files "
        "or export all reports together in one ZIP archive."
    )

    st.info(
        "Reports are generated from records currently stored "
        "in the CyberSentinel database."
    )

    st.subheader("Individual Reports")

    report_options = [
        (
            "Security Events Report",
            "security_events",
            "security_events_report.csv",
        ),
        (
            "Incident Report",
            "incidents",
            "incident_report.csv",
        ),
        (
            "Network Assessment Report",
            "network_scans",
            "network_assessment_report.csv",
        ),
        (
            "File Integrity Report",
            "file_integrity",
            "file_integrity_report.csv",
        ),
    ]

    columns = st.columns(2)

    for index, (title, report_type, filename) in enumerate(
        report_options
    ):

        with columns[index % 2]:

            with st.container(border=True):

                st.markdown(f"**{title}**")

                try:

                    csv_data = generate_csv_report(
                        report_type
                    )

                    st.download_button(
                        label="Download CSV",
                        data=csv_data,
                        file_name=filename,
                        mime="text/csv",
                        key=f"download_{report_type}",
                        use_container_width=True,
                    )

                except Exception as error:

                    st.error(
                        f"Could not generate this report: {error}"
                    )

    st.divider()

    st.subheader("Complete Security Report")

    st.write(
        "Download all four CSV reports together in a single ZIP file."
    )

    try:

        zip_data = generate_complete_report_zip()

        st.download_button(
            label="📦 Download Complete Report (ZIP)",
            data=zip_data,
            file_name="cybersentinel_complete_security_reports.zip",
            mime="application/zip",
            key="download_complete_report",
            use_container_width=True,
        )

    except Exception as error:

        st.error(
            f"Could not generate the ZIP report: {error}"
        )


# --------------------------------------------------
# MAIN DASHBOARD
# --------------------------------------------------

def show_dashboard():

    user = st.session_state.current_user

    with st.sidebar:

        st.title("🛡️ CyberSentinel")

        st.caption(
            "Security Monitoring Platform"
        )

        st.divider()

        st.write(
            f"**User:** {user['username']}"
        )

        st.write(
            f"**Role:** {user['role']}"
        )

        st.divider()

        selected_page = st.radio(
            "Navigation",
            [
                "Dashboard Overview",
                "File Integrity Monitoring",
                "Security Log Analyzer",
                "Network Security Assessment",
                "Incident Response & Management",
                "Security Reports & Export",
            ],
        )

        st.divider()

        if st.button(
            "Logout",
            use_container_width=True,
        ):

            st.session_state.authenticated = False
            st.session_state.current_user = None
            st.session_state.last_file_scan = None
            st.session_state.log_analysis_results = None
            st.session_state.log_analysis_hash = None
            st.session_state.last_network_scan = None

            st.rerun()

        st.caption(
            f"Version {APP_VERSION}"
        )

    if selected_page == "Dashboard Overview":

        show_dashboard_overview()

    elif selected_page == "File Integrity Monitoring":

        show_file_integrity_page()

    elif selected_page == "Security Log Analyzer":

        show_log_analyzer_page()

    elif selected_page == "Network Security Assessment":

        show_network_scanner_page()

    elif selected_page == "Incident Response & Management":

        show_incident_response_page()

    elif selected_page == "Security Reports & Export":

        show_reporting_page()


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if st.session_state.authenticated:

    show_dashboard()

else:

    show_authentication_page()
