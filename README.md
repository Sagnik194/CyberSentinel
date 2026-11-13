# CyberSentinel

**Security Monitoring & Threat Detection Platform**

CyberSentinel is an educational Python application that brings together account security, file integrity monitoring, offline security-log analysis, authorized network assessment, incident tracking, and CSV/ZIP reporting in one Streamlit dashboard.

> **Scope:** CyberSentinel is a portfolio/learning prototype. It is not a production SIEM, endpoint detection platform, or professional vulnerability scanner. Network scans must be limited to systems you own or are explicitly authorized to assess.

## Features

1. **Authentication Security** – bcrypt password hashing, failed-login tracking, and temporary lockout after repeated failures. Public registration creates analyst accounts only.
2. **File Integrity Monitoring** – SHA-256 snapshots and detection of created, modified, unchanged, and deleted files in the configured monitored directory.
3. **Security Log Analyzer** – offline analysis of uploaded `.log` and `.txt` files, up to 5 MB, for login activity and selected suspicious patterns.
4. **Network Security Assessment** – Nmap TCP connect scan with service/version detection for localhost and private IP addresses only.
5. **Incident Response & Management** – create incidents, set severity, track status, and review incident summaries.
6. **Security Dashboard & Reporting** – summary charts plus four CSV reports and a ZIP containing all reports.

## Technology Stack

- Python 3.12+
- Streamlit
- SQLite
- bcrypt
- Plotly
- Nmap
- Pytest

## Project Structure

```text
CyberSentinel/
├── app.py
├── config/
│   └── settings.py
├── database/
│   └── db.py
├── modules/
│   ├── authentication/
│   ├── file_integrity/
│   ├── log_analyzer/
│   ├── network_scanner/
│   ├── incident_response/
│   └── reporting/
├── tests/
├── data/
│   ├── logs/
│   ├── monitored/
│   └── reports/
├── .streamlit/
│   └── config.toml
├── .env.example
├── .gitignore
└── requirements.txt
```

## Requirements

- Python 3.12 or later
- Nmap installed and available on your system PATH for the network assessment module

### Install Nmap on Windows

Download and install Nmap from the official Nmap website: https://nmap.org/download.html

Open a new PowerShell terminal and verify:

```powershell
nmap --version
```

The other application modules work without Nmap, but the network assessment module requires it.

## Installation on Windows

Open PowerShell in the project directory.

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If Windows Application Control blocks a standalone `pip.exe` or `streamlit.exe` launcher, use the `python -m` commands shown here rather than disabling Windows security controls.

### 3. Create the local environment file

```powershell
Copy-Item .env.example .env
```

The default settings are sufficient for local development. Do not commit `.env`.

### 4. Run the application

```powershell
python -m streamlit run app.py
```

Open the local URL printed in the terminal, normally `http://localhost:8501`.

Create an account from the registration tab. New public accounts are assigned the Analyst role.

## Run Tests

With the virtual environment activated:

```powershell
python -m pytest -v
```

For a concise summary:

```powershell
python -m pytest -q
```

The tests use temporary SQLite databases and should not modify your real application database.

## Data and Configuration

- SQLite database: `data/cybersentinel.db` (created automatically)
- Uploaded log analysis temporary files: `data/logs/` (removed after analysis)
- Monitored directory: `data/monitored/`
- Generated report downloads are created in memory and are not automatically stored on disk
- Streamlit upload limit: 5 MB, configured in `.streamlit/config.toml`

## Security Notes and Limitations

- Public registration always creates an Analyst account; it does not accept a role from the browser.
- Passwords are hashed with bcrypt. Passwords are not stored in plaintext.
- The log analyzer processes uploaded files only; it does not continuously monitor operating-system logs.
- File integrity monitoring only watches the configured monitored directory.
- Network scanning is restricted to loopback/private IP addresses and scans the top 1,000 TCP ports. It is not a vulnerability scanner. Only scan authorized systems.
- An open port does not automatically indicate a vulnerability.
- SQLite and Streamlit are used for a local educational prototype. Review architecture, authentication, deployment, logging, and access controls before any real-world or multi-user deployment.

## License

Add a license before redistributing this project. Until then, all rights are reserved by the project owner.
