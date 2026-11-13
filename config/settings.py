
import os
from pathlib import Path

from dotenv import load_dotenv


# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
load_dotenv(BASE_DIR / ".env")

# Application settings
APP_NAME = os.getenv(
    "APP_NAME",
    "CyberSentinel"
)

APP_ENV = os.getenv(
    "APP_ENV",
    "development"
)

APP_VERSION = "1.0.0"

# Directory paths
DATA_DIR = BASE_DIR / "data"
LOG_DIR = DATA_DIR / "logs"
REPORT_DIR = DATA_DIR / "reports"
MONITORED_DIR = DATA_DIR / "monitored"

# Database path
DATABASE_PATH = DATA_DIR / "cybersentinel.db"

# Ensure required directories exist
for directory in [
    DATA_DIR,
    LOG_DIR,
    REPORT_DIR,
    MONITORED_DIR
]:
    directory.mkdir(
        parents=True,
        exist_ok=True
    )
