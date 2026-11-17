"""Central configuration. Paths can be overridden with environment variables."""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

MODEL_PATH = Path(os.environ.get("PHISHGUARD_MODEL", PROJECT_ROOT / "model" / "phishing_model.pkl"))
MODEL_REPORT_PATH = Path(os.environ.get("PHISHGUARD_REPORT", PROJECT_ROOT / "model" / "model_report.json"))
DATASET_PATH = Path(os.environ.get("PHISHGUARD_DATASET", PROJECT_ROOT / "dataset" / "phishguard_balanced_10000.csv"))
DB_PATH = Path(os.environ.get("PHISHGUARD_DB", PROJECT_ROOT / "phishguard.db"))

APP_VERSION = "3.0"
