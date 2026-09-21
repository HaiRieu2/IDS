from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT/"data"
RAW_DATA_DIR= DATA_DIR/"raw"
CONFIG_DATA = PROJECT_ROOT/"config"
ALERT_DATA = DATA_DIR/"alert"
SESSION_DATA = DATA_DIR/"sessions"

