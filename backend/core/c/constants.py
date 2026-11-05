"""
Global constants for DARK EYE.
"""

from pathlib import Path

APP_NAME = "DARK EYE"
APP_VERSION = "0.1.0"
AUTHOR = "Hemanth Kadiyala"

PROJECT_NAME = "DARK-EYE"
VERSION = "0.1.0"

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_DIR = BASE_DIR / "logs"

DEFAULT_LOG_LEVEL = "INFO"

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2"