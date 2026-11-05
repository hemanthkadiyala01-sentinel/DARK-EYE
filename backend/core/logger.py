import logging

from backend.core.constants import LOG_DIR

LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "dark_eye.log"

_configured = False


def get_logger():
    global _configured
    if not _configured:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(),
            ],
        )
        _configured = True
    return logging.getLogger("DARK-EYE")
