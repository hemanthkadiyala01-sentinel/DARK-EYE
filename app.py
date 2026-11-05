from pathlib import Path

from backend.core.file_manager import FileManager
from backend.core.logger import get_logger


class DarkEyeCore:

    def __init__(self):
        self.logger = get_logger("DARK-EYE")

        self.file_manager = FileManager()

        self.logger.info(
            "DARK-EYE Core initialized"
        )


    def scan_system(self, path):

        self.logger.info(
            f"Scanning directory: {path}"
        )

        files = self.file_manager.scan_directory(path)

        self.logger.info(
            f"Found {len(files)} files"
        )

        return files


    def analyze_file(self, path):

        metadata = self.file_manager.metadata(path)

        checksum = self.file_manager.sha256(path)

        return {
            "metadata": metadata,
            "sha256": checksum
        }