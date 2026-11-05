from pathlib import Path
import hashlib

from backend.database.file_memory import FileMemory


class FileIntelligence:

    CATEGORY_MAP = {
        "image": [".png", ".jpg", ".jpeg", ".gif", ".bmp"],
        "document": [".pdf", ".docx", ".txt", ".xlsx"],
        "code": [".py", ".js", ".java", ".cpp", ".html", ".css"],
        "executable": [".exe", ".bat", ".cmd", ".ps1"]
    }

    def __init__(self):
        self.memory = FileMemory()

    @staticmethod
    def detect_type(path):

        file = Path(path)
        extension = file.suffix.lower()

        for category, extensions in FileIntelligence.CATEGORY_MAP.items():
            if extension in extensions:
                return category

        return "unknown"

    @staticmethod
    def calculate_hash(path):

        sha = hashlib.sha256()

        with open(path, "rb") as f:

            while chunk := f.read(8192):
                sha.update(chunk)

        return sha.hexdigest()

    @staticmethod
    def risk_score(path):

        file_type = FileIntelligence.detect_type(path)

        if file_type == "executable":
            return "HIGH"

        if file_type == "unknown":
            return "MEDIUM"

        return "LOW"

    def analyze(self, path):

        file = Path(path)

        file_hash = self.calculate_hash(path)

        result = {

            "name": file.name,
            "path": str(file.resolve()),
            "extension": file.suffix.lower(),
            "size": file.stat().st_size,
            "modified": file.stat().st_mtime,
            "category": self.detect_type(path),
            "type": self.detect_type(path),
            "risk": self.risk_score(path),
            "hash": file_hash,
            "sha256": file_hash

        }

        # IMPORTANT:
        # Search by PATH instead of HASH

        existing = self.memory.find_by_path(result["path"])

        if not existing:

            self.memory.save_file(result)
            result["memory_status"] = "NEW_FILE_SAVED"

        else:

            result["memory_status"] = "FILE_ALREADY_KNOWN"

        return result