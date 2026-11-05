from pathlib import Path

from backend.database.file_memory import FileMemory
from backend.modules.file_intelligence import FileIntelligence


class ChangeMonitor:

    def __init__(self):

        self.memory = FileMemory()
        self.intelligence = FileIntelligence()

    def check_file(self, path):

        file_path = str(Path(path).resolve())

        current = self.intelligence.analyze(path)

        stored = self.memory.find_by_path(file_path)

        # File has never been seen before
        if not stored:

            return {
                "status": "NEW_FILE",
                "file": current
            }

        previous = stored[0]

        # Same file, no changes
        if previous["sha256"] == current["sha256"]:

            return {
                "status": "UNCHANGED",
                "file": current
            }

        # Same path but different hash
        return {
            "status": "MODIFIED",
            "old": previous,
            "new": current
        }

    def close(self):

        self.memory.close()