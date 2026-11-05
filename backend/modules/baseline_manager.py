from backend.database.file_memory import FileMemory
from backend.modules.file_intelligence import FileIntelligence


class BaselineManager:

    def __init__(self):
        self.memory = FileMemory()
        self.intelligence = FileIntelligence()

    def accept_change(self, path):

        file_info = self.intelligence.analyze(path)

        existing = self.memory.find_by_path(file_info["path"])

        if existing:

            self.memory.update_file(file_info)

            return {
                "status": "BASELINE_UPDATED",
                "file": file_info
            }

        self.memory.save_file(file_info)

        return {
            "status": "NEW_BASELINE_CREATED",
            "file": file_info
        }

    def close(self):
        self.memory.close()