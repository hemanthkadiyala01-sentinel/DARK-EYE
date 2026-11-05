import sqlite3
from pathlib import Path

from backend.modules.file_manager import FileManager


IGNORE_FOLDERS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    ".idea",
    ".vscode"
}


class FileIndexer:

    DATABASE = "backend/database/files.db"

    def __init__(self):
        self.connection = sqlite3.connect(self.DATABASE)
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):

        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS files(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                path TEXT UNIQUE,
                extension TEXT,
                size INTEGER,
                sha256 TEXT,
                modified REAL,
                category TEXT
            )
        """)

        self.connection.commit()

    def categorize(self, extension):

        extension = extension.lower()

        categories = {

            "Documents": [
                ".pdf",
                ".doc",
                ".docx",
                ".txt",
                ".md"
            ],

            "Images": [
                ".jpg",
                ".jpeg",
                ".png",
                ".gif"
            ],

            "Videos": [
                ".mp4",
                ".avi",
                ".mov"
            ],

            "Audio": [
                ".mp3",
                ".wav"
            ],

            "Archives": [
                ".zip",
                ".rar",
                ".7z"
            ],

            "Code": [
                ".py",
                ".js",
                ".ts",
                ".java",
                ".cpp",
                ".c",
                ".cs",
                ".html",
                ".css",
                ".json",
                ".xml",
                ".yaml",
                ".yml"
            ]
        }

        for category, extensions in categories.items():
            if extension in extensions:
                return category

        return "Other"

    def index_directory(self, directory):

        # Clear previous index
        self.cursor.execute("DELETE FROM files")
        self.connection.commit()

        files = FileManager.scan_directory(directory)

        count = 0

        for file in files:

            if not file.is_file():
                continue

            # Skip ignored folders
            if any(folder in file.parts for folder in IGNORE_FOLDERS):
                continue

            try:

                metadata = FileManager.metadata(file)

                sha = FileManager.sha256(file)

                category = self.categorize(metadata["suffix"])

                self.cursor.execute("""
                    INSERT OR REPLACE INTO files
                    (
                        name,
                        path,
                        extension,
                        size,
                        sha256,
                        modified,
                        category
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    metadata["name"],
                    metadata["absolute"],
                    metadata["suffix"],
                    metadata["size"],
                    sha,
                    metadata["modified"],
                    category
                ))

                count += 1

            except Exception as error:
                print(f"Skipping {file}: {error}")

        self.connection.commit()

        return count

    def close(self):
        self.connection.close()