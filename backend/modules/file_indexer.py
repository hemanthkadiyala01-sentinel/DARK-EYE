import sqlite3
from pathlib import Path

from backend.modules.file_manager import FileManager


class FileIndexer:

    DATABASE = "backend/database/files.db"

    IGNORE_FOLDERS = {
        ".git",
        ".venv",
        "__pycache__",
        "node_modules",
        ".idea",
        ".vscode"
    }

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

            "Documents": [".pdf", ".doc", ".docx", ".txt", ".md"],

            "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"],

            "Videos": [".mp4", ".avi", ".mov", ".mkv"],

            "Audio": [".mp3", ".wav", ".aac"],

            "Archives": [".zip", ".rar", ".7z", ".tar", ".gz"],

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
                ".yml",
                ".sql",
                ".php"
            ]
        }

        for category, exts in categories.items():
            if extension in exts:
                return category

        return "Other"

    def should_ignore(self, file):

        return any(folder in file.parts for folder in self.IGNORE_FOLDERS)

    def index_directory(self, directory):

        files = FileManager.scan_directory(directory)

        count = 0

        for file in files:

            if self.should_ignore(file):
                continue

            if not file.is_file():
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

            except Exception as e:
                print(f"Error indexing {file}: {e}")

        self.connection.commit()

        return count

    def close(self):
        self.connection.close()