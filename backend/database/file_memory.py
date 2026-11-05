import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).parent / "files.db"


class FileMemory:

    def __init__(self):

        self.connection = sqlite3.connect(DATABASE_PATH)
        self.cursor = self.connection.cursor()

    # -----------------------------
    # Save a new file
    # -----------------------------
    def save_file(self, data):

        query = """
        INSERT INTO files
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
        """

        self.cursor.execute(
            query,
            (
                data["name"],
                data["path"],
                data["extension"],
                data["size"],
                data["sha256"],
                data["modified"],
                data["category"]
            )
        )

        self.connection.commit()

    # -----------------------------
    # Update existing file
    # -----------------------------
    def update_file(self, data):

        query = """
        UPDATE files
        SET
            name = ?,
            extension = ?,
            size = ?,
            sha256 = ?,
            modified = ?,
            category = ?
        WHERE path = ?
        """

        self.cursor.execute(
            query,
            (
                data["name"],
                data["extension"],
                data["size"],
                data["sha256"],
                data["modified"],
                data["category"],
                data["path"]
            )
        )

        self.connection.commit()

    # -----------------------------
    # Find by SHA256
    # -----------------------------
    def find_by_hash(self, sha256):

        self.cursor.execute(
            """
            SELECT *
            FROM files
            WHERE sha256 = ?
            """,
            (sha256,)
        )

        return self._convert_rows(
            self.cursor.fetchall()
        )

    # -----------------------------
    # Find by Path
    # -----------------------------
    def find_by_path(self, path):

        self.cursor.execute(
            """
            SELECT *
            FROM files
            WHERE path = ?
            """,
            (path,)
        )

        return self._convert_rows(
            self.cursor.fetchall()
        )

    # -----------------------------
    # Get All Files
    # -----------------------------
    def get_all_files(self):

        self.cursor.execute(
            "SELECT * FROM files"
        )

        return self._convert_rows(
            self.cursor.fetchall()
        )

    # -----------------------------
    # Count Files
    # -----------------------------
    def count_files(self):

        self.cursor.execute(
            "SELECT COUNT(*) FROM files"
        )

        return self.cursor.fetchone()[0]

    # -----------------------------
    # Delete File
    # -----------------------------
    def delete_file(self, file_id):

        self.cursor.execute(
            "DELETE FROM files WHERE id = ?",
            (file_id,)
        )

        self.connection.commit()

    # -----------------------------
    # Cleanup Ignored Files
    # -----------------------------
    def cleanup_ignored_files(self):

        ignored_folders = [
            ".git",
            ".venv",
            "__pycache__",
            ".pytest_cache",
            ".idea",
            ".vscode",
            "node_modules"
        ]

        for folder in ignored_folders:

            self.cursor.execute(
                """
                DELETE FROM files
                WHERE path LIKE ?
                """,
                (f"%\\{folder}\\%",)
            )

        self.connection.commit()

    # -----------------------------
    # Convert SQLite Rows
    # -----------------------------
    def _convert_rows(self, rows):

        files = []

        for row in rows:

            files.append({

                "id": row[0],
                "name": row[1],
                "path": row[2],
                "extension": row[3],
                "size": row[4],
                "sha256": row[5],
                "modified": row[6],
                "category": row[7]

            })

        return files

    # -----------------------------
    # Close Database
    # -----------------------------
    def close(self):

        self.connection.close()