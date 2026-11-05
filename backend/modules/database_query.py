import sqlite3


class DatabaseQuery:

    DATABASE = "backend/database/files.db"

    def __init__(self):
        self.connection = sqlite3.connect(self.DATABASE)
        self.cursor = self.connection.cursor()

    def search_by_name(self, keyword):
        self.cursor.execute("""
            SELECT * FROM files
            WHERE name LIKE ?
            ORDER BY name
        """, (f"%{keyword}%",))
        return self.cursor.fetchall()

    def search_by_extension(self, extension):
        self.cursor.execute("""
            SELECT * FROM files
            WHERE extension = ?
            ORDER BY name
        """, (extension,))
        return self.cursor.fetchall()

    def search_by_category(self, category):
        self.cursor.execute("""
            SELECT * FROM files
            WHERE category = ?
            ORDER BY name
        """, (category,))
        return self.cursor.fetchall()

    def largest_files(self, limit=10):
        self.cursor.execute("""
            SELECT * FROM files
            ORDER BY size DESC
            LIMIT ?
        """, (limit,))
        return self.cursor.fetchall()

    def recent_files(self, limit=10):
        self.cursor.execute("""
            SELECT * FROM files
            ORDER BY modified DESC
            LIMIT ?
        """, (limit,))
        return self.cursor.fetchall()

    def duplicate_files(self):
        self.cursor.execute("""
            SELECT sha256, COUNT(*)
            FROM files
            GROUP BY sha256
            HAVING COUNT(*) > 1
        """)
        return self.cursor.fetchall()

    def total_files(self):
        self.cursor.execute("""
            SELECT COUNT(*)
            FROM files
        """)
        return self.cursor.fetchone()[0]