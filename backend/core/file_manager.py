from pathlib import Path
import shutil
import hashlib


class FileManager:

    @staticmethod
    def scan_directory(path):
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(path)

        IGNORE_DIRS = {
            ".git",
            ".venv",
            "__pycache__",
            "node_modules",
            ".pytest_cache",
            ".idea",
            ".vscode"
        }

        files = []

        for item in path.rglob("*"):

            if any(part in IGNORE_DIRS for part in item.parts):
                continue

            files.append(item)

        return files


    @staticmethod
    def find_file(directory, filename):
        directory = Path(directory)

        return list(directory.rglob(filename))


    @staticmethod
    def create_folder(path):
        Path(path).mkdir(parents=True, exist_ok=True)


    @staticmethod
    def copy_file(source, destination):
        shutil.copy2(source, destination)


    @staticmethod
    def move_file(source, destination):
        shutil.move(source, destination)


    @staticmethod
    def rename_file(old_path, new_path):
        Path(old_path).rename(new_path)


    @staticmethod
    def delete_file(path):
        Path(path).unlink()


    @staticmethod
    def folder_size(path):
        total = 0

        for file in Path(path).rglob("*"):
            if file.is_file():
                total += file.stat().st_size

        return total


    @staticmethod
    def metadata(path):

        file = Path(path)

        return {
            "name": file.name,
            "suffix": file.suffix,
            "size": file.stat().st_size,
            "created": file.stat().st_ctime,
            "modified": file.stat().st_mtime,
            "absolute": str(file.resolve())
        }


    @staticmethod
    def sha256(path):

        h = hashlib.sha256()

        with open(path, "rb") as f:

            while True:

                chunk = f.read(8192)

                if not chunk:
                    break

                h.update(chunk)

        return h.hexdigest()