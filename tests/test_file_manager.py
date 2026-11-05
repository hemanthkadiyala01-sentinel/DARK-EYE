from backend.modules.file_manager import FileManager

files = FileManager.scan_directory(".")

print("Found:", len(files))

for f in files[:10]:
    print(f)

print()

print(FileManager.metadata(__file__))