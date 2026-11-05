from backend.modules.file_indexer import FileIndexer

indexer = FileIndexer()

count = indexer.index_directory(".")

print(f"Indexed {count} files.")