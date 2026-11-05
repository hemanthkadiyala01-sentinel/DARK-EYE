from backend.modules.database_query import DatabaseQuery

db = DatabaseQuery()

print("=" * 50)
print("Total Indexed Files")
print("=" * 50)

print(db.total_files())

print("\nLargest Files\n")
for file in db.largest_files(5):
    print(file)

print("\nPython Files\n")
for file in db.search_by_extension(".py")[:10]:
    print(file)

print("\nDocument Files\n")
for file in db.search_by_category("Documents")[:10]:
    print(file)

print("\nDuplicate Files\n")
print(db.duplicate_files())