from backend.database.file_memory import FileMemory



class DuplicateDetector:


    def __init__(self):

        self.memory = FileMemory()



    def find_duplicates(self):

        files = self.memory.get_all_files()


        hash_map = {}


        duplicates = []


        for file in files:

            file_hash = file["sha256"]


            if file_hash in hash_map:

                duplicates.append({

                    "original": hash_map[file_hash],

                    "duplicate": file

                })


            else:

                hash_map[file_hash] = file



        return duplicates



    def close(self):

        self.memory.close()