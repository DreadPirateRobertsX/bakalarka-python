import hashlib
from os import path


class HashStorage:
    storage = []
    names = []

    def store_hash(self, src, store, hash_type):
        if not path.exists(src):
            print("Vstpny subor neexistuje!" + " " + src)
            return

        bffer = 1024 * 64

        if hash_type == "1":
            my_hash = hashlib.md5()
        elif hash_type == "2":
            my_hash = hashlib.sha1()
        else:
            my_hash = hashlib.sha256()

        with open(src, "rb") as file:
            while True:
                data = file.read(bffer)
                if not data:
                    break
                my_hash.update(data)
        if store:
            self.storage.append(my_hash.hexdigest())
            self.names.append(src)
        else:
            return my_hash.hexdigest()

    def compare_files(self, f1, f2):
        if not path.exists(f1):
            print("Vstpny subor neexistuje!" + " " + f1)
            return
        if not path.exists(f2):
            print("Vstpny subor neexistuje!" + " " + f2)
            return

        hash1 = self.store_hash(f1, False, "3")
        hash2 = self.store_hash(f2, False, "3")
        print("Hash1: " + str(hash1))
        print("Hash2: " + str(hash2))

    def print_hashes(self):
        for i, x in zip(self.names, self.storage):
            print(i + " " + x)
