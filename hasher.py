import hashlib
from os import path


class HashStorage:
    storage = []
    names = []

    def __init__(self, out_path, case_name):
        self._OUTPUT_PATH = out_path
        self._CASE_NAME = case_name

    def store_hash(self, src, store, hash_type):
        if not path.exists(src):
            print("Vstpny subor neexistuje!" + " " + src)
            return ""

        bffer = 1024 * 64

        if hash_type == "1":
            my_hash = hashlib.md5()
        elif hash_type == "2":
            my_hash = hashlib.sha1()
        else:
            my_hash = hashlib.sha256()
        try:
            with open(src, "rb") as file:
                while True:
                    data = file.read(bffer)
                    if not data:
                        break
                    my_hash.update(data)
        except IOError:
            print("Vstpny subor sa nepodarilo otvorit " + src)

        if store:
            self.storage.append(my_hash.hexdigest())
            self.names.append(src)
        else:
            return str(my_hash.hexdigest())

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

        file = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        file.write("\nHash1: " + str(hash1))
        file.write("\nHash2: " + str(hash2))
        file.close()

    def print_hashes(self, prnt):
        file = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        for i, x in zip(self.names, self.storage):
            if prnt:
                print(i + " " + x)
            file.write("\n" + i + " " + x)
        file.close()
