import extractor
import analyser
import hasher

pid = []
ppid = []
uid = []

tcp = []
sl = []
local = ["127.0.0.53"]
remote = []
status = []

extr = extractor.MyExtractor()
hshr = hasher.HashStorage()


def what_to_analyse():
    a = ""
    while a != "1" and a != "2" and a != "0":
        print("Analyza procesov: 1")
        print("Analyza sietovych spojeni: 2")
        print("Menu: 0")
        a = input()

        if a == "0":
            forensx_init()
        elif a == "1":
            process_analysis()
        elif a == "2":
            network_analysis()
        else:
            print("Neplatny vstup")
    forensx_init()


def hash_file_compare():
    print("Zadate cestu k 1. suboru: ")
    f1 = input()
    print("Zadate cestu k 2. suboru: ")
    f2 = input()

    hshr.compare_files(f1, f2)


def hash_functions():
    print("Pre vypis ziskanych hash-ov stlacte: 1")
    print("Pre porovnanie 2 suborov stlacte: 2")
    print("Pre vytvorenie hashu suboru stlacte: 3")
    print("Menu: 0")
    a = ""

    while a != "1" and a != "0" and a != "2" and a != "3":
        a = input()
        if a == "1":
            hshr.print_hashes()
        elif a == "2":
            hash_file_compare()
        elif a == "3":
            hash_file()
        elif a == "0":
            forensx_init()
        else:
            print("Neplatny vstup")
    forensx_init()


def print_full_data():
    print("Pocet tabuliek procesov: " + str(len(extr.m_processes_storage)) + "\n" +
          "Pocet tabuliek sietovych spojeni: " + str(len(extr.m_readable_conn_storage)) + "\n\n")
    print("Zadajte index tabulky procesov (ENTER pre nevypisanie)")
    a = input()
    if a == '':
        a = -1
    print("Zadajte index tabulky sietovych spojeni (ENTER pre nevypisanie)")
    b = input()
    if b == '':
        b = -1
    extr.printProcesses(int(a) - 1, True)
    extr.printNetworkConn(int(b) - 1, True)


def network_analysis():
    # extr.GetConnOfInterest(tcp, sl, local, remote, status)
    # extr.store_connections()
    # extr.printNetworkConn(0, False)
    print("Zadajte pocet potrebnych tabuliek(10): ")
    num = input()
    print("Zadajte casovy interval v sekundach(0.3):")
    interval = input()
    analyser.analyse_network_conn(extr, num, interval)
    forensx_init()


def process_analysis():
    print("Zadajte pocet potrebnych tabuliek(10): ")
    num = input()
    print("Zadajte casovy interval v sekundach(0.3):")
    interval = input()
    analyser.analyse_processes(extr, num, interval)
    forensx_init()


def file_acquisition():
    print("Zadajte cestu k suboru: ")
    path = input()
    print("Zadajte nazov suboru: ")
    name = input()
    print("Zadate sposob hash-ovania")
    print("MD5: 1")
    print("SHA1: 2")
    print("SHA256: 3")
    print("Ziadne: 0")
    hash_type = input()

    extr.fileCopy(path, "/home/dreadpirateroberts/Desktop/forensX-volume/" + name)
    if hash_type != "0":
        hshr.store_hash("/home/dreadpirateroberts/Desktop/forensX-volume/" + name, True, hash_type)
    forensx_init()


def hash_file():
    types = ["1", "2", "3"]
    print("Zadajte cestu k suboru: ")
    path = input()
    print("Zadate sposob hash-ovania")
    print("MD5: 1")
    print("SHA1: 2")
    print("SHA256: 3")
    hash_type = ""
    while hash_type != "1" and hash_type != "2" and hash_type != "3":
        hash_type = input()
        if hash_type not in types:
            print("Neplatny vstup")

    my_hash = hshr.store_hash(path, False, hash_type)
    hshr.storage.append(my_hash)
    hshr.names.append(path)
    print(path + " " + my_hash)
    forensx_init()


def data_acquisition():
    print("Extrahovat zakladne data: 1")
    print("Extrahovat konkretny subor: 2")
    print("Naspat: 0")
    a = ""
    while a != "0" and a != "1" and a != "2":
        a = input()
        if a == "1":
            extr.getProcesses()
            extr.store_processes(True)

            extr.getNetworkConn()
            extr.store_connections(True)

            extr.exportLogs(hshr)

            print_data()
        elif a == "2":
            file_acquisition()
        elif a == "0":
            forensx_init()
        else:
            print("Neplatny vstup")


def print_data():
    a = ""
    while a != "Y" and a != "y" and a != "n":
        print("Vypisat data? - Tabulky procesov a sietove spojenia (Y/n)")
        a = input()
        if a == "Y" or a == "y":
            print_full_data()
            what_to_analyse()
        elif a == "n":
            forensx_init()
        else:
            print("Neplatny vstup")


def analyse():
    print("Vypisat ziskane data: 1")
    print("Analyza procesov: 2")
    print("Analyza sietovych spojeni: 3")
    print("Spojenie socketu s procesom: 4")
    print("naspat: 0")

    a = ""

    while a != "1" and a != "2" and a != "3" and a != "4":
        a = input()
        if a == "1":
            print_full_data()
            what_to_analyse()
        elif a == "2":
            process_analysis()
        elif a == "3":
            network_analysis()
        elif a == "4":
            analyser.network_conn_init(extr)
        elif a == "0":
            forensx_init()
        else:
            print("Neplatny vstup")
    forensx_init()


def forensx_init():
    print("Pre zber dat stlacte: 1")
    print("Pre overenie integrity stlacte: 2")
    print("Pre analyzu dat stlacte: 3")
    print("Pre ukoncenie programu stlacte: 0")
    a = ""

    while a != "0":
        a = input()
        if a == "1":
            data_acquisition()
        elif a == "2":
            hash_functions()
        elif a == "3":
            analyse()
        elif a == "0":
            break
        else:
            print("Neplatny vstup")
    exit(0)


print(" ______                      __   __")
print("|  ____|                     \\ \\ / /")
print("| |__ ___  _ __ ___ _ __  ___ \\ V / ")
print("|  __/ _ \\| '__/ _ \\ '_ \\/ __| > <")
print("| | | (_) | | |  __/ | | \\__ \\/ . \\")
print("|_|  \\___/|_|  \\___|_| |_|___/_/ \\_\\")
print("\n")

forensx_init()

# a = analyser.value_parser("2 11 23")
# print(a)
# print("zacinam")
# start = time.perf_counter
# end = time.perf_counter()
# final = end - start
# print("Cas: " + str(final))
# print("koniec")

# hasher.test("/home/dreadpirateroberts/Desktop/hash_test.txt")
# hasher.test("/home/test.txt")

# start = time.perf_counter()
# hasher.test()
# end = time.perf_counter()
# final = end - start
# print("Cas: " + str(final))
