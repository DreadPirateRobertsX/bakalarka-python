import extractor
import analyser
import Terminal
import os
import hasher
from datetime import datetime

_LOGS_EXTRACTED = False
print("Zadajte nazov pripadu")
_CASE_NAME = input()
print("Zadajte vystupnu cestu")
_OUTPUT_PATH = input()
while not os.path.exists(_OUTPUT_PATH):
    print("Vstupna cesta neexistuje")
    _OUTPUT_PATH = input()

_OUTPUT_PATH += "/" + _CASE_NAME + "/"
_OUTPUT_PATH = "/home/dreadpirateroberts/Desktop/forensX-volume/" + _CASE_NAME + "/"

directory = os.path.dirname(_OUTPUT_PATH + "Protokol/" + _CASE_NAME)
if not os.path.exists(directory):
    os.makedirs(directory)

f = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "w")
f.write(_CASE_NAME + " - " + str(datetime.now()) + "\n")
f.close()

trm = Terminal.MyTerminal(_OUTPUT_PATH, _CASE_NAME)
extr = extractor.MyExtractor(_OUTPUT_PATH, _CASE_NAME)
hshr = hasher.HashStorage(_OUTPUT_PATH, _CASE_NAME)


def hash_file_compare():
    print("Zadate cestu k 1. suboru: ")
    f1 = input()
    print("Zadate cestu k 2. suboru: ")
    f2 = input()

    file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    file.write("\n" + dt_string)
    file.write(" - Analytik si vyziadal porovnanie 2 suborov: " + f1 + " a " + f2)
    file.close()

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
            hshr.print_hashes(True)
        elif a == "2":
            hash_file_compare()
        elif a == "3":
            hash_file()
        elif a == "0":
            return
        else:
            print("Neplatny vstup")
    return


def print_full_data():
    if len(extr.m_processes_storage) == 0:
        print("Zatial neboli stiahnute ziadne tabulky")
        return
    print("Pocet tabuliek procesov: " + str(len(extr.m_processes_storage)) + "\n" +
          "Pocet tabuliek sietovych spojeni: " + str(len(extr.m_readable_conn_storage)) + "\n\n")
    print("Zadajte index tabulky procesov (ENTER pre nevypisanie)")
    a = input()
    if a == '':
        a = 0
    print("Zadajte index tabulky sietovych spojeni (ENTER pre nevypisanie)")
    b = input()
    if b == '':
        b = 0
    if a != 0:
        if int(a) > len(extr.m_processes_storage):
            print("Tabulka s procesmi neexistuje")
            return
        file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        file.write("\n" + dt_string)
        file.write(" - Analytik si vyziadal vypis " + str(a) + ". tablky s procesmi\n")
        file.close()
    extr.printProcesses(int(a) - 1, True)
    if b != 0:
        if int(b) > len(extr.m_readable_conn_storage):
            print("Tabulka so sietovymi spojeniami neexistuje")
            return
        file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        file.write("\n" + dt_string)
        file.write(" - Analytik si vyziadal vypis " + str(b) + ". tablky so sietovymi spojeniami\n")
        file.close()
    extr.printNetworkConn(int(b) - 1, True)


def network_analysis():
    print("Zadajte pocet potrebnych tabuliek(10): ")
    num = input()
    print("Zadajte casovy interval v sekundach(0.3):")
    interval = input()
    file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    file.write("\n" + dt_string)
    file.write(
        " - Analytik si vyziadal vypis " + num + " tabuliek sietovych spojeni v casovom intervale " + interval + ". sek\n")
    file.close()
    analyser.analyse_network_conn(extr, num, interval)
    return


def process_analysis():
    print("Zadajte pocet potrebnych tabuliek(10): ")
    num = input()
    print("Zadajte casovy interval v sekundach(0.3):")
    interval = input()
    file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    file.write("\n" + dt_string)
    file.write(
        " - Analytik si vyziadal vypis " + num + " tabuliek procesov v casovom intervale " + interval + ". sek\n")
    file.close()
    analyser.analyse_processes(extr, num, interval)
    return


def file_acquisition():
    print("Zadajte cestu k suboru: ")
    path = input()
    print("Zadajte nazov suboru: ")
    name = input()
    if name == "":
        print("Nespravny format pre nazov vystupneho suboru")
        return
    print("Zadate sposob hash-ovania")
    print("MD5: 1")
    print("SHA1: 2")
    print("SHA256: 3")
    print("Ziadne: 0")
    hash_type = input()

    file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    file.write("\n" + dt_string)
    file.write(" - Analytik si vyziadal extrahovanie suboru: " + str(path))
    file.close()

    extr.fileCopy(path, _OUTPUT_PATH + name)
    if hash_type != "0":
        hshr.store_hash(_OUTPUT_PATH + name, True, hash_type)
    return


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

    file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    file.write("\n" + dt_string)
    file.write(" - Analytik si vyziadal vytvorenie hash-u pre subor: " + str(path))

    my_hash = hshr.store_hash(path, False, hash_type)
    hshr.storage.append(my_hash)
    hshr.names.append(path)
    print(path + " " + my_hash)
    file.write("\n" + path + " " + my_hash + "\n")
    file.close()
    return


def data_acquisition():
    global _LOGS_EXTRACTED
    print("Extrahovat zakladne data: 1")
    print("Extrahovat konkretny subor: 2")
    print("Naspat: 0")
    a = ""
    while a != "0" and a != "1" and a != "2":
        a = input()
        if a == "1":
            file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            file.write("\n" + dt_string)
            file.write(" - Ziadost o extrahovanie zakladnych dat\n")
            file.close()

            extr.getProcesses()
            extr.store_processes(True)

            extr.getNetworkConn()
            extr.store_connections(True)

            if not _LOGS_EXTRACTED:
                extr.exportLogs(hshr)
                _LOGS_EXTRACTED = True
            else:
                print("Prajete si znova stiahnut subory s Logmi? - Povodne kopie sa prepisu (Y/n)")
                a = input()
                if a == "Y" or a == "y":
                    extr.exportLogs(hshr)
            extr.extract_command_history(hshr)
            file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            file.write("\n" + dt_string)
            file.write(" - Extrahovana historia prikazov vsetkych pouzivatelov:\n")
            for usr in extr.m_users:
                file.write(" " + str(usr) + "; ")
            file.close()
            print_data()
            print("\nVypisat smerovaciu tabulku? (Y/n)\n")
            x = input()
            if x == "Y" or x == "y":
                file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
                now = datetime.now()
                dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                file.write("\n" + dt_string)
                file.write(" - Analytik si vyziiadal vypis smerovace tabulky:\n")
                extr.getRoutingTable()

        elif a == "2":
            file_acquisition()
        elif a == "0":
            return
        else:
            print("Neplatny vstup")


def print_data():
    a = ""
    while a != "Y" and a != "y" and a != "n":
        print("\nVypisat data? - Tabulky procesov a sietove spojenia (Y/n)")
        a = input()
        if a == "Y" or a == "y":
            print_full_data()
        elif a == "n":
            return
        else:
            print("Neplatny vstup")
    return


def print_users():
    file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    file.write("\n" + dt_string)
    file.write(" - Analytik si vyziadal zobrazit pouzivatelov s uid\n")

    for usr, u_uid in zip(extr.m_users, extr.m_uids):
        file.write(usr + ':' + u_uid + "\n")
        print(usr + ':' + u_uid)
    file.close()


def analyse():
    print("Vypisat ziskane data: 1")
    print("Analyza procesov: 2")
    print("Analyza sietovych spojeni: 3")
    print("Spojenie socketu s procesom: 4")
    print("Vypisat pouzivatelov/UID: 5")
    print("Zobrazit ARP tabulku: 6")
    print("Zobrazit Smerovaciu tabulku: 7")
    print("Zobrazit obsah suboru: 8")
    print("Vyhladat retazec v subore: 9")
    print("naspat: 0")

    while True:
        a = input()
        if a == "1":
            print_full_data()
            break
        elif a == "2":
            process_analysis()
            break
        elif a == "3":
            network_analysis()
            break
        elif a == "4":
            file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            file.write("\n" + dt_string)
            file.write(" - Analytik si vyziadal zobrazit priradenie sietovych spojeni s procesmi ktore ich vytvorili\n")
            file.close()
            analyser.network_conn_init(extr)
            break
        elif a == "5":
            print_users()
            break
        elif a == "6":
            analyser.read_file("/proc/net/arp", _OUTPUT_PATH, _CASE_NAME)

            print("Ulozit?(Y/n)\n")
            x = input()
            if x == "Y" or x == "y":
                print("Zadajte nazov: ")
                x = input()
                direct = os.path.dirname(_OUTPUT_PATH + "ARP/" + x)
                if not os.path.exists(direct):
                    os.makedirs(direct)

                extr.fileCopy("/proc/net/arp", _OUTPUT_PATH + "ARP/" + x)
                hshr.store_hash(_OUTPUT_PATH + "ARP/" + x, True, 3)
                break
        elif a == "7":
            file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            file.write("\n" + dt_string)
            file.write(" - Analytik si vyziiadal vypis smerovace tabulky:\n")
            extr.getRoutingTable()
            break

        elif a == "8":
            print("Zadajte cestu k suboru: \n")
            path = input()
            analyser.read_file(path, _OUTPUT_PATH, _CASE_NAME)
            break

        elif a == "9":
            print("Zadajte cestu k suboru: ")
            path = input()
            print("Zadajte hladany retazec: ")
            string = input()

            file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            file.write("\n" + dt_string)
            file.write(" - Vyhladavanie retazca: " + string + " v subore: " + path + "\n")
            file.close()

            analyser.find_string(string, path, _OUTPUT_PATH, _CASE_NAME)
            break

        elif a == "0":
            return
        else:
            print("Neplatny vstup")
    return


def forensx_init():
    while True:
        print("\n\nPre zber dat stlacte: 1")
        print("Pre overenie integrity stlacte: 2")
        print("Pre analyzu dat stlacte: 3")
        print("Terminal: 4")
        print("Manual: 5")
        print("Pre ukoncenie programu stlacte: 0")

        a = input()
        if a == "1":
            data_acquisition()
        elif a == "2":
            hash_functions()
        elif a == "3":
            analyse()
        elif a == "4":
            trm.terminal_init()
        elif a == "5":
            man = open("man.txt", "r")
            print(man.read())
        elif a == "0":
            break
        else:
            print("Neplatny vstup")

    file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    file.write("\n\n\n" + dt_string)
    file.write(" - Koniec programu - Vypis ziskanych hash-ov\n")
    file.close()
    hshr.print_hashes(False)

    final_hash = hshr.store_hash(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, False, 3)
    file = open(_OUTPUT_PATH + "Protokol/Hash.txt", "w+")
    file.write(final_hash)
    file.close()
    return


print(" ______                      __   __")
print("|  ____|                     \\ \\ / /")
print("| |__ ___  _ __ ___ _ __  ___ \\ V / ")
print("|  __/ _ \\| '__/ _ \\ '_ \\/ __| > <")
print("| | | (_) | | |  __/ | | \\__ \\/ . \\")
print("|_|  \\___/|_|  \\___|_| |_|___/_/ \\_\\")
print("\n")

try:
    forensx_init()
except:
    print("Nieco nefunguje")
    file_o = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now_o = datetime.now()
    dt_string_o = now_o.strftime("%d/%m/%Y %H:%M:%S")

    file_o.write("\n\n\n" + dt_string_o)
    file_o.write(" - Koniec programu - Vypis ziskanych hash-ov\n")
    file_o.close()
    hshr.print_hashes(False)

    final_hash = hshr.store_hash(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, False, 3)
    os.makedirs(_OUTPUT_PATH + "Protokol/Hash")
    file = open(_OUTPUT_PATH + "Protokol/Hash")
    file.write(final_hash)
    file.close()
