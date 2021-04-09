import extractor
import analyser

pid = []
ppid = []
uid = []

tcp = []
sl = []
local = ["127.0.0.53"]
remote = []
status = []

extr = extractor.MyExtractor()


def what_to_analyse():
    a = ""
    while a != "1" and a != "2" and a != "0":
        print("Analyza procesov: 1")
        print("Analyza sietovych spojeni: 2")
        print("Menu: 0")
        a = input()

        if a == "0":
            forensx_init_da()
        elif a == "1":
            process_analysis()
        elif a == "2":
            network_analysis()
        else:
            print("Neplatny vstup")


def print_full_data():
    print("Pocet tabuliek procesov: " + str(len(extr.m_processes_storage)) + "\n" +
          "Pocet tabuliek sietovych spojeni: " + str(len(extr.m_readable_conn_storage)) + "\n\n")
    print("Zadajte index tabulky procesov (-1 pre nevypisanie)")
    a = int(input())
    print("Zadajte index tabulky sietovych spojeni (-1 pre nevypisanie)")
    b = int(input())
    extr.printProcesses(a - 1, True)
    extr.printNetworkConn(b - 1, True)


def network_analysis():
    # extr.GetConnOfInterest(tcp, sl, local, remote, status)
    # extr.store_connections()
    # extr.printNetworkConn(0, False)
    print("Zadajte pocet potrebnych tabuliek(10): ")
    num = input()
    print("Zadajte casovy interval v sekundach(0.3):")
    interval = input()
    analyser.analyse_network_conn(extr, num, interval)
    forensx_init_da()


def process_analysis():
    print("Zadajte pocet potrebnych tabuliek(10): ")
    num = input()
    print("Zadajte casovy interval v sekundach(0.3):")
    interval = input()
    analyser.analyse_processes(extr, num, interval)
    forensx_init_da()


def data_acquisition():
    extr.getProcesses()
    extr.store_processes(True)

    extr.getNetworkConn()
    extr.store_connections(True)

    extr.exportLogs()
    a = ""
    while a != "Y" and a != "y" and a != "n":
        print("Vypisat data? (Y/n)")
        a = input()
        if a == "Y" or a == "y":
            print_full_data()
            what_to_analyse()
        elif a == "n":
            forensx_init_da()
        else:
            print("Neplatny vstup")


def forensx_init():
    print("Pre zber dat stlacte: 1")
    print("Pre overenie integrity stlacte: 2")
    print("Pre zabezpecenie integrity stlacte: 3")
    print("Pre ukoncenie programu stlacte: 0")
    a = ""

    while a != "e":
        a = input()
        if a == "1":
            data_acquisition()
        elif a == "0":
            exit(0)
        else:
            print("Neplatny vstup")
    exit(0)


def forensx_init_da():
    print("Pre zber dat stlacte: 1")
    print("Pre overenie integrity stlacte: 2")
    print("Pre zabezpecenie integrity stlacte: 3")
    print("Vypisat ziskane data: 4")
    print("Analyza procesov: 5")
    print("Analyza sietovych spoeni: 6")
    print("Pre ukoncenie programu stlacte: 0")

    a = ""

    while a != "e":
        a = input()
        if a == "1":
            data_acquisition()
        elif a == "4":
            print_full_data()
            what_to_analyse()
        elif a == "5":
            process_analysis()
        elif a == "6":
            network_analysis()
        elif a == "0":
            exit(0)
        else:
            print("Neplatny vstup")
    exit(0)


forensx_init()
