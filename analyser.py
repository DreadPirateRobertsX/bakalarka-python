from time import sleep
import os
import extractor
from datetime import datetime


def analyse_processes(extracted, num, interval):
    extracted.m_processes_of_interest_storage.clear()
    print("Zadate hodnoty PID oddelene medzerou (ENTER pre nespecifikovanie)")
    x = input()
    pid = value_parser(x)
    print("Zadate hodnoty PPID oddelene medzerou (ENTER pre nespecifikovanie)")
    x = input()
    ppid = value_parser(x)
    print("Zadate hodnoty UID oddelene medzerou (ENTER pre nespecifikovanie)")
    x = input()
    uid = value_parser(x)
    for i in range(0, int(num)):
        extracted.getProcessesOfInterest(pid, ppid, uid, float(interval))
        extracted.store_processes(False)
        extracted.printProcesses(i, False)


def analyse_network_conn(extracted, num, interval):
    extracted.m_conn_of_interest_storage.clear()
    print("Zadate typ spojenia UDP/TCP (ENTER pre nespecifikovanie)")
    x = input()
    tcp = value_parser(x)
    print("Zadate hodnoty Sl oddelene medzerou (ENTER pre nespecifikovanie)")
    x = input()
    sl = value_parser(x)
    print("Zadate hodnoty local-address oddelene medzerou (ENTER pre nespecifikovanie)")
    x = input()
    local = value_parser(x)
    print("Zadate hodnoty remote-address oddelene medzerou (ENTER pre nespecifikovanie)")
    x = input()
    remote = value_parser(x)
    print("Zadate hodnoty status oddelene medzerou (ENTER pre nespecifikovanie)")
    x = input()
    status = value_parser(x)
    for i in range(0, int(num)):
        extracted.GetConnOfInterest(tcp, sl, local, remote, status)
        extracted.printNetworkConn(i, False)
        sleep(float(interval))


def network_conn_init(extracted):
    helper = False
    result_locals = []
    result_pids = []
    locals, inodes = get_nc_inode(extracted)
    for inode, local in zip(inodes, locals):
        pids = extractor.getPIDs()
        for pid in pids:
            fds = os.listdir("/proc/" + pid + "/fd/")
            for fd in fds:
                try:
                    if ("socket:[" + inode + "]") == os.readlink("/proc/" + pid + "/fd/" + fd):
                        result_locals.append(local)
                        result_pids.append(pid)
                        helper = True
                        break
                except IOError:
                    continue
            if helper:
                helper = False
                break

    extracted.printConnInit(result_locals, result_pids)


def value_parser(string_values):
    return string_values.split(' ').copy()


def find_string(string, path, _OUTPUT_PATH, _CASE_NAME):
    if not os.path.exists(path):
        print("Hladany subor neexistuje!")
        return

    i = 0
    prot = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    prot.write("\n" + dt_string + "\n")

    try:
        with open(path) as file:
            for line in file:
                if string in line:
                    print(str(i) + ": " + line)
                    prot.write(str(i) + ": " + line)
                i += 1
    except IOError:
        print("Vstpny subor sa nepodarilo otvorit")

    prot.write("\n")
    prot.close()


def get_nc_inode(extr):
    extr.getNetworkConn()
    locals = []
    inodes = []
    for raw_conn, read_conn in zip(extr.m_raw_network_conn, extr.m_readable_conn):
        locals.append(read_conn[2])
        inodes.append(raw_conn[9])
    return locals, inodes


def read_file(path_of_file, _OUTPUT_PATH, _CASE_NAME):
    file = open(_OUTPUT_PATH + "Protokol/" + _CASE_NAME, "a")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    file.write("\n" + dt_string)
    file.write(" - Analytik si vyziadal zobrazit subor: " + path_of_file + "\n")
    file.close()

    try:
        with open(path_of_file, 'r') as file:
            print(file.read())
    except IOError:
        print("Neplatna cesta hladaneho sboru")
    except UnicodeDecodeError:
        print("Nejde o textovy subor")
