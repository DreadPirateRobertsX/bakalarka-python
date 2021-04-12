from time import sleep

pid = []
ppid = []
uid = []

tcp = []
sl = []
local = []
remote = []
status = []


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
        extracted.getProcessesOfInterest(pid, ppid, uid)
        extracted.store_processes(False)
        extracted.printProcesses(i, False)
        sleep(float(interval))


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
    for i in range(0, int(num)):
        extracted.GetConnOfInterest(tcp, sl, local, remote, status)
        extracted.printNetworkConn(i, False)
        sleep(float(interval))


def value_parser(string_values):
    return string_values.split(' ').copy()
