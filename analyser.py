from time import sleep

pid = []
ppid = []
uid = [1000]

tcp = []
sl = []
local = ["192.168.1.14"]
remote = []
status = []


def analyse_processes(extracted, num, interval):
    extracted.m_processes_of_interest_storage.clear()
    for i in range(0, int(num)):
        extracted.getProcessesOfInterest(pid, ppid, uid)
        extracted.store_processes(False)
        extracted.printProcesses(i, False)
        sleep(float(interval))


def analyse_network_conn(extracted, num, interval):  # ulozit data
    extracted.m_conn_of_interest_storage.clear()
    for i in range(0, int(num)):
        extracted.GetConnOfInterest(tcp, sl, local, remote, status)
        extracted.printNetworkConn(i, False)
        sleep(float(interval))
