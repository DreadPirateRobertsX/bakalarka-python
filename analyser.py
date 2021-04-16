from time import sleep
import os
import extractor


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
    result_sls = []
    result_pids = []
    sls, inodes = get_nc_inode(extracted)
    for inode, sl in zip(inodes, sls):
        pids = extractor.getPIDs()
        for pid in pids:

            fds = os.listdir("/proc/%s/fd/" % pid)
            for fd in fds:
                try:
                    if ('socket:[%s]' % inode) == os.readlink("/proc/%s/fd/%s" % (pid, fd)):
                        result_sls.append(sl)
                        result_pids.append(pid)
                        helper = True
                        break
                except:
                    continue
            if helper:
                helper = False
                break

    extracted.printConnInit(result_sls, result_pids)


def value_parser(string_values):
    return string_values.split(' ').copy()


def get_nc_inode(extr):
    extr.getNetworkConn()
    sl = []
    inodes = []
    for conn in extr.m_raw_network_conn:
        sl.append(conn[0])
        inodes.append(conn[9])
    return sl, inodes
