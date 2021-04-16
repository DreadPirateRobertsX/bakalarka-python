import os
import socket
import struct
from prettytable import PrettyTable
from shutil import copyfile
import os.path
import psutil
from os import path
from time import sleep
from math import floor, ceil


def loadLineToProcess(num, full_path):
    if not path.exists(full_path):
        print("Vstpny subor neexistuje!" + " " + full_path)
        return

    file_ob = open(full_path).readlines()
    line = ""
    for i, line in enumerate(file_ob):
        if i + 1 == num:
            break
    return line


def loadFileToArray(full_path):
    if not path.exists(full_path):
        print("Vstpny subor neexistuje!" + " " + full_path)
        return

    with open(full_path) as file:
        lines = [line.split() for line in file]

    return lines


def getPIDs():
    pids = []
    my_path = "/proc"
    dirs = os.listdir(my_path)
    for file in dirs:
        if file.isnumeric():
            pids.append(file)
    return pids


def comm_from_pid(pid):
    full_path = "/proc/" + str(pid) + "/comm"
    comm = loadLineToProcess(1, full_path)

    return comm


class MyExtractor:
    m_processes = []
    m_raw_network_conn = []
    m_readable_conn = []

    m_processes_storage = []
    m_raw_network_conn_storage = []
    m_readable_conn_storage = []
    m_processes_of_interest_storage = []
    m_conn_of_interest_storage = []

    def getProcesses(self):
        self.m_processes.clear()

        my_path = "/proc"
        dirs = os.listdir(my_path)
        for file in dirs:
            if file.isnumeric():
                proc = Process()
                proc.m_pid = file
                self.loadProcData(proc)
                self.m_processes.append(proc)

    def getProcessesOfInterest(self, pid, ppid, uid, interval):
        self.m_processes.clear()
        helper = 0
        var = []
        my_path = "/proc"
        dirs = os.listdir(my_path)
        for file in dirs:
            if file.isnumeric():
                proc = Process()
                proc.m_pid = file
                self.loadProcData(proc)
                if proc.m_pid in pid or proc.m_ppid in ppid or proc.m_uid in uid:
                    var.append(psutil.Process(int(proc.m_pid)))
                    var[helper].cpu_percent(interval=0)
                    helper += 1

                    # proc.m_cpu_usage = p.cpu_percent(interval=0)
                    # proc.m_ram_usage = p.memory_percent()   !! nezabudni
                    self.m_processes.append(proc)
        sleep(interval)

        for v, proc in zip(var, self.m_processes):
            proc.m_cpu_usage = v.cpu_percent(interval=0)
            proc.m_ram_usage = v.memory_percent(memtype="rss")

    @staticmethod
    def loadProcData(proc):
        my_path = "/proc"

        full_path = my_path + "/" + proc.m_pid + "/status"
        line = loadLineToProcess(7, full_path)
        proc.m_ppid = line
        tmp = str(proc.m_pid).strip(' ')
        proc.m_ppid = tmp[0]

        full_path = my_path + "/" + proc.m_pid + "/status"
        line = loadLineToProcess(3, full_path)
        proc.m_state = line
        proc.m_state = str(proc.m_state).rstrip('\n')

        proc.m_state = proc.m_state.split(" ")
        if len(proc.m_state) > 1:
            proc.m_state = proc.m_state[1]
        else:
            proc.m_state = "(Zombie)"

        full_path = my_path + "/" + proc.m_pid + "/loginuid"
        line = loadLineToProcess(1, full_path)
        proc.m_uid = line

        full_path = my_path + "/" + proc.m_pid + "/wchan"
        line = loadLineToProcess(1, full_path)
        proc.m_wchan = line

        full_path = my_path + "/" + proc.m_pid + "/comm"
        line = loadLineToProcess(1, full_path)
        proc.m_comm = line

    def printProcesses(self, table_num, full):
        if table_num < 0:
            return

        if full:
            tmp = self.m_processes_storage
            t = PrettyTable(['PID', 'PPID', 'State', 'UID', 'Wchan', 'comm'])
            for process in tmp[table_num]:
                t.add_row([process.m_pid, str(process.m_ppid).rstrip('\n'), str(process.m_state).rstrip('\n'),
                           str(process.m_uid).rstrip('\n'), str(process.m_wchan).rstrip('\n'),
                           str(process.m_comm).rstrip('\n')])
        else:
            tmp = self.m_processes_of_interest_storage
            t = PrettyTable(['PID', 'PPID', 'State', 'UID', 'Wchan', 'comm', 'CPU %', "MEM %"])
            for process in tmp[table_num]:
                t.add_row([process.m_pid, str(process.m_ppid).rstrip('\n'), str(process.m_state).rstrip('\n'),
                           str(process.m_uid).rstrip('\n'), str(process.m_wchan).rstrip('\n'),
                           str(process.m_comm).rstrip('\n'), process.m_cpu_usage, floor(process.m_ram_usage*100)/100])

        print(t)

    def getNetworkConn(self):
        self.m_raw_network_conn.clear()
        self.m_readable_conn.clear()

        my_path = "/proc/net"

        full_path = my_path + "/tcp"
        raw_network_conn = loadFileToArray(full_path)
        del raw_network_conn[0]
        self.m_raw_network_conn = list(map(list, raw_network_conn))
        readable_table = self.formatTcpUdpTable(raw_network_conn, "TCP")

        full_path = my_path + "/udp"
        raw_network_conn = loadFileToArray(full_path)
        del raw_network_conn[0]
        self.m_raw_network_conn += raw_network_conn
        readable_table_udp = self.formatTcpUdpTable(raw_network_conn, "UDP")

        readable_table += readable_table_udp
        self.m_readable_conn = list(map(list, readable_table))

    def GetConnOfInterest(self, tcp, sl, local, remote, status):
        self.getNetworkConn()
        tmp = []
        for connection in self.m_readable_conn:
            if connection[0] in tcp or str(connection[1]).strip(":") in sl or connection[2].split(":")[0] in local \
                    or connection[3].split(":")[0] in remote or connection[4] in status:
                tmp.append(connection.copy())
        self.m_conn_of_interest_storage.append(tmp.copy())

    @staticmethod
    def formatTcpUdpTable(raw_table, table_type):
        readable_table = list(map(list, raw_table))
        for conn in readable_table:
            local = conn[1]
            remote = conn[2]

            spltd = local.split(":")
            addr_long = int(spltd[0], 16)
            hex(addr_long)
            struct.pack("<L", addr_long)
            spltd[0] = socket.inet_ntoa(struct.pack("<L", addr_long))
            spltd[1] = int(spltd[1], 16)
            local = str(spltd[0]) + ":" + str(spltd[1])
            conn[1] = local

            spltd = remote.split(":")
            addr_long = int(spltd[0], 16)
            hex(addr_long)
            struct.pack("<L", addr_long)
            spltd[0] = socket.inet_ntoa(struct.pack("<L", addr_long))
            spltd[1] = int(spltd[1], 16)
            remote = str(spltd[0]) + ":" + str(spltd[1])
            conn[2] = remote

            conn.insert(0, table_type)
        return readable_table

    def printNetworkConn(self, table_num, full):
        if table_num < 0:
            return
        t = PrettyTable(['Type', 'sl', 'local_addr', 'remoote_addr', 'status', 'tx-queue', 'rx-queue'])
        if full:
            tmp = self.m_readable_conn_storage
        else:
            tmp = self.m_conn_of_interest_storage
        for connection in tmp[table_num]:
            t.add_row([connection[0], connection[1], connection[2], connection[3], connection[4], connection[5],
                       connection[6]])
        print(t)

    def printConnInit(self, result_sls, result_pids):
        pid = "-"
        t = PrettyTable(
            ['Type', 'sl', 'local_addr', 'remoote_addr', 'status', 'tx-queue', 'rx-queue', 'process', 'PID'])
        comm = "-"
        for connection in self.m_readable_conn:
            if str(connection[1]) in result_sls:
                for sl, pid in zip(result_sls, result_pids):
                    if sl == connection[1]:
                        comm = comm_from_pid(pid)
                        break

            t.add_row([connection[0], connection[1], connection[2], connection[3], connection[4], connection[5],
                       connection[6], comm, pid])
            comm = "-"
        print(t)

    @staticmethod
    def fileCopy(src, dst):
        if path.exists(src):
            copyfile(src, dst)
        else:
            print("Vstpny subor neexistuje!" + " " + src)

    def exportLogs(self, hasher):
        if path.exists("/var/log/syslog"):
            self.fileCopy("/var/log/syslog", "/home/dreadpirateroberts/Desktop/forensX-volume/syslog")
            hasher.store_hash("/home/dreadpirateroberts/Desktop/forensX-volume/syslog", True, "3")
        if path.exists("/var/log/auth.log"):
            self.fileCopy("/var/log/auth.log", "/home/dreadpirateroberts/Desktop/forensX-volume/auth.log")
            hasher.store_hash("/home/dreadpirateroberts/Desktop/forensX-volume/auth.log", True, "3")
        if path.exists("/var/log/boot.log"):
            self.fileCopy("/var/log/boot.log", "/home/dreadpirateroberts/Desktop/forensX-volume/boot.log")
            hasher.store_hash("/home/dreadpirateroberts/Desktop/forensX-volume/boot.log", True, "3")
        if path.exists("/var/log/kern.log"):
            self.fileCopy("/var/log/kern.log", "/home/dreadpirateroberts/Desktop/forensX-volume/kern.log")
            hasher.store_hash("/home/dreadpirateroberts/Desktop/forensX-volume/kern.log", True, "3")
        if path.exists("/var/log/faillog"):
            self.fileCopy("/var/log/faillog", "/home/dreadpirateroberts/Desktop/forensX-volume/faillog")
            hasher.store_hash("/home/dreadpirateroberts/Desktop/forensX-volume/faillog", True, "3")

    def store_processes(self, full):
        tmp = self.m_processes.copy()
        if full:
            self.m_processes_storage.append(tmp)
        else:
            self.m_processes_of_interest_storage.append(tmp)

    def store_connections(self, full):
        if full:
            tmp = self.m_raw_network_conn.copy()
            self.m_raw_network_conn_storage.append(tmp)
            tmp = self.m_readable_conn.copy()
            self.m_readable_conn_storage.append(tmp)
        else:
            tmp = self.m_readable_conn.copy()
            self.m_conn_of_interest_storage.append(tmp)


class Process:
    m_pid = 0
    m_comm = ""
    m_uid = ""
    m_wchan = ""
    m_ppid = ""
    m_state = ""
    m_cpu_usage = ""
    m_ram_usage = ""
