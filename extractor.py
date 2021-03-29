import os
import socket
import struct
from prettytable import PrettyTable
from shutil import copyfile


def loadLineToProcess(num, full_path):
    file_ob = open(full_path).readlines()
    line = ""
    for i, line in enumerate(file_ob):
        if i + 1 == num:
            break
    return line


def loadFileToArray(full_path):
    with open(full_path) as file:
        lines = [line.split() for line in file]

    return lines


class MyExtractor:
    m_processes = []
    m_raw_network_conn = []
    m_readable_conn = []

    def getProcesses(self):
        path = "/proc"
        dirs = os.listdir(path)
        for file in dirs:
            if file.isnumeric():
                proc = Process()
                proc.m_pid = file
                self.loadProcData(proc)
                self.m_processes.append(proc)

        return self.m_processes

    @staticmethod
    def loadProcData(proc):
        path = "/proc"

        full_path = path + "/" + proc.m_pid + "/status"
        line = loadLineToProcess(7, full_path)
        proc.m_ppid = line
        tmp = str(proc.m_pid).strip(' ')
        proc.m_ppid = tmp[0]

        full_path = path + "/" + proc.m_pid + "/status"
        line = loadLineToProcess(3, full_path)
        proc.m_state = line
        proc.m_state = str(proc.m_state).rstrip('\n')
        proc.m_state = proc.m_state.split(" ")[1]

        full_path = path + "/" + proc.m_pid + "/loginuid"
        line = loadLineToProcess(1, full_path)
        proc.m_uid = line

        full_path = path + "/" + proc.m_pid + "/wchan"
        line = loadLineToProcess(1, full_path)
        proc.m_wchan = line

        full_path = path + "/" + proc.m_pid + "/comm"
        line = loadLineToProcess(1, full_path)
        proc.m_comm = line

    def printProcesses(self):
        t = PrettyTable(['PID', 'PPID', 'State', 'UID', 'Wchan', 'comm'])
        for process in self.m_processes:
            t.add_row([process.m_pid, str(process.m_ppid).rstrip('\n'), str(process.m_state).rstrip('\n'), str(process.m_uid).rstrip('\n'), str(process.m_wchan).rstrip('\n'), str(process.m_comm).rstrip('\n')])
        print(t)

    def getNetworkConn(self):
        path = "/proc/net"

        full_path = path + "/tcp"
        raw_network_conn = loadFileToArray(full_path)
        del raw_network_conn[0]
        self.m_raw_network_conn = list(map(list, raw_network_conn))
        readable_table = self.formatTcpUdpTable(raw_network_conn, "TCP")

        full_path = path + "/udp"
        raw_network_conn = loadFileToArray(full_path)
        del raw_network_conn[0]
        self.m_raw_network_conn += raw_network_conn
        readable_table_udp = self.formatTcpUdpTable(raw_network_conn, "UDP")

        readable_table += readable_table_udp
        self.m_readable_conn = list(map(list, readable_table))

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
            spltd[0] = socket.inet_ntoa(struct.pack("<L", addr_long))  # '192.168.0.2
            spltd[1] = int(spltd[1], 16)
            local = str(spltd[0]) + ":" + str(spltd[1])
            conn[1] = local

            spltd = remote.split(":")
            addr_long = int(spltd[0], 16)
            hex(addr_long)
            struct.pack("<L", addr_long)
            spltd[0] = socket.inet_ntoa(struct.pack("<L", addr_long))  # '192.168.0.2
            spltd[1] = int(spltd[1], 16)
            remote = str(spltd[0]) + ":" + str(spltd[1])
            conn[2] = remote

            conn.insert(0, table_type)
        return readable_table

    def printNetworkConn(self):
        t = PrettyTable(['Type', 'sl', 'local_addr', 'remoote_addr', 'status', 'tx-queue', 'rx-queue'])
        for connection in self.m_readable_conn:
            t.add_row([connection[0], connection[1],  connection[2], connection[3], connection[4], connection[5], connection[6]])
        print(t)

    @staticmethod
    def fileCopy(src, dst):
        copyfile(src, dst)

    def exportLogs(self):
        self.fileCopy("/var/log/syslog", "/home/dreadpirateroberts/Desktop/forensX-volume/syslog")
        self.fileCopy("/var/log/auth.log", "/home/dreadpirateroberts/Desktop/forensX-volume/auth.log")
        self.fileCopy("/var/log/boot.log", "/home/dreadpirateroberts/Desktop/forensX-volume/boot.log")
        self.fileCopy("/var/log/kern.log", "/home/dreadpirateroberts/Desktop/forensX-volume/kern.log")
        self.fileCopy("/var/log/faillog", "/home/dreadpirateroberts/Desktop/forensX-volume/faillog")


class Process:
    m_pid = 0
    m_comm = ""
    m_uid = 0
    m_wchan = ""
    m_ppid = 0
    m_state = ""
