import os
import time
import socket
import struct
from prettytable import PrettyTable
from shutil import copyfile
from codecs import decode
import os.path
import psutil
from os import path
# from time import sleep, time
from math import floor
from datetime import datetime


def loadLineToProcess(num, full_path):
    if not path.exists(full_path):
        print("Vstpny subor neexistuje1!" + " " + full_path)
        return "---"
    try:
        file_ob = open(full_path).readlines()
    except IOError:
        return "---"
    line = ""
    for i, line in enumerate(file_ob):
        if i + 1 == num:
            break
    return line


def loadFileToArray(full_path):
    if not path.exists(full_path):
        print("Vstpny subor neexistuje!" + " " + full_path)
        return "---"
    try:
        with open(full_path) as file:
            lines = [line.split() for line in file]
    except IOError:
        return "---"

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
    m_uids = []

    def __init__(self, out_path, case_name):
        self._OUTPUT_PATH = out_path
        self._CASE_NAME = case_name
        self.m_users = self.get_users()
        self.get_users_uid()

    @staticmethod
    def get_users():
        final = []
        users = []
        # dirs = os.listdir("/home")

        shadow = loadFileToArray("/etc/passwd")
        for line in shadow:
            line = line[0].split(":")
            if line[-1] == "/bin/bash" or line[-1] == "/bin/sh":
                users.append(line[0])
        for usr in users:
            for line in shadow:
                line = line[0].split(":")
                if line[0] == usr:
                    final.append(usr)
                    break

        return final

    def getProcesses(self):
        self.m_processes.clear()

        my_path = "/proc"
        dirs = os.listdir(my_path)
        for file in dirs:
            if file.isnumeric():
                proc = Process()
                proc.m_pid = file
                self.load_proc_data(proc)
                self.m_processes.append(proc)

        file = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        file.write("\n" + dt_string)
        file.write(" - Extrahovana tabulka s procesmi\n")
        file.close()

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
                self.load_proc_data(proc)
                if proc.m_pid in pid or proc.m_ppid in ppid or proc.m_uid in uid:
                    var.append(psutil.Process(int(proc.m_pid)))
                    var[helper].cpu_percent(interval=0)
                    helper += 1

                    self.m_processes.append(proc)
        time.sleep(interval)

        for v, proc in zip(var, self.m_processes):
            try:
                proc.m_cpu_usage = v.cpu_percent(interval=0)
            except IOError:
                proc.m_cpu_usage = "-"
            try:
                proc.m_ram_usage = v.memory_percent()
            except IOError:
                proc.m_ram_usage = "-"

    @staticmethod
    def load_proc_data(proc):
        my_path = "/proc"

        full_path = my_path + "/" + proc.m_pid + "/status"
        line = loadLineToProcess(7, full_path)
        proc.m_ppid = line
        if line != "---":
            tmp = str(proc.m_ppid).split('\t')
            proc.m_ppid = str(int(tmp[1]))

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

        try:
            p = psutil.Process(int(proc.m_pid))
            p.create_time()
            proc.m_start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.create_time()))
        except psutil.NoSuchProcess:
            proc.m_start_time = "-"
            pass

    def printProcesses(self, table_num, full):
        if table_num < 0:
            return
        if full:
            tmp = self.m_processes_storage
            t = PrettyTable(['PID', 'PPID', 'State', 'UID', 'Wchan', 'comm', 'Start time'])
            for process in tmp[table_num]:
                t.add_row([process.m_pid, str(process.m_ppid).rstrip('\n'), str(process.m_state).rstrip('\n'),
                           str(process.m_uid).rstrip('\n'), str(process.m_wchan).rstrip('\n'),
                           str(process.m_comm).rstrip('\n'), str(process.m_start_time)])
        else:
            tmp = self.m_processes_of_interest_storage
            t = PrettyTable(['PID', 'PPID', 'State', 'UID', 'Wchan', 'comm', 'CPU %', "MEM %"])
            for process in tmp[table_num]:
                t.add_row([process.m_pid, str(process.m_ppid).rstrip('\n'), str(process.m_state).rstrip('\n'),
                           str(process.m_uid).rstrip('\n'), str(process.m_wchan).rstrip('\n'),
                           str(process.m_comm).rstrip('\n'), process.m_cpu_usage,
                           floor(process.m_ram_usage * 100) / 100])

        f = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        f.write("\n" + str(t))
        f.close()
        print(t)

    def getRoutingTable(self):
        file = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        file.write("\n" + dt_string)
        file.write(" - Citanie obsahu smerovacej tabulky /proc/net/route\n")

        my_path = "/proc/net/route"
        raw_routing_table = loadFileToArray(my_path)
        del raw_routing_table[0]
        self.format_route_table(raw_routing_table)
        self.printRoutingTable(raw_routing_table)

    def printRoutingTable(self, table):
        t = PrettyTable(['Iface', 'Destination', 'Gateway', 'Flags', 'RefCnt', 'Use', 'Metric'])

        for line in table:
            t.add_row([line[0], line[1], line[2], line[3], line[4], line[5],
                       line[6]])

        f = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        f.write("/n" + str(t))
        f.close()
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

        full_path = my_path + "/udp6"
        raw_network_conn = loadFileToArray(full_path)
        del raw_network_conn[0]
        self.m_raw_network_conn += raw_network_conn
        readable_table_udp6 = self.formatTcpUdpTable(raw_network_conn, "UDP6")
        readable_table += readable_table_udp6
        self.m_readable_conn = list(map(list, readable_table))

        full_path = my_path + "/tcp6"
        raw_network_conn = loadFileToArray(full_path)
        del raw_network_conn[0]
        self.m_raw_network_conn += raw_network_conn
        readable_table_udp6 = self.formatTcpUdpTable(raw_network_conn, "TCP6")
        readable_table += readable_table_udp6
        self.m_readable_conn = list(map(list, readable_table))

        file = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        file.write("\n" + dt_string)
        file.write(" - Extrahovana tabulka so sietovymi spojeniami\n")
        file.close()

    def GetConnOfInterest(self, tcp, sl, local, remote, status):
        self.getNetworkConn()
        tmp = []
        for connection in self.m_readable_conn:
            if connection[0] in tcp or str(connection[1]).strip(":") in sl or connection[2].split(":")[0] in local \
                    or connection[3].split(":")[0] in remote or connection[4] in status:
                tmp.append(connection.copy())
        self.m_conn_of_interest_storage.append(tmp.copy())

    @staticmethod
    def format_route_table(raw_table):
        for routes in raw_table:
            destination = int(routes[1], 16)
            hex(destination)
            struct.pack("<L", destination)
            routes[1] = socket.inet_ntoa(struct.pack("<L", destination))

            getway = int(routes[2], 16)
            hex(getway)
            struct.pack("<L", getway)
            routes[2] = socket.inet_ntoa(struct.pack("<L", getway))

    @staticmethod
    def formatTcpUdpTable(raw_table, table_type):
        readable_table = list(map(list, raw_table))
        for conn in readable_table:
            local = conn[1]
            remote = conn[2]

            spltd = local.split(":")

            if table_type == "TCP" or table_type == "UDP":
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
            else:
                spltd[0] = decode(spltd[0], 'hex')
                spltd[0] = struct.unpack('>IIII', spltd[0])
                spltd[0] = struct.pack('@IIII', *spltd[0])
                spltd[0] = socket.inet_ntop(socket.AF_INET6, spltd[0])
                spltd[1] = int(spltd[1], 16)

                local = str(spltd[0]) + ":" + str(spltd[1])
                conn[1] = local

                spltd = remote.split(":")

                spltd[0] = decode(spltd[0], 'hex')
                spltd[0] = struct.unpack('>IIII', spltd[0])
                spltd[0] = struct.pack('@IIII', *spltd[0])
                spltd[0] = socket.inet_ntop(socket.AF_INET6, spltd[0])
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

        f = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        f.write("/n" + str(t))
        f.close()
        print(t)

    def extract_command_history(self, hasher):
        full_path = os.path.dirname(self._OUTPUT_PATH + "CommandHistory/")
        if not os.path.exists(full_path):
            os.makedirs(full_path)
        print("Extrahovana historia prikazov vsetkych pouzivatelov:")
        for user in self.m_users:
            file_path = full_path + "/" + user
            print(user)
            self.fileCopy("/home/" + str(user) + "/.bash_history", file_path)
            hasher.store_hash(file_path, True, 3)
        self.fileCopy("/root/.bash_history", full_path + "/root")
        hasher.store_hash(full_path + "/root", True, 3)

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

        f = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        f.write("/n" + str(t))
        f.close()
        print(t)

    def fileCopy(self, src, dst):
        if path.exists(src):
            try:
                file = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
            except IOError:
                print("Subor sa nepodarilo otvorit")
                return
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            file.write("\n" + dt_string)
            file.write(" - Vytvorena kopia suboru: " + src + " \n")
            file.close()

            copyfile(src, dst)
            print("Subor " + src + " - stiahnuty")
        else:
            print("Vstpny subor neexistuje!" + " " + src)

    def exportLogs(self, hasher):
        if path.exists("/var/log/syslog"):
            self.fileCopy("/var/log/syslog", self._OUTPUT_PATH + "syslog")
            hasher.store_hash(self._OUTPUT_PATH + "syslog", True, "3")

        if path.exists("/var/log/auth.log"):
            self.fileCopy("/var/log/auth.log", self._OUTPUT_PATH + "auth.log")
            hasher.store_hash(self._OUTPUT_PATH + "auth.log", True, "3")

        if path.exists("/var/log/boot.log"):
            self.fileCopy("/var/log/boot.log", self._OUTPUT_PATH + "boot.log")
            hasher.store_hash(self._OUTPUT_PATH + "boot.log", True, "3")

        if path.exists("/var/log/kern.log"):
            self.fileCopy("/var/log/kern.log", self._OUTPUT_PATH + "kern.log")
            hasher.store_hash(self._OUTPUT_PATH + "kern.log", True, "3")

        if path.exists("/var/log/faillog"):
            self.fileCopy("/var/log/faillog", self._OUTPUT_PATH + "faillog")
            hasher.store_hash(self._OUTPUT_PATH + "faillog", True, "3")

        file = open(self._OUTPUT_PATH + "Protokol/" + self._CASE_NAME, "a")
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        file.write("\n" + dt_string)
        file.write(
            " - Extrahovane logy: /var/log/syslog; /var/log/auth.log; /var/log/boot.log; /var/log/kern.log; /var/log/faillog; \n")
        file.close()

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

    def get_users_uid(self):
        try:
            f = open("/etc/passwd", "r")
        except IOError:
            print("Subor /etc/passwd sa nepodarilo otvorit")
            return
        lines = f.readlines()
        for usr in self.m_users:
            found = False
            for line in lines:
                if usr in line:
                    line = line.split(":")
                    if line[0] == str(usr):
                        self.m_uids.append(line[2])
                        found = True
                        break
            if not found:
                self.m_uids.append("-1")


class Process:
    m_pid = 0
    m_comm = ""
    m_uid = ""
    m_wchan = ""
    m_ppid = ""
    m_state = ""
    m_start_time = ""
    m_cpu_usage = ""
    m_ram_usage = ""
