import os


def loadLineToProcess(num, full_path):
    file_ob = open(full_path).readlines()
    line = ""
    for i, line in enumerate(file_ob):
        if i + 1 == num:
            break
    return line


class MyExtractor:
    m_processes = []

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

        full_path = path + "/" + proc.m_pid + "/status"
        line = loadLineToProcess(3, full_path)
        proc.m_state = line

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
        print("PID " + "PPID " + "STATE " + "UID " + "wchan " + "comm\n")
        for process in self.m_processes:
            # print(process.m_pid + " " + process.m_ppid + " " + process.m_state + " " + process.m_uid + " " +
            # process.m_wchan + "\n" + process.m_comm + "\n")
            print(process.m_pid, end=' ')
            print(process.m_ppid, end=' ')
            print(process.m_state, end=' ')
            print(process.m_uid, end=' ')
            print(process.m_wchan, end=' ')
            print(process.m_comm, end='\n')


class Process:
    m_pid = 0
    m_comm = ""
    m_uid = 0
    m_wchan = ""
    m_ppid = 0
    m_state = ""
