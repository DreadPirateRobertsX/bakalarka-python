import extractor

extr = extractor.MyExtractor()

extr.getProcesses()
extr.store_processes(True)

extr.getNetworkConn()
extr.store_connections()

extr.exportLogs()

extr.printProcesses(0, True)
extr.printNetworkConn()

pid = [1, 9, 8]
ppid = [1]
uid = [1000]
extr.getProcessesOfInterest(pid, ppid, uid)
extr.store_processes(False)
extr.printProcesses(0, False)
print("a")
tcp = []
sl = ["1", "2"]
local = []
remote = []
status = []
extr.GetConnOfInterest(tcp, sl, local, remote, status)
