import extractor

extr = extractor.MyExtractor()

processes = extr.getProcesses()
extr.getNetworkConn()
extr.exportLogs()

extr.printProcesses()
print("\n")
extr.printNetworkConn()



