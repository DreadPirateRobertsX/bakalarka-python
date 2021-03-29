import extractor

extr = extractor.MyExtractor()
# test
processes = extr.getProcesses()
extr.getNetworkConn()
extr.exportLogs()

extr.printProcesses()
print("\n")
extr.printNetworkConn()



