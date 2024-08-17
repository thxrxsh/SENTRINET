import threading
import time
from . import core

scan_thread = None
analysis_thread = None

is_scanning = False
is_analyzing = False
stop_scanning = False
stop_analyzing = False



def capturePackets():
    global stop_scanning
    core.set_stop_flag(False)
    core.capturePackets()


#Fake Analysing Function
def analyzePackets():
    global stop_analyzing
    while not stop_analyzing:
        print("Analyzing packets...")
        time.sleep(5)  # Simulate delay between analyses



def stopScan(request):
    global stop_scanning, stop_analyzing, is_scanning, is_analyzing

    stop_scanning = True
    stop_analyzing = True
    core.set_stop_flag(True)
    core.saveScanRecords(request)

    if scan_thread is not None:
        scan_thread.join()

    if analysis_thread is not None:
        analysis_thread.join()

    is_scanning = False
    is_analyzing = False




def startScan():
    global scan_thread, is_scanning, stop_scanning
    global analysis_thread, is_analyzing, stop_analyzing

    if not is_scanning:  
        is_scanning = True
        stop_scanning = False
        scan_thread = threading.Thread(target=capturePackets)
        scan_thread.start()


    if not is_analyzing: 
        is_analyzing = True
        stop_analyzing = False
        analysis_thread = threading.Thread(target=analyzePackets)
        analysis_thread.start()
