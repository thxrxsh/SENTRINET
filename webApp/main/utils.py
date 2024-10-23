from django.utils import timezone

import threading
import time
from datetime import datetime
import pytz
from . import core
from . import database

scan_thread = None
analysis_thread = None

is_scanning = False
is_analyzing = False
stop_scanning = False
stop_analyzing = False

SCAN_STATUS = "Protected"



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
    global stop_scanning, stop_analyzing, is_scanning, is_analyzing, RECORD_ID

    stop_scanning = True
    stop_analyzing = True
    core.set_stop_flag(True)

    RECORD_ID = core.saveScanRecords(request)

    if scan_thread is not None:
        scan_thread.join()

    if analysis_thread is not None:
        analysis_thread.join()

    is_scanning = False
    is_analyzing = False



def startScan():
    global START_TIME
    global scan_thread, is_scanning, stop_scanning
    global analysis_thread, is_analyzing, stop_analyzing

    if not is_scanning:
        START_TIME = datetime.now()
        is_scanning = True
        stop_scanning = False
        scan_thread = threading.Thread(target=capturePackets)
        scan_thread.start()



    if not is_analyzing: 
        is_analyzing = True
        stop_analyzing = False
        analysis_thread = threading.Thread(target=analyzePackets)
        analysis_thread.start()



def convertTimeZone(request, date_time):
    user_timezone = request.session.get('django_timezone')

    if user_timezone:
        tz = pytz.timezone(user_timezone)
    else:
        tz = pytz.timezone('UTC')

    # Ensure date_time is timezone-aware
    if timezone.is_naive(date_time):
        date_time = timezone.make_aware(date_time, timezone.get_current_timezone())

    # Convert to user's timezone
    date_time = timezone.localtime(date_time, tz)

    return date_time




def getScanSummary(request):
    global RECORD_ID
    scan_summary = {}

    record = database.getRecord(RECORD_ID)

    if record:
        scan_summary['record_id'] = RECORD_ID
        
        file_name = record.csv_filename

        duration = record.stop_time - record.start_time

        start_time = convertTimeZone(request, record.start_time) 
        stop_time = convertTimeZone(request, record.stop_time)

        scan_summary['start_date'] = start_time.strftime('%Y-%m-%d')
        scan_summary['start_time'] = start_time.strftime('%H:%M:%S')

        total_seconds = int(duration.total_seconds())
        days, remainder = divmod(total_seconds, 86400)  # 86400 seconds in a day
        hours, remainder = divmod(remainder, 3600)      # 3600 seconds in an hour
        minutes, seconds = divmod(remainder, 60)              # 60 seconds in a minute

        scan_summary['duration'] = [days, hours, minutes, seconds]

        counts = core.getCounts(file_name)
        scan_summary['counts'] = counts
        scan_summary['status'] = core.analyzeStatus(file_name)
    else:
        scan_summary['error'] = 'Record not found'

    return scan_summary



def getReportsList(request):
    
    scan_records = database.getRecords(request.user)
    records_list = []
    for record in scan_records:

        duration = record.stop_time - record.start_time

        days = duration.days
        hours, remainder = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        # formatted_duration = f"{days}d {hours}h {minutes}min {seconds}sec"
        formatted_duration = [days, hours, minutes, seconds]

        start_time = convertTimeZone(request, record.start_time) 
        stop_time = convertTimeZone(request, record.stop_time)

        record_data = {
            'record_id': record.record_id,
            'start_date': start_time.strftime('%Y-%m-%d'),
            'start_time': start_time.strftime('%H:%M:%S'),
            'duration': formatted_duration,
            'status': record.status,
        }
        records_list.append(record_data)

    return records_list




def getReport(request, report_id):
    
    report_details = {}

    record = database.getRecord(report_id)

    if record:
        file_name = record.csv_filename

        duration = record.stop_time - record.start_time

        start_time = convertTimeZone(request, record.start_time) 
        stop_time = convertTimeZone(request, record.stop_time)

        report_details['start_date'] = start_time.strftime('%Y-%m-%d')
        report_details['start_time'] = start_time.strftime('%H:%M:%S')

        report_details['stop_date'] = stop_time.strftime('%Y-%m-%d')
        report_details['stop_time'] = stop_time.strftime('%H:%M:%S')

        total_seconds = int(duration.total_seconds())
        days, remainder = divmod(total_seconds, 86400)  # 86400 seconds in a day
        hours, remainder = divmod(remainder, 3600)      # 3600 seconds in an hour
        minutes, seconds = divmod(remainder, 60)              # 60 seconds in a minute

        report_details['duration'] = [days, hours, minutes, seconds]

        counts = core.getCounts(file_name)
        packet_details = core.getPacketDetails(file_name)
        status = core.analyzeStatus(file_name)

        report_details['counts'] = counts
        report_details['status'] = status
        report_details['packet_details'] = packet_details

    else:
        report_details['error'] = 'Record not found'

    return report_details



def liveStatus(request):
    live_status = {}

    counts = core.getCounts(core.PACKETS_CSV_PATH)
    status = core.analyzeStatus(core.PACKETS_CSV_PATH)

    live_status['counts'] = counts
    live_status['status'] = status

    return live_status



def liveReport(request):
    global START_TIME, SCAN_STATUS
    report_details = {}

    start_time = START_TIME
    current_time = datetime.now()

    duration = current_time - start_time
    

    start_time = convertTimeZone(request, start_time)
    # current_time = convertTimeZone(request, current_time)



    report_details['start_date'] = start_time.strftime('%Y-%m-%d')
    report_details['start_time'] = start_time.strftime('%H:%M:%S')

    total_seconds = int(duration.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)  
    minutes, seconds = divmod(remainder, 60)         

    report_details['duration'] = [days, hours, minutes, seconds]

    counts = core.getCounts(core.PACKETS_CSV_PATH)
    packet_details = core.getPacketDetails(core.PACKETS_CSV_PATH)
    status = core.analyzeStatus(core.PACKETS_CSV_PATH)

    if status != SCAN_STATUS:

        if status == 'Protected':
            message = f"Your network is Protected"
            addAlert(request, message, "message-normal")

        elif status == 'Low Risk':
            message = f"Your network is currently in a Low-Risk status"
            addAlert(request, message, "message-warning")

        elif status == 'Medium Risk':
            message = f"Your network is currently in a Medium-Risk status"
            addAlert(request, message, "message-warning")

        elif status == 'High Risk':
            message = f"Your network is currently in a High-Risk status"
            addAlert(request, message, "message-danger")

        elif status == 'Critical':
            message = f"Your network is currently in a Critical status"
            addAlert(request, message, "message-danger")

        SCAN_STATUS = status


    report_details['counts'] = counts
    report_details['status'] = status
    report_details['packet_details'] = packet_details

    return report_details




def deleteReport(request, report_id):
    try:
        csv_filename = database.deleteRecord(report_id)
        core.deleteCSV(csv_filename)
        return True

    except:
        return False



def addAlert(request, message, status):
    alert = database.insertAlert(request.user, message, status)
    request.session['new_alerts_count'] += 1
    return alert


def removeAlert(alert_id):
    return database.deleteAlert(alert_id)



def getAlerts(request):

    user_timezone = request.session.get('django_timezone')

    unseen_alerts = database.getUserAlerts(request.user, user_timezone, False)
    seen_alerts = database.getUserAlerts(request.user, user_timezone, True)

    unseen_alerts_serialized = list(unseen_alerts.values('id', 'message', 'date_time', 'seen', 'message_status'))
    seen_alerts_serialized = list(seen_alerts.values('id', 'message', 'date_time', 'seen', 'message_status'))

    alerts = {
        'unseen': unseen_alerts_serialized,
        'seen': seen_alerts_serialized
    }

    database.markAllAlertsAsSeen(request.user)

    request.session['new_alerts_count'] = 0
    return alerts



def checkForNewAlerts(request):
    return request.session['new_alerts_count']

def checkForTotalAlerts(request):
    alerts = database.getUserAlerts(request.user)
    alerts_count = len(list(alerts.values('id', 'message', 'date_time', 'seen', 'message_status')))
    return alerts_count


def getLastReportDetails(request):
    last_record = database.getRecords(request.user).first()

    if last_record:

        last_record.stop_time = convertTimeZone(request, last_record.stop_time)

        report_details = {
            'report_id' : last_record.record_id,
            'scan_status': last_record.status,
            'stop_time': last_record.stop_time,
        }

    else:
        report_details = None

    return report_details
    