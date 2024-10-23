from main.models import ScanRecord, Alert
from django.shortcuts import get_object_or_404
from django.utils.dateformat import format
import pytz
from django.utils import timezone

# Save the details to the ScanRecord table
def saveScanRecord(request, start_time, stop_time, status, new_csv_filename):

    scan_record = ScanRecord(
        start_time=start_time,
        stop_time=stop_time,
        status=status,
        csv_filename=new_csv_filename,
        user=request.user
    )
    scan_record.save()
    print("Data Saved :",scan_record.record_id)

    return scan_record.record_id   
     

def getRecord(record_id):
    scan_record = get_object_or_404(ScanRecord, record_id=record_id)
    return scan_record


def getRecords(user):
    scan_records = ScanRecord.objects.filter(user=user).order_by('-start_time')
    return scan_records



def deleteRecord(record_id):

    scan_record = get_object_or_404(ScanRecord, record_id=record_id)
    csv_filename = scan_record.csv_filename
    scan_record.delete()

    return csv_filename
    




def insertAlert(user, message, status):
    alert = Alert.objects.create(user=user, message=message, message_status=status)
    return alert


def deleteAlert(alert_id):
    try:
        alert = Alert.objects.get(id=alert_id)
        alert.delete()
        return True
    except Alert.DoesNotExist:
        return False





def getUserAlerts(user, user_timezone=None, seen=None):
    alerts = Alert.objects.filter(user=user, seen=seen).order_by('-date_time') if seen is not None else Alert.objects.filter(user=user).order_by('-date_time')

    if user_timezone:
        tz = pytz.timezone(user_timezone)
    else:
        tz = pytz.timezone('UTC')

    for alert in alerts:
        alert.date_time = timezone.localtime(alert.date_time, tz)

    return alerts



def markAllAlertsAsSeen(user):
    alerts = Alert.objects.filter(user=user, seen=False)
    alerts.update(seen=True)
    return alerts


