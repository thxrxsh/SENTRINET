from django.db import models
from django.contrib.auth.models import User

class ScanRecord(models.Model):
    record_id = models.AutoField(primary_key=True)
    start_time = models.DateTimeField(unique=True)
    stop_time = models.DateTimeField()
    status = models.CharField(max_length=45)
    csv_filename = models.CharField(max_length=45)
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
