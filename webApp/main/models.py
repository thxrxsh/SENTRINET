from django.db import models
from django.contrib.auth.models import User

class ScanRecord(models.Model):
    record_id = models.AutoField(primary_key=True)
    start_time = models.DateTimeField(unique=True)
    stop_time = models.DateTimeField()
    status = models.CharField(max_length=45)
    csv_filename = models.CharField(max_length=45)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class Alert(models.Model):
    date_time = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
    message_status = models.CharField(max_length=20, default='Normal')
    seen = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"Alert for {self.user.username} at {self.date_time}"