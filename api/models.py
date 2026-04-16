from django.db import models
from django.utils import timezone
import uuid
# Create your models here.


class Scan(models.Model):
    session_id = models.CharField(max_length=100, blank=True, null=True)
    external_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    url = models.URLField()
    scan_date = models.DateTimeField(auto_now_add=True)
    
    status = models.CharField(max_length=20, default='pending')
    findings = models.TextField(blank=True, null=True)
    
    
    def __str__(self):
        return f"{self.id} - {self.url}"