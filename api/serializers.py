from rest_framework import serializers
from .models import Scan


class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ['id', 'url', 'scan_date', 'status', 'findings']
        
        read_only_fields = ['id', 'scan_date', 'status', 'findings']
        