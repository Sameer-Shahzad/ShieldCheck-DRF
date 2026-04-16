from rest_framework import serializers
from .models import Scan


class ScanSerializer(serializers.ModelSerializer):
    
    session_id = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    class Meta:
        model = Scan
        fields = ['session_id', 'url', 'scan_date', 'status', 'findings']
        
        read_only_fields = ['scan_date', 'status', 'findings']
        