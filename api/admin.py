from django.contrib import admin

from api.models import Scan

# Register your models here.

class ScanAdmin(admin.ModelAdmin):
    list_display = ('session_id', 'external_id', 'url', 'scan_date', 'status')
    readonly_fields = ('external_id', 'scan_date', 'status', 'findings')
    
admin.site.register(Scan, ScanAdmin)