from django.contrib import admin

from api.models import Scan

# Register your models here.

class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'url', 'scan_date', 'status')
    readonly_fields = ('id', 'scan_date', 'status', 'findings')
    
admin.site.register(Scan, ScanAdmin)