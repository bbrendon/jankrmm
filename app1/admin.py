# from django.utils.timezone import localtime
from django.conf.locale.en import formats as en_formats
from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from django.utils.text import Truncator

# Register your models here.
from .models import Computer, DefenderEvent, DefenderStatus

# en_formats.DATETIME_FORMAT = "Y-m-d H:m"  # https://t.ly/Bfitw
en_formats.DATETIME_FORMAT = "Y-m-d H:i"  # https://t.ly/Bfitw


class DefenderStatusInline(admin.TabularInline):
    model = DefenderStatus
    extra = 0  # No extra empty forms


class ComputerAdmin(admin.ModelAdmin):
    def last_event_ts(self, obj):
        defender_status = DefenderStatus.objects.filter(computer=obj).first()
        
        return defender_status.last_event_ts if defender_status else None

    def truncated_serial(self, obj):
        return Truncator(obj.serial).chars(12)  


    list_display = (
        "truncated_serial",
        "hostname",
        "ip",
        "ip_public",
        "os_version",
        "console_user",
        "last_check_in",
        "last_event_ts",
        "antivirus_mode_status",
        "view_text_file", 
    )

            
    inlines = [DefenderStatusInline]  # Add the inline to the Computer admin


    last_event_ts.short_description = "Defender TS"
    truncated_serial.short_description = "Serial"  # Column name in the admin

    def antivirus_mode_status(self, obj):
        defender_status = DefenderStatus.objects.filter(computer=obj).first()
        return defender_status.antivirus_mode if defender_status else None

    antivirus_mode_status.short_description = "Antivirus"  # Column name in the admin

    def view_text_file(self, obj):
        url = reverse('view_text_file', args=[obj.serial])
        return format_html('<a href="{}" target="_blank">View Text File</a>', url)

    view_text_file.short_description = "Text File"  # Column name in the admin


class DefenderStatusAdmin(admin.ModelAdmin):
    # fields to display
    list_display = (
        "computer",
        "last_event_ts",
        "antivirus_mode",
        "antivirus_mode_ts",
        "platform",
        "platform_ts",
        "engine",
        "engine_ts",
        "security_intelligence",
        "security_intelligence_ts",
        "last_quick_scan_ts",
        "last_full_scan_ts",
    )


class DefenderEventAdmin(admin.ModelAdmin):
    list_display = ("computer", "timestamp", "event_id", "message", "severity")
    list_filter = (
        "computer",
        "event_id",
    )


# Register the Computer model with the custom admin class
admin.site.register(Computer, ComputerAdmin)
admin.site.register(DefenderStatus, DefenderStatusAdmin)
admin.site.register(DefenderEvent, DefenderEventAdmin)
