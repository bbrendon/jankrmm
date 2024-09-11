from django.core.mail import send_mail
from django.db import models
from django.utils import timezone
from django.conf import settings


class Computer(models.Model):
    serial = models.CharField(max_length=50, primary_key=True)
    hostname = models.CharField(max_length=50, null=True)
    ip = models.GenericIPAddressField(null=True)
    ip_public = models.GenericIPAddressField(null=True)
    # operating_system = models.CharField(max_length=255)
    os_version = models.CharField(max_length=255, null=True)
    processor = models.CharField(max_length=255, null=True)
    ram = models.FloatField(help_text="RAM capacity in MB", null=True)
    storage = models.FloatField(help_text="Disk space in GB", null=True)
    last_check_in = models.DateTimeField(null=True, blank=True)
    # record_modified = models.DateTimeField(auto_now=True)
    console_user = models.CharField(max_length=50, null=True)

    # defender_status = JSONField(null=True)

    # antivirus_mode : active/inactive  (with timestamp)
    # Platform : Version 4.18.24060.7 (with timestamp)
    # Engine : Version 1.1.24060.5  (with timestamp)
    # Security intelligence Version 1.415.235.0 (with timestamp)
    # Last quick scan - Completed (with timestamp)
    # Last full scan  - ? (with timestamp)

    def __str__(self):
        return self.hostname or self.serial or "Unnamed Computer"

class DefenderStatus(models.Model):
    ACTIVE_INACTIVE_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),
    ]

    computer = models.OneToOneField(
        Computer, on_delete=models.CASCADE, related_name="defender_status"
    )
    antivirus_mode = models.CharField(
        max_length=10, choices=ACTIVE_INACTIVE_CHOICES, default="inactive"
    )
    antivirus_mode_ts = models.DateTimeField(null=True, blank=True)
    platform = models.CharField(max_length=50, null=True, blank=True)
    platform_ts = models.DateTimeField(null=True, blank=True)
    engine = models.CharField(max_length=50, null=True, blank=True)
    engine_ts = models.DateTimeField(null=True, blank=True)
    security_intelligence = models.CharField(max_length=50, null=True, blank=True)
    security_intelligence_ts = models.DateTimeField(null=True, blank=True)
    last_quick_scan_ts = models.DateTimeField(null=True, blank=True)
    last_full_scan_ts = models.DateTimeField(null=True, blank=True)
    last_event_ts = models.DateTimeField(null=True, blank=True)

    # update engine_ts when engine changes
    # This updates intermittently. confusing.? ??
    def save(self, *args, **kwargs):
        # Check if the engine field has changed
        if self.pk is not None:
            old_instance = DefenderStatus.objects.get(pk=self.pk)

            if old_instance.engine != self.engine:
                self.engine_ts = timezone.now()

            if old_instance.security_intelligence != self.security_intelligence:
                self.security_intelligence_ts = timezone.now()

            if old_instance.antivirus_mode != self.antivirus_mode:
                print(
                    f"{self.computer.hostname} / {self.computer.serial} : mode changed to {self.antivirus_mode}"
                )
                self.antivirus_mode_ts = timezone.now()
                send_mail(
                    f"Defender alert on {self.computer.hostname} / {self.computer.serial}",
                    f"The antivirus mode has changed from {old_instance.antivirus_mode} to {self.antivirus_mode}.",
                    settings.EMAIL_FROM,  # sender email
                    [settings.EMAIL_TO],  #   recipient email
                    fail_silently=False,
                )

            if old_instance.platform != self.platform:
                self.platform_ts = timezone.now()

        super().save(*args, **kwargs)

    # def save(self, *args, **kwargs):
    #     if self.pk is not None:
    #         # if the value of engine changes, change the timestamp.
    #         existing_record = DefenderStatus.objects.get(pk=self.pk)
    #         if existing_record.engine != self.engine:
    #             self.engine_ts = timezone.now()
    #     else:
    #         self.engine_ts = timezone.now()

    #     super(DefenderStatus, self).save(*args, **kwargs)

    def __str__(self):
        return f"Defender Status for {self.computer.serial}"


class DefenderEvent(models.Model):
    computer = models.ForeignKey(Computer, on_delete=models.CASCADE, related_name="defender_events")
    event_id = models.IntegerField()
    message = models.TextField()
    severity = models.CharField(max_length=50)
    timestamp = models.DateTimeField()

    def __str__(self):
        return f"{self.computer.serial} / {self.computer.hostname} / {self.timestamp} / {self.event_id}"
