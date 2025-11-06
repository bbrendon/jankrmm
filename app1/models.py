from auditlog.registry import auditlog
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone

from .utils import send_mail_custom


class Computer(models.Model):
    STATUS_CHOICES = [
        ("CHANGE_ME", "Change Me"),  # unset status
        ("PREPPED", "Prepped"),
        ("ASSIGNED", "Assigned"),
        ("TERMED_NOT_RETURNED", "Termed Not Returned"),
        ("RETIRED", "Retired"),
        ("IT_STORAGE", "IT Storage"),
        ("WAITING_RETURN", "Waiting for Return"),
        ("LOCATION_UNKNOWN", "Location Unknown"),
    ]

    serial: models.CharField = models.CharField(
        max_length=60,
        primary_key=True,
        validators=[
            RegexValidator(
                regex=r"^[a-zA-Z0-9_-]+$",
                message="Serial must be alphanumeric and can only contain _, -",
            )
        ],
    )
    hostname: models.CharField = models.CharField(max_length=50, null=True, blank=True)
    ip: models.CharField = models.CharField(max_length=255, null=True, blank=True)
    ip_public: models.GenericIPAddressField = models.GenericIPAddressField(null=True, blank=True)
    os_version: models.CharField = models.CharField(max_length=255, null=True, blank=True)
    processor: models.CharField = models.CharField(max_length=255, null=True, blank=True)
    ram: models.FloatField = models.FloatField(
        help_text="RAM capacity in MB", null=True, blank=True
    )
    storage: models.FloatField = models.FloatField(
        help_text="Disk space in GB", null=True, blank=True
    )
    last_check_in: models.DateTimeField = models.DateTimeField(null=True, blank=True)
    # record_modified: models.DateTimeField = models.DateTimeField(auto_now=True)
    console_user: models.CharField = models.CharField(max_length=50, null=True, blank=True)
    laps: models.CharField = models.CharField(
        help_text="Local Admin Password", max_length=50, null=True, blank=True
    )
    asset_tag: models.CharField = models.CharField(max_length=50, null=True, blank=True)
    status: models.CharField = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default="CHANGE_ME",
    )
    warranty_exp: models.DateField = models.DateField(null=True, blank=True)
    assigned_user: models.CharField = models.CharField(max_length=50, null=True, blank=True)
    assigned_date: models.DateField = models.DateField(null=True, blank=True)
    encryption_enabled: models.BooleanField = models.BooleanField(
        verbose_name="Encrypted", null=True, default=None
    )
    encryption_key: models.TextField = models.TextField(null=True, blank=True)
    notes: models.TextField = models.TextField(null=True, blank=True)

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
                send_mail_custom(
                    self.computer,
                    f"The antivirus mode has changed from {old_instance.antivirus_mode} to {self.antivirus_mode}.",
                )
                # send_mail(
                #     f"Defender alert on {self.computer.hostname} / {self.computer.serial}",
                #     f"The antivirus mode has changed from {old_instance.antivirus_mode} to {self.antivirus_mode}.",
                #     settings.EMAIL_FROM,  # sender email
                #     # [settings.EMAIL_TO],  #   recipient email
                #     settings.EMAIL_TO.split(','),
                #     fail_silently=False,
                # )

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


auditlog.register(Computer, include_fields=["status", "assigned_user"])
