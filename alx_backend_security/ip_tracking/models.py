# ip_tracking/models.py
from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=255)
    blocked = models.BooleanField(default=False)  # NEW: mark if request was blocked
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - blocked={self.blocked}"


class BlockedIP(models.Model):
    ip_address = models.CharField(max_length=45, unique=True, db_index=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-blocked_at"]
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"

    def __str__(self) -> str:
        return f"{self.ip_address}"


class SuspiciousIP(models.Model):
    """
    Stores IPs flagged by anomaly detection.
    An IP may have multiple reasons; avoid duplicate (ip, reason).
    """
    ip_address = models.CharField(max_length=45, db_index=True)
    reason = models.CharField(max_length=255)
    detected_at = models.DateTimeField(auto_now_add=True)
    handled = models.BooleanField(default=False)  # optional: mark when reviewed

    class Meta:
        unique_together = ("ip_address", "reason")
        ordering = ("-detected_at",)
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"

    def __str__(self):
        return f"{self.ip_address} - {self.reason} @ {self.detected_at:%Y-%m-%d %H:%M:%S}"
