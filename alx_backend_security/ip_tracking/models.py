# ip_tracking/models.py
from django.db import models

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
