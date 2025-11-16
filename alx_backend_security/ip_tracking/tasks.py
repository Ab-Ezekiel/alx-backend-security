# ip_tracking/tasks.py
from __future__ import annotations
from datetime import timedelta
import logging
from . import models
from celery import shared_task
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.conf import settings

from .models import RequestLog, SuspiciousIP

logger = logging.getLogger(__name__)

# Configurable thresholds & sensitive paths (override in settings if desired)
RATE_LIMIT_THRESHOLD = getattr(settings, "ANOMALY_RATE_THRESHOLD", 100)  # requests per hour
SENSITIVE_PATHS = getattr(settings, "ANOMALY_SENSITIVE_PATHS", ["/admin", "/login"])


@shared_task(bind=True)
def detect_anomalous_ips(self):
    """
    Celery task to detect suspicious IPs hourly.
    - Flags IPs with > RATE_LIMIT_THRESHOLD requests in the last hour.
    - Flags IPs that accessed any SENSITIVE_PATHS in the last hour.
    Writes to SuspiciousIP model (unique per ip+reason).
    """
    now = timezone.now()
    window_start = now - timedelta(hours=1)

    logger.info("Anomaly detection started: window %s - %s", window_start, now)

    try:
        # 1) Detect heavy requesters: count requests per IP in the last hour
        qs = (
            RequestLog.objects.filter(timestamp__gte=window_start)
            .values("ip_address")
            .order_by()
            .annotate(req_count=models.Count("id"))
            .filter(req_count__gt=RATE_LIMIT_THRESHOLD)
        )

        heavy_ips = [row["ip_address"] for row in qs]
        logger.info("Heavy IPs detected: %s", heavy_ips)

        for ip in heavy_ips:
            reason = f"High request rate: >{RATE_LIMIT_THRESHOLD}/hour"
            _create_suspicious(ip, reason)

        # 2) Detect sensitive-path access
        # Build Q for sensitive paths (simple contains or exact equality depending on your needs)
        from django.db.models import Q

        path_query = Q()
        for p in SENSITIVE_PATHS:
            # match exact path or startswith — adjust as needed
            # here we mark if path equals or starts with the sensitive path
            path_query |= Q(path__startswith=p)

        sensitive_qs = (
            RequestLog.objects.filter(timestamp__gte=window_start)
            .filter(path_query)
            .values("ip_address")
            .distinct()
        )
        sensitive_ips = [row["ip_address"] for row in sensitive_qs]
        logger.info("IPs accessing sensitive paths: %s", sensitive_ips)

        for ip in sensitive_ips:
            reason = f"Accessed sensitive path within last hour: {', '.join(SENSITIVE_PATHS)}"
            _create_suspicious(ip, reason)

    except Exception as exc:
        # If anything unexpected happens, log and re-raise to allow Celery retries if configured
        logger.exception("Anomaly detection failed: %s", exc)
        raise


def _create_suspicious(ip: str, reason: str):
    """
    Create a SuspiciousIP record if not already present (unique per ip+reason).
    This is best-effort and tolerant to race conditions.
    """
    if not ip:
        return
    try:
        with transaction.atomic():
            SuspiciousIP.objects.create(ip_address=ip, reason=reason)
            logger.info("Created SuspiciousIP: %s (%s)", ip, reason)
    except IntegrityError:
        # already exists: ignore
        logger.debug("SuspiciousIP already exists: %s (%s)", ip, reason)
    except Exception:
        logger.exception("Failed to create SuspiciousIP: %s (%s)", ip, reason)
