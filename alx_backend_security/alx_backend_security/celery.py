# alx_backend_security/celery.py
from __future__ import annotations
import os
from celery import Celery
from celery.schedules import crontab

# set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'alx_backend_security.settings')

# create Celery app instance
app = Celery('alx_backend_security')

# load settings from Django settings.py, using CELERY_ prefix
app.config_from_object('django.conf:settings', namespace='CELERY')

# auto-discover tasks from installed apps (e.g., ip_tracking.tasks)
app.autodiscover_tasks()

# --- add the hourly anomaly detection schedule ---
app.conf.beat_schedule = {
    "ip-anomaly-detection-hourly": {
        "task": "ip_tracking.tasks.detect_anomalous_ips",
        "schedule": crontab(minute=0, hour="*"),  # every hour
    },
}
