# alx_backend_security/__init__.py
from .celery import app as celery_app

__all__ = ("celery_app",)
