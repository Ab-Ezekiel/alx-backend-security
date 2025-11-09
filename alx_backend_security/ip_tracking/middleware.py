# ip_tracking/middleware.py
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin

# Lazy import models to avoid app-loading issues during startup
def get_blocked_model():
    from .models import BlockedIP
    return BlockedIP

def get_client_ip_from_request(request):
    """
    Try to obtain client IP reliably:
      - prefer django-ipware if installed
      - else, check X-Forwarded-For then REMOTE_ADDR
    Note: When using a proxy/load balancer, ensure your proxy sets headers
    and your Django `SECURE_PROXY_SSL_HEADER` / `USE_X_FORWARDED_HOST` are properly configured.
    """
    try:
        # prefer django-ipware if available
        from ipware import get_client_ip
        ip, is_routable = get_client_ip(request)
        return ip
    except Exception:
        # fallback
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            # X-Forwarded-For: client, proxy1, proxy2
            ip = xff.split(",")[0].strip()
            if ip:
                return ip
        return request.META.get("REMOTE_ADDR")


class BlocklistMiddleware(MiddlewareMixin):
    """
    Middleware to block requests from IPs present in BlockedIP model.
    Return 403 Forbidden for blocked IPs.
    """
    def process_request(self, request):
        ip = get_client_ip_from_request(request)
        if not ip:
            return None  # can't decide; allow request through (or you could block)

        BlockedIP = get_blocked_model()

        try:
            # Query by exact ip string
            if BlockedIP.objects.filter(ip_address=ip).exists():
                return HttpResponseForbidden("Your IP has been blocked.")
        except Exception:
            # If DB is not available (e.g., during migrations), don't block requests;
            # fail open to keep site reachable. Optionally log this.
            return None

        return None
