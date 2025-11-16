# ip_tracking/middleware.py
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.utils.module_loading import import_string


def get_client_ip(request):
    """
    Try to get ipware first, fallback to X-Forwarded-For and REMOTE_ADDR.
    Returns the IP string or None.
    """
    try:
        # try ipware if available
        from ipware import get_client_ip as ipware_get_client_ip
        ip, _ = ipware_get_client_ip(request)
        if ip:
            return ip
    except Exception:
        # ipware not installed or failed, fallback below
        pass

    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        # X-Forwarded-For may contain a comma-separated list
        ip = xff.split(",")[0].strip()
        if ip:
            return ip

    return request.META.get("REMOTE_ADDR")


def geolocate_from_request_or_backend(request, ip):
    """
    Try to obtain geolocation info (country, city) for an IP.
    Preference order:
    1) cached value
    2) request.geolocation (set by django-ip-geolocation middleware)
    3) programmatic backend call (best-effort)
    Returns dict with keys 'country' and 'city' (values may be None).
    """
    if not ip:
        return {"country": None, "city": None}

    cache_key = f"geo:{ip}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    geo_result = {"country": None, "city": None}

    # 1) try request.geolocation (middleware from django-ip-geolocation)
    geo_obj = getattr(request, "geolocation", None)
    if geo_obj:
        # handle several possible shapes (dict-like, object-like)
        try:
            # dict-like
            if isinstance(geo_obj, dict):
                country = None
                city = None
                c = geo_obj.get("country")
                if isinstance(c, dict):
                    country = c.get("name") or c.get("code")
                else:
                    country = c
                # city may be top-level or in 'city' key
                city = geo_obj.get("city") or (geo_obj.get("region") and geo_obj.get("region").get("name"))
                geo_result["country"] = country
                geo_result["city"] = city
            else:
                # object-like: try attributes _country, _geo, country, city
                country = None
                city = None
                country_attr = getattr(geo_obj, "_country", None) or getattr(geo_obj, "country", None)
                if isinstance(country_attr, dict):
                    country = country_attr.get("name") or country_attr.get("code")
                else:
                    country = country_attr
                # try city from object attributes
                city_attr = getattr(geo_obj, "_city", None) or getattr(geo_obj, "city", None)
                if isinstance(city_attr, dict):
                    city = city_attr.get("name") or city_attr.get("city")
                else:
                    city = city_attr
                geo_result["country"] = country
                geo_result["city"] = city
        except Exception:
            pass

    # 2) If still missing values, try the configured backend programmatically
    if not geo_result.get("country") or not geo_result.get("city"):
        backend_path = getattr(settings, "IP_GEOLOCATION_SETTINGS", {}).get(
            "BACKEND", "django_ip_geolocation.backends.IPGeolocationAPI"
        )
        try:
            BackendClass = import_string(backend_path)
            backend = BackendClass()
            # try geolocate with ip argument, if signature accepts it; otherwise call without args
            try:
                backend.geolocate(ip)
            except TypeError:
                # some implementations require no arg and use settings.FORCE_IP_ADDR or request context,
                # fallback to calling geolocate() and hope backend uses ip param another way
                try:
                    backend.geolocate()
                except Exception:
                    pass

            # backend should expose _country and _geo (per package README)
            c = getattr(backend, "_country", None) or getattr(backend, "country", None)
            if isinstance(c, dict):
                geo_result["country"] = geo_result.get("country") or (c.get("name") or c.get("code"))
            else:
                geo_result["country"] = geo_result.get("country") or c

            g = getattr(backend, "_geo", None) or getattr(backend, "geo", None)
            # depending on backend, city might be in _raw_data or other attr; try best-effort
            if isinstance(g, dict):
                # some backends put 'city' at different levels, attempt common ones
                geo_result["city"] = geo_result.get("city") or g.get("city") or g.get("name")
            else:
                # fallback: sometimes backend has _raw_data containing city under keys
                raw = getattr(backend, "_raw_data", None)
                if isinstance(raw, dict):
                    geo_result["city"] = geo_result.get("city") or raw.get("city") or raw.get("city_name") or raw.get("region")
        except Exception:
            # backend import/call failed or no API, silently fail (we'll store None)
            pass

    # Cache for 24 hours (24*3600 seconds)
    try:
        cache.set(cache_key, geo_result, 24 * 3600)
    except Exception:
        # caching failing should not stop the request
        pass

    return geo_result


class CombinedIPMiddleware:
    """
    Middleware that:
     - obtains client IP
     - enriches with geolocation (country, city) using django-ip-geolocation or backend
     - logs every request to RequestLog (with `blocked` flag)
     - blocks requests whose IP is in BlockedIP, returning 403
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = get_client_ip(request)
        path = request.path
        timestamp = timezone.now()

        # Lazy import models to avoid app-loading issues during startup/migrations
        try:
            from .models import RequestLog, BlockedIP
        except Exception:
            RequestLog = None
            BlockedIP = None

        # Determine blocked state (fail-open: if DB not available, treat as not blocked)
        is_blocked = False
        try:
            if ip and BlockedIP is not None:
                is_blocked = BlockedIP.objects.filter(ip_address=ip).exists()
        except Exception:
            # DB error: fail-open (do not block). Optionally log to logger (not to DB).
            is_blocked = False
            
        # Geolocation (cache-aware)
        geo = geolocate_from_request_or_backend(request, ip)
        country = geo.get("country")
        city = geo.get("city")

        # Attempt to log the request (non-blocking on DB failure)
        try:
            if RequestLog is not None:
                RequestLog.objects.create(
                    ip_address=ip or "unknown",
                    path=path or "",
                    timestamp=timestamp,
                    blocked=is_blocked,
                    country=country,
                    city=city,
                )
        except Exception:
            # If logging fails (DB unavailable), don't block the request for availability.
            pass

        # If blocked, return 403
        if is_blocked:
            return HttpResponseForbidden("Your IP has been blocked.")

        # Otherwise proceed to view
        response = self.get_response(request)
        return response
