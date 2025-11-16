# ip_tracking/views.py
from functools import wraps
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Try import from the installed package. The package in your venv is "django_ratelimit".
try:
    from django_ratelimit.decorators import ratelimit
except Exception:
    # Fallback to older import name if ever installed as `ratelimit`
    from ratelimit.decorators import ratelimit  # type: ignore

def dynamic_rate_limit(view_func):
    """
    Apply per-IP rate limits:
      - authenticated users: 10/min
      - anonymous users: 5/min
    This wraps the view with a ratelimit decorator at runtime.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        rate = "10/m" if request.user.is_authenticated else "5/m"
        decorated = ratelimit(key="ip", rate=rate, block=True)(view_func)
        return decorated(request, *args, **kwargs)
    return _wrapped_view


@csrf_exempt
@dynamic_rate_limit
def login_view(request):
    """
    Minimal login view for demonstration/testing of rate limiting.
    Expects POST with 'username' and 'password'.
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    username = request.POST.get("username")
    password = request.POST.get("password")

    from django.contrib.auth import authenticate, login
    user = authenticate(request, username=username, password=password)
    if user:
        login(request, user)
        return JsonResponse({"success": True})
    return JsonResponse({"success": False, "error": "Invalid credentials"}, status=401)
