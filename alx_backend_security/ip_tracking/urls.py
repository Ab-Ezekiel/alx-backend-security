# ip_tracking/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.login_view, name="ip_tracking_login"),
]
