# ip_tracking/admin.py
from django.contrib import admin
from .models import BlockedIP, RequestLog


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'path', 'timestamp', 'blocked')
    ordering = ('-timestamp',)
    list_filter = ('blocked',)


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "blocked_at", "note")
    search_fields = ("ip_address", "note")
    readonly_fields = ("blocked_at",)
