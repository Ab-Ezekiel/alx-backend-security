# ip_tracking/management/commands/block_ip.py
from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = "Add one or more IP addresses to the BlockedIP table."

    def add_arguments(self, parser):
        parser.add_argument("ips", nargs="+", help="IP addresses to block")
        parser.add_argument("--note", "-n", help="Optional note for this block")

    def handle(self, *args, **options):
        ips = options["ips"]
        note = options.get("note") or ""
        created = []
        skipped = []

        for ip in ips:
            ip = ip.strip()
            if not ip:
                continue
            obj, was_created = BlockedIP.objects.get_or_create(ip_address=ip, defaults={"note": note})
            if was_created:
                created.append(ip)
            else:
                skipped.append(ip)

        if created:
            self.stdout.write(self.style.SUCCESS(f"Blocked IPs added: {', '.join(created)}"))
        if skipped:
            self.stdout.write(self.style.WARNING(f"IPs already present (skipped): {', '.join(skipped)}"))
