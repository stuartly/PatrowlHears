from django.core.management.base import BaseCommand

from data.tasks import download_import_recent_cve


class Command(BaseCommand):
    def handle(self, *args, **options):
        download_import_recent_cve()
