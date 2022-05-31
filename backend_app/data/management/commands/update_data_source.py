from django.core.management.base import BaseCommand

from data.models import DataSource
from data.tasks import download_import_recent_cve


class Command(BaseCommand):
    def handle(self, *args, **options):
        # check if source are enabled
        cve_source = DataSource.objects.get(name="CVE")
        if not cve_source.is_enabled:
            print("CVE data source is disabled")
            return
        else:
            print("Updating CVE data source")
            download_import_recent_cve()
