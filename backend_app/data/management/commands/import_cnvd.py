import os

from django.core.management.base import BaseCommand
from datetime import datetime
import xml.etree.ElementTree as ET
from common.feeds.vulns import import_cve


class Command(BaseCommand):
    def handle(self, *args, **options):

        for f in os.listdir("cnvd_data"):
            file_name = os.path.join("cnvd_data", f)
            print(file_name)
            tree = ET.parse(file_name)
            root = tree.getroot()
            for vulnerability in root:
                save_vuln(vulnerability)


def get_text(element):
    if element is None:
        return ""
    else:
        return element.text


def save_vuln(vulnerability):
    cnvd_id = get_text(vulnerability.find("number"))
    title = get_text(vulnerability.find("title"))
    modified_time_str = get_text(vulnerability.find("openTime"))
    if modified_time_str == "":
        modified_time_str = "2022-4-3"
    modified_time = datetime.strptime(modified_time_str, "%Y-%m-%d")

    published_time_str = get_text(vulnerability.find("submitTime"))
    if published_time_str == "":
        published_time_str = "2022-4-3"
    published_time = datetime.strptime(published_time_str, "%Y-%m-%d")

    description = get_text(vulnerability.find("description"))

    patch_description = get_text(vulnerability.find("patchDescription"))
    discoverer_name = get_text(vulnerability.find("discovererName"))
    reference_links = []
    if vulnerability.find("referenceLink") is not None:
        reference_links = get_text(vulnerability.find("referenceLink")).split()

    formal_way = get_text(vulnerability.find("formalWay"))
    is_event = get_text(vulnerability.find("isEvent"))
    related_cves = vulnerability.find("cves")
    related_cves_list = []
    if related_cves is not None:
        for cve in related_cves:
            cve_number = get_text(cve.find("cveNumber"))
            related_cves_list.append(cve_number)

    products = vulnerability.find("products")
    products_list = []
    if products is not None:
        for product in products:
            products_list.append(get_text(product))

    patch_name = ''
    if vulnerability.find("patchName") is not None:
        patch_name = get_text(vulnerability.find("patchName"))

    long_description = discoverer_name + "\n" + description + "\n" + patch_description + "\n" \
                       + formal_way + "\n" + is_event + "\n" + \
                       "\n" + patch_name + "\n" + patch_description + "\n" + str(products_list)

    data = {
        'cve': {
            'CVE_data_meta': {
                'ID': cnvd_id,
                'ASSIGNER': "",
            },
            'description': {
                'description_data': [{
                    'value': long_description
                }]
            },

            'references': {
                'reference_data': list(map(lambda x: {'url': x, "tags": [], 'name': x}, reference_links))
            },
            'problemtype': {}
        },
        'publishedDate': published_time.strftime('%Y-%m-%dT%H:%MZ'),
        'lastModifiedDate': modified_time.strftime('%Y-%m-%dT%H:%MZ'),
        'impact': {},
        'configurations': {
            'nodes': []
        }
    }

    import_cve(data)
