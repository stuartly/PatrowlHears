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


def download_cnvd_data():
    """
    Download the cnvd data from the cnvd website
    """
    import requests

    user_agent = {
        'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36',
        'Cookie': "__jsluid_s=32988571238275e20e6f4effd4e148fd; __jsl_clearance_s=1649676858.633|0|CVbgdOwe7QH5O%2FCnA2shtPpkIUU%3D; JSESSIONID=68B2F5DBF96711FA4B3D8CEDAECA310C; puk=5478ebd67ede671d674f85b82632b6f4af45cca5e75a93ba0e985e2dc66fe1ff1942d475e9417a37c0d19f26977b0df48f22a3853bbcef22dda23858b585be8c42e13ceaf8e690ce419a93e101c2cb32e03fadf66ae939616b76a7a390318c44bd8fa2d2781a77b1e27a6e825482801e07319ac7a702bdab209b3a4f0fb9d42e"
        }

    for i in range(1, 1200):
        print(i)
        res = requests.get('https://www.cnvd.org.cn/shareData/download/' + str(i), headers=user_agent)
        if res.status_code == 200:
            print("download")
            file_name = res.headers['Content-Disposition'].split('=')[1]
            with open('cnvd_data/' + file_name, 'w', encoding='utf-8') as f:
                f.write(res.text)
