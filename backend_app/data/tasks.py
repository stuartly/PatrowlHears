from celery import shared_task
from django.apps import apps

from .models import DataSource
from .utils import _run_datasync, _run_datasync_model
from common.utils.constants import DATASYNC_MODELS
from common.feeds.metadata import import_exploit
from common.feeds.vulns import import_cpe, import_cve, sync_exploits_fromvia, import_feedvuln
import requests
import re
import os
from os.path import isfile, join
import zipfile
import json
from tqdm import tqdm
import logging
from celery import group
from common.utils import chunks

logger = logging.getLogger(__name__)


@shared_task(bind=True, acks_late=True)
def run_datasync_task(self, limit, since, to):
    _run_datasync(
        limit=limit,
        since=since,
        to=to
    )
    return True


@shared_task(bind=True, acks_late=True)
def run_datasync_model_task(self, model, limit, since, to, store):
    _run_datasync_model(
        model_class=apps.get_model(DATASYNC_MODELS[model]),
        model_name=model,
        limit=limit,
        since=since,
        to=to,
        store=store
    )
    return True


@shared_task(bind=True, acks_late=True)
def run_datasync_models_task(self, limit, since, to, store):
    for m in DATASYNC_MODELS.keys():
        _run_datasync_model(
            model_class=apps.get_model(DATASYNC_MODELS[m]),
            model_name=m,
            limit=limit,
            since=since,
            to=to,
            store=store
        )
    return True


@shared_task(bind=True, acks_late=False, ignore_result=False)
def import_exploit_task(self, data):
    e = import_exploit(data=data)
    if 'status' in e.keys() and e['status'] == 'error':
        logger.error(e['reason'])
    return True


@shared_task(bind=True, acks_late=False, ignore_result=False)
def import_cpe_task(self, vector, title, product, vendor):
    return import_cpe(vector, title, product, vendor)


@shared_task(bind=True, acks_late=False, ignore_result=False)
def import_cve_task(self, data):
    return import_cve(data)


@shared_task(bind=True, acks_late=False, ignore_result=False)
def import_via_task(self, cve_id, data):
    return sync_exploits_fromvia(cve_id, data)


@shared_task(bind=True, acks_late=False, ignore_result=False)
def import_feedvuln_task(self, data, filename, filename_hash):
    return import_feedvuln(data, filename, filename_hash)


@shared_task(bind=True, acks_late=True)
def download_import_recent_cve_task():
    download_import_recent_cve()


def download_import_recent_cve():
    """
        Download the latest CVEs from the NVD and import them into the database.
        :return:
    """

    # check if source are enabled
    data_source = DataSource.objects.get(name="CVE")
    if not data_source.is_enabled:
        return

        # Creating download directory
    download_dir = os.path.dirname(os.path.realpath(__file__)) + "/download/"
    if not os.path.exists(download_dir):
        print("Creating download directory")
        os.makedirs(download_dir)

    # Downloading recent cve and write to file
    print("[+] Downloading CVE dictionary from NVD")
    r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip", stream=True)
    filename = 'nvdcve-1.1-modified.json.zip'
    filepath = download_dir + filename
    with open(filepath, 'wb') as f:
        pbar = tqdm(unit="B", unit_scale=True, total=int(r_file.headers['Content-Length']), desc=filename)
        for chunk in r_file.iter_content(chunk_size=1024):
            f.write(chunk)
            pbar.update(1024)
        pbar.close()

    # Unzip file and read json
    print("read nvdcve-1.1-modified.json.zip")
    archive = zipfile.ZipFile(filepath, 'r')
    jsonfile = archive.open(archive.namelist()[0])
    cve_dict = json.loads(jsonfile.read())
    jsonfile.close()

    # Import cve
    files_sig = []
    for cve_entry in tqdm(cve_dict['CVE_Items']):
        files_sig.append(import_cve_task.s(cve_entry).set(queue='data'))
    pbar = tqdm(total=len(files_sig), desc="CVES-run")
    chunk_size = 32
    for chunk in chunks(files_sig, chunk_size):
        res = group(chunk)()
        res.get()
        pbar.update(chunk_size)
    pbar.close()
