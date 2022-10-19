"""
Parse CLI arguments and pass to cve2stix.main
"""

import argparse
from datetime import datetime, timedelta, date
from dateutil.relativedelta import relativedelta
import logging
import os
import yaml

import cve2stix
from cve2stix.config import Config, CREDENTIALS_FILE_PATH, STIX2_OBJECTS_FOLDER
from cve2stix.main import main

logger = logging.getLogger(__name__)


def cli():
    arg_parser = argparse.ArgumentParser(
        prog=cve2stix.__appname__,
        description="Turn CVEs and CPEs in the National Vulnerability database into STIX 2.1 Objects.",
        allow_abbrev=False,
    )

    arg_parser.add_argument(
        "--download-settings",
        action="store",
        type=str,
        required=True,
        help="Settings for first time download of CVEs and CPEs",
    )

    # arg_parser.add_argument(
    #     "--download-updates",
    #     action="store",
    #     type=str,
    #     required=True,
    #     help="Settings for first time download of CVEs and CPEs",
    # )


    args = arg_parser.parse_args()

    api_key = None
    if os.path.exists(CREDENTIALS_FILE_PATH):
        with open(CREDENTIALS_FILE_PATH, "r") as stream:
            try:
                data = yaml.safe_load(stream)
                api_key = data["nvd_api_key"]
            except:
                pass
    
    cve_backfill_start_date = datetime.now() - relativedelta(months=6)
    cve_backfill_end_date = datetime.now()
    stix2_objects_folder = STIX2_OBJECTS_FOLDER

    with open(args.download_settings, "r") as stream:
        try:
            data = yaml.safe_load(stream)
            cve_backfill_start_date = data["cve-earliest-publish-date"]
            cve_backfill_end_date = data["cve-latest-publish-date"]
            if data.get("stix2-objects-folder"):
                stix2_objects_folder = data.get("stix2-objects-folder")
        except yaml.YAMLError:
            raise ValueError("Incorrect yaml file in ")

    if not isinstance(cve_backfill_start_date, date):
        logger.error("cve-earliest-publish-date is not in ISO format.")
        exit(1)

    if not isinstance(cve_backfill_end_date, date):
        logger.error("cve-earliest-latest-date is not in ISO format.")
        exit(1)
    


    config = Config(
        cve_backfill_start_date=cve_backfill_start_date,
        cve_backfill_end_date=cve_backfill_end_date,
        stix2_objects_folder=stix2_objects_folder,
        api_key=api_key,
    )

    main(config)
