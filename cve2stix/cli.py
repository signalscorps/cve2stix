"""
Parse CLI arguments and pass to cve2stix.main
"""

import argparse
from datetime import datetime, date
from dateutil.relativedelta import relativedelta
import logging
import os
import yaml

import cve2stix
from cve2stix.enrichment import Enrichment
from cve2stix.config import (
    STIX2_BUNDLES_FOLDER,
    Config,
    CREDENTIALS_FILE_PATH,
    STIX2_OBJECTS_FOLDER,
)
from cve2stix.main import main

logger = logging.getLogger(__name__)


def cli():
    arg_parser = argparse.ArgumentParser(
        prog=cve2stix.__appname__,
        description="Turn CVEs in the National Vulnerability database into STIX 2.1 Objects.",
        allow_abbrev=False,
    )

    arg_parser.add_argument(
        "--settings",
        action="store",
        type=str,
        required=True,
        help="Settings for cve2stix tool",
    )

    args = arg_parser.parse_args()

    api_key = None
    if os.path.exists(CREDENTIALS_FILE_PATH):
        with open(CREDENTIALS_FILE_PATH, "r") as stream:
            try:
                data = yaml.safe_load(stream)
                api_key = data["nvd_api_key"]
            except:
                pass

    cve_start_date = datetime.now() - relativedelta(months=2)
    cve_end_date = datetime.now()
    stix2_objects_folder = STIX2_OBJECTS_FOLDER
    stix2_bundles_folder = STIX2_BUNDLES_FOLDER
    enrichments = False
    run_mode = "download"

    with open(args.settings, "r") as stream:
        try:
            data = yaml.safe_load(stream)
            cve_start_date = data["earliest-cve-date"]
            cve_end_date = data["latest-cve-date"]
            if data.get("stix2-objects-folder"):
                stix2_objects_folder = data.get("stix2-objects-folder")
            if data.get("stix2-bundles-folder"):
                stix2_bundles_folder = data.get("stix2-bundles-folder")
            if data.get("run-mode"):
                run_mode = data.get("run-mode")
            if data.get("enrichments-folder-path"):
                enrichments_folder_path = data.get("enrichments-folder-path")

        except yaml.YAMLError:
            raise ValueError("Incorrect yaml file in ")

    if not isinstance(cve_start_date, date):
        logger.error("cve-earliest-publish-date is not in ISO format.")
        exit(1)

    if not isinstance(cve_end_date, date):
        logger.error("cve-earliest-latest-date is not in ISO format.")
        exit(1)

    if run_mode not in ("download", "update"):
        logger.error("run-mode should be one of 'download' or 'update'")
        exit(1)

    config = Config(
        cve_start_date=cve_start_date,
        cve_end_date=cve_end_date,
        stix2_objects_folder=stix2_objects_folder,
        stix2_bundles_folder=stix2_bundles_folder,
        api_key=api_key,
        run_mode=run_mode,
        enrichments_folder_path=enrichments_folder_path,
    )

    main(config)
