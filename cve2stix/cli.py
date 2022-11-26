"""
Parse CLI arguments and pass to cve2stix.main
"""

import argparse
import logging
import os
import yaml

import cve2stix
from cve2stix.config import (
    Config,
    CREDENTIALS_FILE_PATH,
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

    api_key = ""
    if os.path.exists(CREDENTIALS_FILE_PATH):
        with open(CREDENTIALS_FILE_PATH, "r") as stream:
            try:
                data = yaml.safe_load(stream)
                api_key = data["nvd_api_key"]
            except:
                pass

    with open(args.settings, "r") as stream:
        try:
            data = yaml.safe_load(stream)

            config = Config(
                type=data.get("type"),
                start_date=data.get("start-date"),
                end_date=data.get("end-date"),
                cve_run_mode=data.get("cve-run-mode"),
                cve_enrichment=data.get("cve-enrichment"),
                cve_folder_path=data.get("cve-folder-path"),
                cpe_folder_path=data.get("cpe-folder-path"),
                api_key=api_key,
            )

        except yaml.YAMLError:
            raise ValueError("Invalid yaml file")

    main(config)
