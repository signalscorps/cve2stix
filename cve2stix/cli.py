"""
Parse CLI arguments and pass to cve2stix.main
"""

import argparse
import datetime
import logging
import os
import yaml

import cve2stix
from cve2stix.config import Config, CREDENTIALS_FILE_PATH
from cve2stix.main import main

logger = logging.getLogger(__name__)

def cli():
    arg_parser = argparse.ArgumentParser(
        prog=cve2stix.__appname__,
        description="Turn CVEs and CPEs in the National Vulnerability database into STIX 2.1 Objects.",
        allow_abbrev=False,
    )

    arg_parser.add_argument(
        "--cve-backfill-start-date",
        action="store",
        default=Config.cve_backfill_start_date,
        type=datetime.date.fromisoformat,
        required=True,
        help="Start date for backfilling CVEs from NVD database",
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
    

    config = Config(
        cve_backfill_start_date=args.cve_backfill_start_date,
        api_key=api_key,
    )

    main(config)


