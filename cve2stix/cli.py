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
        help="start date for backfilling CVEs from NVD database in YYYY-MM-DD format. For eg., 2020-12-23",
    )

    arg_parser.add_argument(
        "--cve-backfill-end-date",
        action="store",
        default=Config.cve_backfill_end_date,
        type=datetime.date.fromisoformat,
        required=True,
        help="end date for backfilling CVEs from NVD database in YYYY-MM-DD format. For eg., 2020-12-23",
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
        cve_backfill_end_date=args.cve_backfill_end_date,
        api_key=api_key,
    )

    main(config)
