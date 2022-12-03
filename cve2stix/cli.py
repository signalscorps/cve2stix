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
    STIX2_OBJECTS_FOLDER,
    STIX2_BUNDLES_FOLDER,
    STIX2_ENRICHMENTS_FOLDER,
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
                stix2_enrichments_folder=data.get(
                    "stix2-enrichments-folder", STIX2_ENRICHMENTS_FOLDER
                ),
                stix2_objects_folder=data.get(
                    "stix2-objects-folder", STIX2_OBJECTS_FOLDER
                ),
                stix2_bundles_folder=data.get(
                    "stix2-bundles-folder", STIX2_BUNDLES_FOLDER
                ),
                api_key=api_key,
            )

        except yaml.YAMLError:
            raise ValueError("Invalid yaml file")

    main(config)


if __name__ == "__main__":
    cli()
