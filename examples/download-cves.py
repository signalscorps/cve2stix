"""
Script for downloading CVEs

This script downloads CVEs and commits them
into the repo

WARNING: This script will add commits
"""

from datetime import datetime
from dateutil import rrule
from dateutil.relativedelta import relativedelta
import git
from pathlib import Path
import os
import sys
import time
import yaml

from cve2stix.config import Config
from cve2stix.main import main
from cve2stix import logger

EXAMPLES_FOLDER = Path(os.path.abspath(__file__)).parent
REPO_FOLDER = EXAMPLES_FOLDER.parent
CREDENTIALS_FILE_PATH = REPO_FOLDER / "credentials.yml"

STIX2_OBJECTS_FOLDER = REPO_FOLDER / "stix2_objects"
STIX2_BUNDLES_FOLDER = REPO_FOLDER / "stix2_bundles"

repo = git.Repo(REPO_FOLDER)
repo.config_writer().set_value("user", "name", "cve2stix").release()
repo.config_writer().set_value("user", "email", "cve2stix@example.com").release()


api_key = None
if os.path.exists(CREDENTIALS_FILE_PATH):
    with open(CREDENTIALS_FILE_PATH, "r") as stream:
        try:
            data = yaml.safe_load(stream)
            api_key = data["nvd_api_key"]
        except:
            pass

if len(sys.argv) != 3:
    print("ERROR: Expected 2 args - start date and stop date")

cve_start_date = datetime.strptime(sys.argv[1], "%Y-%m-%d")
cve_end_date = datetime.strptime(sys.argv[2], "%Y-%m-%d")

start_date = cve_start_date

while start_date < cve_end_date:

    end_date = min(start_date + relativedelta(months=1), cve_end_date)

    config = Config(
        cve_start_date=start_date,
        cve_end_date=end_date,
        stix2_objects_folder=STIX2_OBJECTS_FOLDER,
        stix2_bundles_folder=STIX2_BUNDLES_FOLDER,
        api_key=api_key,
        run_mode="download",
    )

    main(config)

    repo.git.add("--all")
    count_staged_files = len(repo.index.diff("HEAD"))
    if count_staged_files != 0:
        repo.git.commit(
            "-m",
            f"Add CVEs from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
        )

        logger.info(
            "Commit: Add CVEs from %s to %s",
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
        )
    else:
        logger.info("Skipping commit, since there were no changes to add.")

    start_date = end_date

    if start_date < cve_end_date:
        time.sleep(5)

