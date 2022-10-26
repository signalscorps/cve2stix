"""
Script for bulk download of CVEs

This script downloads CVEs and commits them
into the repo

WARNING: This script does not ensure consistency of
STIX2 objects created. So ensure that "stix2_objects"
folder is empty when this script is run. This script
is intended for the first time run only.
"""

from datetime import datetime
from dateutil import rrule
from dateutil.relativedelta import relativedelta
import git
from pathlib import Path
import os
import yaml

from cve2stix.config import Config
from cve2stix.main import main

EXAMPLES_FOLDER = Path(os.path.abspath(__file__)).parent
REPO_FOLDER = EXAMPLES_FOLDER.parent
CREDENTIALS_FILE_PATH = REPO_FOLDER / "credentials.yml"

STIX2_OBJECTS_FOLDER = os.path.abspath("stix2_objects")

api_key = None
if os.path.exists(CREDENTIALS_FILE_PATH):
    with open(CREDENTIALS_FILE_PATH, "r") as stream:
        try:
            data = yaml.safe_load(stream)
            api_key = data["nvd_api_key"]
        except:
            pass

cve_start_date = datetime(1999, 1, 1)
cve_end_date = datetime(2000, 1, 1)

for start_date in rrule.rrule(
    rrule.MONTHLY,
    dtstart=cve_start_date,
    until=cve_end_date,
):

    end_date = start_date + relativedelta(months=1)

    config = Config(
        cve_backfill_start_date=start_date,
        cve_backfill_end_date=end_date,
        stix2_objects_folder=STIX2_OBJECTS_FOLDER,
        api_key=api_key,
    )

    main(config)

    repo = git.Repo(".")
    repo.git.add("--all")
    repo.git.commit(
        "-m", f"Add CVEs from {start_date} to {end_date}"
    )
