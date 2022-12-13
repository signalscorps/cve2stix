"""
Stores the config of cve2stix tool
"""

from dataclasses import dataclass
from dateutil.relativedelta import relativedelta
from datetime import datetime, date
import logging
from pathlib import Path
import os

CVE2STIX_FOLDER = Path(os.path.abspath(__file__)).parent
REPO_FOLDER = CVE2STIX_FOLDER.parent

STIX2_OBJECTS_FOLDER = REPO_FOLDER / "stix2_objects"
STIX2_BUNDLES_FOLDER = REPO_FOLDER / "stix2_bundles"
STIX2_ENRICHMENTS_FOLDER = REPO_FOLDER / "stix2_enrichments"

logger = logging.getLogger(__name__)


@dataclass
class Config:
    type: str = "cve"
    start_date: datetime = datetime.now() - relativedelta(months=2)
    end_date: datetime = datetime.now()
    cve_run_mode: str = "download"  # or "update"
    api_key: str = ""
    stix2_objects_folder: str = ""
    stix2_bundles_folder: str = ""
    stix2_enrichments_folder: str = ""

    # Constant configs, SHOULD NOT be changed
    nvd_cve_api_endpoint: str = "https://services.nvd.nist.gov/rest/json/cves/1.0/"
    nvd_cpe_api_endpoint: str = "https://services.nvd.nist.gov/rest/json/cpes/1.0/"
    results_per_page: int = 500

    def __post_init__(self):
        # Validation for config fields

        if self.type not in ("cve", "cpe"):
            logger.error("type should be one of 'cve' or 'cpe'")
            exit(1)

        if not isinstance(self.start_date, date):
            logger.error("start-date is not in ISO format.")
            exit(1)

        if not isinstance(self.end_date, date):
            logger.error("end-date is not in ISO format.")
            exit(1)

        if self.cve_run_mode not in ("download", "update"):
            logger.error("cve-run-mode should be one of 'download' or 'update'")
            exit(1)
