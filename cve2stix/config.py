"""
Stores the config of cve2stix tool
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import os

CVESTIX_FOLDER = Path(os.path.abspath(__file__)).parent
REPO_FOLDER = CVESTIX_FOLDER.parent
CREDENTIALS_FILE_PATH = REPO_FOLDER / "credentials.yml"


@dataclass
class Config:
    cve_backfill_start_date: datetime = None
    api_key: str = None

    nvd_cve_api_endpoint: str = "https://services.nvd.nist.gov/rest/json/cves/1.0/"