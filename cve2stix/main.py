"""
Main driver logic for cve2stix
"""

from datetime import datetime
import json
import requests

from cve2stix.config import Config

def main(config: Config):
    print(config.cve_backfill_start_date)

    query={
        "apiKey": config.api_key,
        "pubStartDate": "2021-10-01T00:00:00:001 Z",
        "pubEndDate": "2021-10-31T00:00:00:000 Z",
        "addOns": "dictionaryCpes",
        "resultsPerPage": 1,
        "sortOrder": "publishedDate",
        "startIndex": 0
    }

    response = requests.get(config.nvd_cve_api_endpoint, query)
    
    print("Status Code:", response.status_code)
    
    content = response.json()
    print(content)
