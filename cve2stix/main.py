"""
Main driver logic for cve2stix
"""

from datetime import datetime
import re
import requests
from stix2 import Vulnerability

from cve2stix.config import Config


def parse_cve_api_response(cve_content):
    for cve_item in cve_content["result"]["CVE_Items"]:

        vulnerability_dict = {
            "created": datetime.strptime(cve_item["publishedDate"], "%Y-%m-%dT%H:%MZ"),
            "modified": datetime.strptime(
                cve_item["lastModifiedDate"], "%Y-%m-%dT%H:%MZ"
            ),
            "name": cve_item["cve"]["CVE_data_meta"]["ID"],
            "description": cve_item["cve"]["description"]["description_data"][0][
                "value"
            ],
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve_item["cve"]["CVE_data_meta"]["ID"],
                }
            ],
            "extensions": {
                "extension-definition--b76208eb-b943-4705-9fab-fffec50d030d": {
                    "extension_type": "property-extension",
                    "cve": cve_item["cve"],
                }
            },
        }

        for problemtype_data in cve_item["cve"]["problemtype"]["problemtype_data"]:
            for problem_description in problemtype_data["description"]:
                vulnerability_dict["external_references"] += [
                    {"source_name": "cwe", "external_id": problem_description["value"]}
                ]

        for reference_data in cve_item["cve"]["references"]["reference_data"]:
            vulnerability_dict["external_references"] += [
                {
                    "source_name": reference_data["name"],
                    # "source": reference_data["refsource"],
                    "url": reference_data["url"],
                    # "tags": reference_data["tags"],
                }
            ]

        vulnerability = Vulnerability(**vulnerability_dict)
        print(vulnerability)


def main(config: Config):
    print(config.cve_backfill_start_date)

    query = {
        "apiKey": config.api_key,
        "pubStartDate": "2021-10-01T00:00:00:001 Z",
        "pubEndDate": "2021-10-31T00:00:00:000 Z",
        "addOns": "dictionaryCpes",
        "resultsPerPage": 10,
        "sortOrder": "publishedDate",
        "startIndex": 0,
    }

    response = requests.get(config.nvd_cve_api_endpoint, query)

    print("Status Code:", response.status_code)

    content = response.json()

    parse_cve_api_response(content)
