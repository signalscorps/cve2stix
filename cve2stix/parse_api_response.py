"""
Helper methods for parsing results from NVD API
"""

from datetime import datetime
import logging
from stix2 import Vulnerability, Software

logger = logging.getLogger(__name__)


def parse_cve_api_response(cve_content):
    vulnerabilities = []
    for cve_item in cve_content["result"]["CVE_Items"]:

        try:
            vulnerability_dict = {
                "created": datetime.strptime(
                    cve_item["publishedDate"], "%Y-%m-%dT%H:%MZ"
                ),
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
                        {
                            "source_name": "cwe",
                            "external_id": problem_description["value"],
                        }
                    ]

            for reference_data in cve_item["cve"]["references"]["reference_data"]:
                vulnerability_dict["external_references"] += [
                    {
                        "source_name": reference_data["name"],
                        "url": reference_data["url"],
                    }
                ]

            vulnerability = Vulnerability(**vulnerability_dict)
            vulnerabilities.append(vulnerability)
        except:
            logger.warning(
                "An unexpected error occurred when parsing CVE %s",
                cve_item.get("cve").get("CVE_data_meta").get("ID"),
            )

    return vulnerabilities

# def parse_cpe_api_response(cpe_content):
#     softwares = []

#     for cpe_item in cpe_