"""
Helper methods for parsing results from NVD API
"""

from datetime import datetime
import json
import logging
from stix2 import Vulnerability, Indicator, Relationship, Software
from typing import List

from cve2stix.cve import CVE
from cve2stix.error_handling import error_logger
from cve2stix.enrichment import CTIDataset, Enrichment

logger = logging.getLogger(__name__)


def build_pattern_for_node(node):
    pattern = ""
    vulnerable_cpes = []
    all_cpes = []
    if len(node["children"]) > 0:
        for child in node["children"]:
            (
                child_pattern,
                child_vulnerable_cpes,
                child_all_cpes,
            ) = build_pattern_for_node(child)
            if pattern != "":
                pattern += f" {node['operator']} "
            pattern += child_pattern
            vulnerable_cpes += child_vulnerable_cpes
            all_cpes += child_all_cpes

    for cpe_match_element in node["cpe_match"]:
        all_cpes.append(cpe_match_element["cpe23Uri"])
        if cpe_match_element["vulnerable"] == True:
            vulnerable_cpes.append(cpe_match_element["cpe23Uri"])
        if pattern != "":
            pattern += f" {node['operator']} "
        pattern += f"software:cpe='{cpe_match_element['cpe23Uri']}'"

    return f"({pattern})", vulnerable_cpes, all_cpes


def _process_enrichment(
    cve_item, vulnerability, cti_dataset: CTIDataset, enrichment: "Enrichment | None"
):
    if enrichment == None:
        raise ValueError("Enrichment variable should not be None")

    enrichment_attack_patterns = []
    enrichment_relationships = []

    for problemtype_data in cve_item["cve"]["problemtype"]["problemtype_data"]:
        for problem_description in problemtype_data["description"]:
            cwe_id = problem_description["value"]
            if cwe_id not in cti_dataset.cwe_id_to_capec_stix_id_map:
                logger.debug(
                    "CWE %s in CVE %s is not found in preprocessed CTI dataset",
                    cwe_id,
                    cve_item.get("cve").get("CVE_data_meta").get("ID"),
                )
                continue

            for capec_stix_id in cti_dataset.cwe_id_to_capec_stix_id_map[cwe_id]:
                capec_attack_pattern = enrichment.capec_fs.get(capec_stix_id)
                enrichment_attack_patterns.append(capec_attack_pattern)
                enrichment_relationships.append(
                    Relationship(
                        created=vulnerability["created"],
                        created_by_ref="identity--748e6444-f073-4c50-b558-f49be8897a81",
                        modified=vulnerability["modified"],
                        relationship_type="targets",
                        source_ref=capec_attack_pattern,
                        target_ref=vulnerability,
                        external_references=[
                            {
                                "source_name": "cve2stix",
                                "description": "This object was created using cve2stix from the Signals Corps.",
                                "url": "https://github.com/signalscorps/cve2stix",
                            }
                        ],
                    )
                )

                capec_id = cti_dataset.stix_id_to_capec_id_map[capec_stix_id]
                if cti_dataset.is_capec_id_present_in_attack_dataset(capec_id):
                    attack_stix_ids = (
                        cti_dataset.capec_id_to_enterprise_attack_map.get(capec_id, [])
                        + cti_dataset.capec_id_to_mobile_attack_map.get(capec_id, [])
                        + cti_dataset.capec_id_to_ics_attack_map.get(capec_id, [])
                    )
                    for attack_stix_id in attack_stix_ids:
                        attack_pattern = enrichment.get_attack_stix_object(
                            attack_stix_id
                        )
                        enrichment_attack_patterns.append(attack_pattern)
                        enrichment_relationships.append(
                            Relationship(
                                created=vulnerability["created"],
                                created_by_ref="identity--748e6444-f073-4c50-b558-f49be8897a81",
                                modified=vulnerability["modified"],
                                relationship_type="targets",
                                source_ref=attack_pattern,
                                target_ref=vulnerability,
                                external_references=[
                                    {
                                        "source_name": "cve2stix",
                                        "description": "This object was created using cve2stix from the Signals Corps.",
                                        "url": "https://github.com/signalscorps/cve2stix",
                                    }
                                ],
                            )
                        )

    return enrichment_attack_patterns, enrichment_relationships


def parse_cve_api_response(
    cve_content, cti_dataset: "CTIDataset | None", enrichment: "Enrichment | None"
) -> List[CVE]:
    parsed_response = []
    for cve_item in cve_content["result"]["CVE_Items"]:

        try:
            vulnerability_dict = {
                "created_by_ref": "identity--748e6444-f073-4c50-b558-f49be8897a81",
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
                    "extension-definition--b2b5f2cd-49e6-4091-a0e0-c0bb71543e23": {
                        "extension_type": "property-extension",
                        "nvd_cve": cve_item["cve"],
                        "configurations": cve_item["configurations"],
                        "impact": cve_item["impact"],
                        "publishedDate": cve_item["publishedDate"],
                        "lastModifiedDate": cve_item["lastModifiedDate"],
                    }
                },
                "object_marking_refs": [
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                ],
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

            vulnerability_dict["external_references"] += [
                {
                    "source_name": "cve2stix",
                    "description": "This object was created using cve2stix from the Signals Corps.",
                    "url": "https://github.com/signalscorps/cve2stix",
                }
            ]

            indicator_dict = None
            if len(cve_item["configurations"]["nodes"]) != 0:

                indicator_dict = {
                    "created_by_ref": "identity--748e6444-f073-4c50-b558-f49be8897a81",
                    "created": datetime.strptime(
                        cve_item["publishedDate"], "%Y-%m-%dT%H:%MZ"
                    ),
                    "modified": datetime.strptime(
                        cve_item["lastModifiedDate"], "%Y-%m-%dT%H:%MZ"
                    ),
                    "indicator_types": ["compromised"],
                    "name": cve_item["cve"]["CVE_data_meta"]["ID"],
                    "description": cve_item["cve"]["description"]["description_data"][
                        0
                    ]["value"],
                    "pattern_type": "stix",
                    "valid_from": datetime.strptime(
                        cve_item["publishedDate"], "%Y-%m-%dT%H:%MZ"
                    ),
                    "external_references": [
                        {
                            "source_name": "cve2stix",
                            "description": "This object was created using cve2stix from the Signals Corps.",
                            "url": "https://github.com/signalscorps/cve2stix",
                        }
                    ],
                    "object_marking_refs": [
                        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                    ],
                }

                vulnerable_cpes = []
                all_cpes = []
                pattern_so_far = ""
                for node in cve_item["configurations"]["nodes"]:
                    (
                        temp_pattern,
                        temp_vuln_cpes,
                        temp_all_cpes,
                    ) = build_pattern_for_node(node)
                    if temp_pattern == "()":
                        continue
                    if pattern_so_far != "":
                        pattern_so_far += " OR "
                    pattern_so_far += f"{temp_pattern}"
                    vulnerable_cpes += temp_vuln_cpes
                    all_cpes += temp_all_cpes

                pattern = pattern_so_far.replace("\\", "\\\\")
                pattern = pattern.replace("\\\\'", "\\'")
                indicator_dict["pattern"] = f"[{pattern}]"
                indicator_dict["extensions"] = {
                    "extension-definition--b463c449-d022-48b7-b464-3e9c7ec5cf16": {
                        "extension_type": "property-extension",
                        "all_cpe23uris": list(set(all_cpes)),
                        "all_cpe23uris_refs": [],
                        "vulnerable_cpe23uris": list(set(vulnerable_cpes)),
                        "vulnerable_cpe23uris_refs": [],
                    }
                }

            vulnerability = Vulnerability(**vulnerability_dict)
            indicator = None
            relationship = None
            if indicator_dict != None:
                indicator = Indicator(**indicator_dict)
                relationship = Relationship(
                    created=vulnerability["created"],
                    created_by_ref="identity--748e6444-f073-4c50-b558-f49be8897a81",
                    modified=vulnerability["modified"],
                    relationship_type="identifies",
                    source_ref=indicator,
                    target_ref=vulnerability,
                    external_references=[
                        {
                            "source_name": "cve2stix",
                            "description": "This object was created using cve2stix from the Signals Corps.",
                            "url": "https://github.com/signalscorps/cve2stix",
                        }
                    ],
                )

            # Enrichments
            enrichment_attack_patterns = []
            enrichment_relationships = []
            if cti_dataset != None:
                (
                    enrichment_attack_patterns,
                    enrichment_relationships,
                ) = _process_enrichment(
                    cve_item, vulnerability, cti_dataset, enrichment
                )

            parsed_response.append(
                CVE(
                    vulnerability=vulnerability,
                    indicator=indicator,
                    identifies_relationship=relationship,
                    enrichment_attack_patterns=enrichment_attack_patterns,
                    enrichment_relationships=enrichment_relationships,
                )
            )
        except:
            raise
            logger.warning(
                "An unexpected error occurred when parsing %s",
                cve_item.get("cve").get("CVE_data_meta").get("ID"),
            )
            error_logger.warning(
                "An unexpected error occurred when parsing %s",
                cve_item.get("cve").get("CVE_data_meta").get("ID"),
            )
            if indicator_dict != None and "pattern" in indicator_dict:
                error_logger.warning(
                    "The pattern field:\n%s", indicator_dict["pattern"]
                )
            error_logger.warning("CVE item is:\n%s", json.dumps(cve_item))

    return parsed_response


def parse_cpe_api_response(cpe_content):
    parsed_response = []
    for cpe_item in cpe_content["result"]["cpes"]:

        software_dict = {
            "name": cpe_item["titles"][0]["title"],
            "cpe": cpe_item["cpe23Uri"],
            "version": cpe_item["cpe23Uri"].split(":")[5],
            "vendor": cpe_item["cpe23Uri"].split(":")[3],
            "languages": cpe_item["titles"][0]["lang"],
            # "revoked": cpe_item["deprecated"],
        }

        software = Software(**software_dict)
        parsed_response.append(software)

    return parsed_response
