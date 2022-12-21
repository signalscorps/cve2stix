"""
Miscellaneous helper functions
"""

import json
from stix2 import new_version
from stix2.exceptions import InvalidValueError
import logging
import pytz

from cve2stix.cve import CVE

logger = logging.getLogger(__name__)


def get_date_string_nvd_format(date):
    return date.strftime("%Y-%m-%dT%H:%M:%S:%f")[:-3] + " UTC"


def store_new_cve(stix_store, parsed_response: CVE):
    stix_objects = (
        [
            parsed_response.vulnerability,
            parsed_response.indicator,
            parsed_response.identifies_relationship,
        ]
        + parsed_response.enrichment_attack_patterns
        + parsed_response.enrichment_relationships
        + parsed_response.softwares
    )

    status = stix_store.store_cve_in_bundle(
        parsed_response.vulnerability["name"], stix_objects
    )
    if status == False:
        return False

    stix_store.store_objects_in_filestore(stix_objects)
    return True


def update_existing_cve(existing_cve: CVE, stix_store, parsed_response):
    stix_objects = []
    try:
        vulnerability_dict = json.loads(parsed_response.vulnerability.serialize())
        vulnerability_dict.pop("type", None)
        vulnerability_dict.pop("created", None)
        vulnerability_dict.pop("id", None)
        vulnerability_dict.pop("created_by_ref", None)
        old_vulnerability = stix_store.get_object_by_id(
            existing_cve.vulnerability.id
        )
        new_vulnerability = new_version(old_vulnerability, **vulnerability_dict)
        stix_objects.append(new_vulnerability)

        if parsed_response.indicator != None:
            indicator_dict = json.loads(parsed_response.indicator.serialize())
            indicator_dict.pop("type", None)
            indicator_dict.pop("created", None)
            indicator_dict.pop("id", None)
            indicator_dict.pop("created_by_ref", None)

            old_indicator = None
            if existing_cve.indicator != None:
                old_indicator = stix_store.get_object_by_id(
                    existing_cve.indicator.id
                )

            new_indicator = parsed_response.indicator
            if old_indicator != None:
                new_indicator = new_version(old_indicator, **indicator_dict)
            stix_objects.append(new_indicator)

        if parsed_response.identifies_relationship != None:
            old_relationship = None
            if existing_cve.identifies_relationship != None:
                old_relationship = stix_store.get_object_by_id(
                    existing_cve.identifies_relationship.id
                )

            new_relationship = parsed_response.identifies_relationship
            if old_relationship != None:
                new_relationship = new_version(
                    old_relationship,
                    modified=pytz.UTC.localize(
                        parsed_response.vulnerability["modified"]
                    ),
                )
            stix_objects.append(new_relationship)

        stix_objects += parsed_response.enrichment_attack_patterns
        stix_objects += parsed_response.enrichment_relationships
        stix_objects += parsed_response.softwares

        stix_store.store_objects_in_filestore(stix_objects)
        stix_store.store_cve_in_bundle(
            parsed_response.vulnerability["name"], stix_objects, update=True
        )

    except InvalidValueError:
        logger.warning(
            "Tried updating %s, whose latest copy is already downloaded. Hence skipping it",
            parsed_response.vulnerability["name"],
        )