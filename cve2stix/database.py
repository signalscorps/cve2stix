"""
Setup SQLite3 database with peewee library.

This will be useful for storing CVEs and CPEs.
"""

from peewee import SqliteDatabase, Model, CharField
from stix2 import Software
import logging
import re
from typing import List

from cve2stix.cve import CVE
from cve2stix.error_handling import error_logger
from cve2stix.stix_store import StixStore

logger = logging.getLogger(__name__)
db = SqliteDatabase("state.db", pragmas={"foreign_keys": 1})


class BaseModel(Model):
    class Meta:
        database = db


class STIX_CVE(BaseModel):
    cve_name = CharField(unique=True)
    cve_stix_id = CharField()


class STIX_CPE(BaseModel):
    cpe23uri = CharField(unique=True)
    cpe_stix_id = CharField()


# Connect to database and create database tables
db.connect()
db.create_tables([STIX_CVE, STIX_CPE])

# Database helper methods
def store_cves_in_database(parsed_responses: List[CVE], stix_store: StixStore):
    for parsed_response in parsed_responses:
        STIX_CVE.get_or_create(
            cve_name=parsed_response.vulnerability.name,
            defaults={"cve_stix_id": parsed_response.vulnerability.id},
        )

        temp_cpe23Uri_ref = {}

        # Add CPE references
        if parsed_response.indicator != None:

            # Add all_cpe23uris_refs and references in CPE
            for cpe23Uri in parsed_response.indicator.extensions[
                "extension-definition--b463c449-d022-48b7-b464-3e9c7ec5cf16"
            ]["all_cpe23uris"]:
                regex_cpe23Uri = cpe23Uri.replace("*", ".*")

                # % is short of LIKE, which is more efficient than REGEXP
                # https://stackoverflow.com/questions/9629488/mysql-regexp-much-slow-than-like
                cpe_instances = STIX_CPE.select().where(
                    STIX_CPE.cpe23uri % regex_cpe23Uri
                )
                if cpe_instances == None or len(cpe_instances) == 0:
                    error_logger.error(
                        "While adding %s ref, CPE %s was not found in database",
                        parsed_response.vulnerability.name,
                        cpe23Uri,
                    )

                for cpe_instance in cpe_instances:
                    if cpe23Uri in temp_cpe23Uri_ref:
                        temp_cpe23Uri_ref[cpe23Uri].append(cpe_instance.cpe_stix_id)
                    else:
                        temp_cpe23Uri_ref[cpe23Uri] = [cpe_instance.cpe_stix_id]

                    parsed_response.indicator.extensions[
                        "extension-definition--b463c449-d022-48b7-b464-3e9c7ec5cf16"
                    ]["all_cpe23uris_refs"] += [cpe_instance.cpe_stix_id]

                    # Add CPE software object in CVE
                    software = stix_store.get_object_by_id(cpe_instance.cpe_stix_id)
                    if software != None:
                        parsed_response.softwares += [software]
                    else:
                        error_logger.error(
                            "While adding %s ref, CPE %s was not found in stix2_objects, even though it's present in database",
                            parsed_response.vulnerability.name,
                            cpe23Uri,
                        )

            # Add vulnerable_cpe23uris_refs
            for cpe23Uri in parsed_response.indicator.extensions[
                "extension-definition--b463c449-d022-48b7-b464-3e9c7ec5cf16"
            ]["vulnerable_cpe23uris"]:
                if cpe23Uri in temp_cpe23Uri_ref:
                    parsed_response.indicator.extensions[
                        "extension-definition--b463c449-d022-48b7-b464-3e9c7ec5cf16"
                    ]["vulnerable_cpe23uris_refs"] += temp_cpe23Uri_ref[cpe23Uri]


def store_cpes_in_database(parsed_responses: List[Software], stix_store):
    for software in parsed_responses:
        STIX_CPE.get_or_create(
            cpe23uri=software.cpe,
            defaults={
                "cpe_stix_id": software.id,
            },
        )
