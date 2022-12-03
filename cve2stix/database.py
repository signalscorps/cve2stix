"""
Setup SQLite3 database with peewee library.

This will be useful for storing CVEs and CPEs.
"""

from peewee import SqliteDatabase, Model, CharField
from stix2 import Software
import logging
import json

from cve2stix.cve import CVE
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
    # cpe_bundle_id = CharField()


class Inconsistency(BaseModel):
    # Intentionally haven't created ForeignKeys of the below fields
    cve_name = CharField()
    cpe23uri = CharField()


# Connect to database and create database tables
db.connect()
db.create_tables([STIX_CVE, STIX_CPE, Inconsistency])

# Database helper methods
def store_cves_in_database(
    parsed_responses: list[CVE], cpe_stix_store: StixStore
):
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
                cpe_instance = STIX_CPE.get_or_none(STIX_CPE.cpe23uri == cpe23Uri)
                if cpe_instance != None:
                    temp_cpe23Uri_ref[cpe_instance.cpe23uri] = cpe_instance.cpe_stix_id
                    parsed_response.indicator.extensions[
                        "extension-definition--b463c449-d022-48b7-b464-3e9c7ec5cf16"
                    ]["all_cpe23uris_refs"] += [cpe_instance.cpe_stix_id]

                    # Add CPE software object in CVE
                    software = cpe_stix_store.get_object_by_id(cpe_instance.cpe_stix_id)
                    if software != None:
                        parsed_response.softwares += [software]
                    else:
                        logger.error(
                            "While adding %s ref, CPE %s was not found",
                            cpe23Uri,
                            parsed_response.vulnerability.name,
                        )
                        Inconsistency.get_or_create(
                            cve_name=parsed_response.vulnerability.name,
                            cpe23uri=cpe23Uri,
                        )
                else:
                    Inconsistency.get_or_create(
                        cve_name=parsed_response.vulnerability.name, cpe23uri=cpe23Uri
                    )

            # Add vulnerable_cpe23uris_refs
            for cpe23Uri in parsed_response.indicator.extensions[
                "extension-definition--b463c449-d022-48b7-b464-3e9c7ec5cf16"
            ]["vulnerable_cpe23uris"]:
                if cpe23Uri in temp_cpe23Uri_ref:
                    parsed_response.indicator.extensions[
                        "extension-definition--b463c449-d022-48b7-b464-3e9c7ec5cf16"
                    ]["vulnerable_cpe23uris_refs"] += [temp_cpe23Uri_ref[cpe23Uri]]


def store_cpes_in_database(parsed_responses: list[Software], cve_stix_store):
    for software in parsed_responses:
        STIX_CPE.get_or_create(
            cpe23uri=software.cpe,
            defaults={
                "cpe_stix_id": software.id,
            },
        )

        software_dict = json.loads(software.serialize())

        # TODO: Add references to CVEs based on entries in Inconsistency table
        for inconsistent_pair in Inconsistency.select().where(
            Inconsistency.cpe23uri == software.cpe
        ):
            cve_name = inconsistent_pair.cve_name
            cve_stix_id = STIX_CVE.get_or_none(STIX_CVE.cve_name == cve_name)
            if cve_stix_id == None:
                # TODO: ERROR
                continue

            existing_cve = cve_stix_store.get_cve_from_bundle(cve_name)
            

        # Delete cpe from inconsistent table
        Inconsistency.delete().where(Inconsistency.cpe23uri == software.cpe).execute()
