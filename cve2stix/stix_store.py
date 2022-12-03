"""
Contains logic for storing parsed stix objects.
"""

import json
import os
import logging
from stix2 import FileSystemStore, Filter, Bundle, MemoryStore
from stix2.base import STIXJSONEncoder
from stix2.datastore import DataSourceError

from cve2stix.cve import CVE

logger = logging.getLogger(__name__)


def get_first_item_safely(list):
    if list != None and len(list) > 0:
        return list[0]
    return None


class StixStore:
    """
    Interface for handling storing and getting STIX objects
    """

    def __init__(self, file_store_path, bundle_path):
        if os.path.exists(file_store_path) == False:
            os.makedirs(file_store_path)
        self.file_store_path = file_store_path
        self.stix_file_store = FileSystemStore(file_store_path, allow_custom=True)

        if os.path.exists(bundle_path) == False:
            os.makedirs(bundle_path)
        self.stix_bundle_path = bundle_path

    def get_object(
        self,
        stix_object_name,
        stix_object_identity=None,
        tlp_level=None,
        confidence=None,
        extensions=None,
    ):
        """
        Query STIX2 Object based on `stix_object_name`
        """
        query = [
            Filter("name", "=", stix_object_name),
        ]

        if stix_object_identity:
            query += [Filter("created_by_ref", "=", stix_object_identity)]

        if confidence:
            query += [Filter("confidence", "=", confidence)]

        if tlp_level:
            query += [Filter("object_marking_refs", "=", tlp_level)]

        if extensions:
            query += [Filter("extensions", "=", extensions)]

        observables_found = self.stix_file_store.source.query(query)

        if observables_found == None or len(observables_found) == 0:
            return None

        return observables_found[0]

    def get_object_by_id(
        self,
        stix_object_id,
    ):
        query = [
            Filter("id", "=", stix_object_id),
        ]
        observables_found = self.stix_file_store.source.query(query)

        if observables_found == None or len(observables_found) == 0:
            return None

        return observables_found[0]

    def get_object_custom_query(
        self,
        filters,
    ):
        observables_found = self.stix_file_store.source.query(filters)

        if observables_found == None or len(observables_found) == 0:
            return None

        return observables_found[0]

    def store_objects_in_filestore(self, stix_objects):
        for stix_object in stix_objects:
            self.store_object_in_filestore(stix_object)

    def store_object_in_filestore(self, stix_object):
        if stix_object == None:
            logger.debug("Tried storing None object in store, ignoring it..")
            return
        try:
            self.stix_file_store.add(stix_object, pretty=False)
        except DataSourceError as ex:
            # Ignoring error, since it occurs when file is already
            # present in the file store, which is OK
            if hasattr(stix_object, "id"):
                logger.debug(
                    "Exception caught while storing stix object %s: %s",
                    stix_object.id,
                    ex,
                )
            else:
                logger.debug(
                    "Exception caught while storing stix object %s: %s",
                    stix_object,
                    ex,
                )

    def get_stix_bundle_cve_folder(self, cve_id):
        _, year, id = cve_id.split("-")
        block = id[:-3] + "XXX"
        return f"{self.stix_bundle_path}/{year}/{block}/{cve_id}/"

    def get_cve_from_bundle(self, cve_id):
        # TODO: Issue here
        stix_bundle_cve_folder = self.get_stix_bundle_cve_folder(cve_id)
        stix_bundle_file = f"{stix_bundle_cve_folder}/stix_bundle.json"
        if os.path.isfile(stix_bundle_file) == False:
            return None

        memory_store = MemoryStore()
        memory_store.load_from_file(stix_bundle_file)
        vulnerabilities = memory_store.query([Filter("type", "=", "vulnerability")])
        indicators = memory_store.query([Filter("type", "=", "indicator")])
        identifies_relationships = memory_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "identifies"),
            ]
        )
        enrichment_attack_patterns = memory_store.query(
            [Filter("type", "=", "attack-pattern")]
        )
        enrichment_relationships = memory_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "targets"),
            ]
        )
        softwares = memory_store.query([Filter("type", "=", "software")])

        vulnerability = get_first_item_safely(vulnerabilities)
        indicator = get_first_item_safely(indicators)
        identifies_relationship = get_first_item_safely(identifies_relationships)

        return CVE(
            vulnerability=vulnerability,
            indicator=indicator,
            identifies_relationship=identifies_relationship,
            enrichment_attack_patterns=enrichment_attack_patterns,
            enrichment_relationships=enrichment_relationships,
            softwares=softwares,
        )

    def store_cve_in_bundle(self, cve_id, stix_objects, update=False):
        # Create a bundle
        bundle_of_all_objects = Bundle(*stix_objects, allow_custom=True)

        # Create folder to store CVE
        stix_bundle_cve_folder = self.get_stix_bundle_cve_folder(cve_id)
        os.makedirs(stix_bundle_cve_folder, exist_ok=True)

        stix_bundle_file = f"{stix_bundle_cve_folder}/stix_bundle.json"
        if os.path.isfile(stix_bundle_file) and update == False:
            return False

        with open(stix_bundle_file, "w") as f:
            f.write(json.dumps(bundle_of_all_objects, cls=STIXJSONEncoder, indent=4))

        return True

    def delete_cpe_software(self, cpe_stix_id):
        # CPE Path
        cpe_software_path = os.path.join(
            self.file_store_path, "software", f"{cpe_stix_id}.json"
        )
        try:
            os.remove(cpe_software_path)
        except:
            # Silently ignore in case file is not present
            pass

    def force_update_cpe_software(self, software):
        self.delete_cpe_software(software.id)
        self.store_object_in_filestore(software)

    # def get_cpe_from_bundle(self, bundle_id: str):
    #     stix_bundle_file = f"{self.stix_bundle_path}/{bundle_id}.json"
    #     if os.path.isfile(stix_bundle_file) == False:
    #         return None

    #     memory_store = MemoryStore()
    #     memory_store.load_from_file(stix_bundle_file)
    #     softwares = memory_store.query([Filter("type", "=", "software")])

    #     return softwares[0]

    # def store_cpe_in_bundle(self, stix_objects, update=False):

    #     # Create a bundle
    #     bundle_of_all_objects = Bundle(*stix_objects)

    #     # Create folder to store CVE
    #     os.makedirs(self.stix_bundle_path, exist_ok=True)

    #     stix_bundle_file = f"{self.stix_bundle_path}/{bundle_of_all_objects.id}.json"
    #     if os.path.isfile(stix_bundle_file) and update == False:
    #         return None

    #     with open(stix_bundle_file, "w") as f:
    #         f.write(json.dumps(bundle_of_all_objects, cls=STIXJSONEncoder, indent=4))

    #     return bundle_of_all_objects.id
