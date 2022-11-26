"""
Handles the cache, which stores
MITRE CTI GitHub repo
"""

from dataclasses import dataclass
import git
import logging
import os

from stix2 import FileSystemSource, Filter

logger = logging.getLogger(__name__)


class Enrichment:
    MITRE_CTI_GITHUB_URL = "https://github.com/mitre/cti"
    MITRE_CTI_FOLDER_NAME = "cti"

    MITRE_CAPEC_RELATIVE_PATH = "capec/2.1"
    MITRE_ENTERPRISE_RELATIVE_PATH = "enterprise-attack"
    MITRE_MOBILE_RELATIVE_PATH = "mobile-attack"
    MITRE_ICS_RELATIVE_PATH = "ics-attack"

    def __init__(self, cache_folder_path):
        self.cache_folder_path = cache_folder_path
        if not os.path.isdir(cache_folder_path):
            logger.info("Creating cache folder %s", cache_folder_path)
            os.makedirs(cache_folder_path)

        self.cti_folder_path = os.path.join(
            self.cache_folder_path, Enrichment.MITRE_CTI_FOLDER_NAME
        )

        capec_file_path = os.path.join(
            self.cti_folder_path, Enrichment.MITRE_CAPEC_RELATIVE_PATH
        )
        os.makedirs(capec_file_path, exist_ok=True)
        self.capec_fs = FileSystemSource(capec_file_path)

        enterprise_attack_file_path = os.path.join(
            self.cti_folder_path, Enrichment.MITRE_ENTERPRISE_RELATIVE_PATH
        )
        os.makedirs(enterprise_attack_file_path, exist_ok=True)
        self.enterprise_attack_fs = FileSystemSource(enterprise_attack_file_path)

        mobile_attack_file_path = os.path.join(
            self.cti_folder_path, Enrichment.MITRE_MOBILE_RELATIVE_PATH
        )
        os.makedirs(mobile_attack_file_path, exist_ok=True)
        self.mobile_attack_fs = FileSystemSource(mobile_attack_file_path)

        ics_attack_file_path = os.path.join(
            self.cti_folder_path, Enrichment.MITRE_ICS_RELATIVE_PATH
        )
        os.makedirs(ics_attack_file_path, exist_ok=True)
        self.ics_attack_fs = FileSystemSource(ics_attack_file_path)

    def get_attack_stix_object(self, attack_stix_id):
        attack_pattern = self.enterprise_attack_fs.get(attack_stix_id)
        if attack_pattern == None:
            attack_pattern = self.mobile_attack_fs.get(attack_stix_id)
        if attack_pattern == None:
            attack_pattern = self.ics_attack_fs.get(attack_stix_id)
        return attack_pattern

    def update_mitre_cti_database(self):
        if os.path.isdir(self.cti_folder_path):
            logger.info(
                "Pulling latest changes from %s", Enrichment.MITRE_CTI_GITHUB_URL
            )
            g = git.cmd.Git(self.cti_folder_path)
            g.pull()
        else:
            logger.info(
                "Cloning latest changes from %s", Enrichment.MITRE_CTI_GITHUB_URL
            )
            git.Repo.clone_from(Enrichment.MITRE_CTI_GITHUB_URL, self.cti_folder_path)

    def preprocess_cti_dataset(self):
        self.update_mitre_cti_database()

        cwe_capec_map = {}
        capec_stix_id_map = {}

        logger.info("Preprocessing CAPEC dataset...")
        capec_attack_patterns = self.capec_fs.query(
            [Filter("type", "=", "attack-pattern")]
        )

        # Map between CAPEC name and CAPEC stix id
        for capec_attack_pattern in capec_attack_patterns:
            for external_ref in capec_attack_pattern.external_references:
                if external_ref["source_name"] == "capec":
                    capec_stix_id_map[capec_attack_pattern.id] = external_ref[
                        "external_id"
                    ]
                    break

        # Fill up map between CWEs and CAPEC
        for capec_attack_pattern in capec_attack_patterns:
            for external_ref in capec_attack_pattern.external_references:
                if external_ref["source_name"] == "cwe":
                    cwe_id = external_ref["external_id"]
                    if cwe_id in cwe_capec_map:
                        cwe_capec_map[cwe_id].append(capec_attack_pattern.id)
                    else:
                        cwe_capec_map[cwe_id] = [capec_attack_pattern.id]

        logger.info("Preprocessing ATT&CK dataset...")
        capec_enterprise_attack_map = self._preprocess_attack_dataset(
            Enrichment.MITRE_ENTERPRISE_RELATIVE_PATH
        )
        capec_mobile_attack_map = self._preprocess_attack_dataset(
            Enrichment.MITRE_MOBILE_RELATIVE_PATH
        )
        capec_ics_attack_map = self._preprocess_attack_dataset(
            Enrichment.MITRE_ICS_RELATIVE_PATH
        )

        return CTIDataset(
            cwe_capec_map,
            capec_stix_id_map,
            capec_enterprise_attack_map,
            capec_mobile_attack_map,
            capec_ics_attack_map,
        )

    def _preprocess_attack_dataset(self, attack_relative_path):
        capec_attack_map = {}

        attack_file_path = os.path.join(self.cti_folder_path, attack_relative_path)
        attack_fs = FileSystemSource(attack_file_path)

        attack_patterns = attack_fs.query([Filter("type", "=", "attack-pattern")])

        for attack_pattern in attack_patterns:
            for external_ref in attack_pattern.external_references:
                if external_ref["source_name"] == "capec":
                    capec_id = external_ref["external_id"]
                    if capec_id in capec_attack_map:
                        capec_attack_map[capec_id].append(attack_pattern.id)
                    else:
                        capec_attack_map[capec_id] = [attack_pattern.id]

        return capec_attack_map

    def is_mitre_cti_database_in_cache(self):
        return os.path.isdir(self.cti_folder_path)


@dataclass
class CTIDataset:
    cwe_id_to_capec_stix_id_map: dict = None
    stix_id_to_capec_id_map: dict = None
    capec_id_to_enterprise_attack_map: dict = None
    capec_id_to_mobile_attack_map: dict = None
    capec_id_to_ics_attack_map: dict = None

    def is_capec_id_present_in_attack_dataset(self, capec_id):
        return (
            (capec_id in self.capec_id_to_enterprise_attack_map)
            or (capec_id in self.capec_id_to_mobile_attack_map)
            or (capec_id in self.capec_id_to_ics_attack_map)
        )
