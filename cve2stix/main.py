"""
Main driver logic for cve2stix
"""

import logging
import math
import requests
import time
from dateutil.relativedelta import relativedelta

from cve2stix.config import Config
from cve2stix.database import store_cves_in_database, store_cpes_in_database
from cve2stix.enrichment import Enrichment
from cve2stix.error_handling import store_error_logs_in_file
from cve2stix.helper import (
    get_date_string_nvd_format,
    store_new_cve,
    update_existing_cve,
)
from cve2stix.parse_api_response import parse_cve_api_response, parse_cpe_api_response
from cve2stix.stix_store import StixStore

logger = logging.getLogger(__name__)


def cve_main(config: Config):

    cti_dataset = None
    enrichment = None
    if config.stix2_enrichments_folder != None:
        # Download/update mitre dataset
        enrichment = Enrichment(config.stix2_enrichments_folder)
        cti_dataset = enrichment.preprocess_cti_dataset()

    start_date = config.start_date

    # Iterate over each month seperately
    while start_date < config.end_date:

        end_date = min(start_date + relativedelta(months=1), config.end_date)

        logger.info(
            "%s CVEs from %s to %s",
            config.cve_run_mode.capitalize(),
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
        )

        total_results = math.inf
        start_index = -1
        backoff_time = 10

        while config.results_per_page * (start_index + 1) < total_results:

            start_index += 1

            logger.debug("Calling NVD CVE API with startIndex: %d", start_index)

            # Create CVE query and send request to NVD API
            query = {
                "apiKey": config.api_key,
                "addOns": "dictionaryCpes",
                "resultsPerPage": config.results_per_page,
                "sortOrder": "publishedDate",
                "startIndex": start_index * config.results_per_page,
            }

            if config.cve_run_mode == "download":
                query["pubStartDate"] = get_date_string_nvd_format(start_date)
                query["pubEndDate"] = get_date_string_nvd_format(end_date)
            else:
                query["modStartDate"] = get_date_string_nvd_format(start_date)
                query["modEndDate"] = get_date_string_nvd_format(end_date)
                query["includeMatchStringChange"] = True

            try:

                response = requests.get(config.nvd_cve_api_endpoint, query)

                if response.status_code != 200:
                    logger.warning("Got response status code %d.", response.status_code)
                    raise requests.ConnectionError

            except requests.ConnectionError as ex:
                logger.warning(
                    "Got ConnectionError. Backing off for %d seconds.", backoff_time
                )
                start_index -= 1
                time.sleep(backoff_time)
                backoff_time *= 2
                continue

            content = response.json()
            logger.info(
                "Got response from NVD API with status code: %d", response.status_code
            )

            parsed_responses = parse_cve_api_response(content, cti_dataset, enrichment)
            logger.debug(
                "Parsed %s CVEs into vulnerability stix objects", len(parsed_responses)
            )

            total_results = content["totalResults"]

            stix_store = StixStore(
                config.stix2_objects_folder, config.stix2_bundles_folder
            )

            # Store CVEs in database
            store_cves_in_database(parsed_responses, stix_store)

            total_store_count = 0
            total_update_count = 0

            # Store CVEs in stix store
            for parsed_response in parsed_responses:
                cve = stix_store.get_cve_from_bundle(parsed_response.vulnerability.name)
                if cve == None:
                    # CVE not present, so we download it
                    status = store_new_cve(
                        stix_store,
                        parsed_response,
                    )
                    if status == True:
                        total_store_count += 1
                else:
                    # CVE already present, so we update it
                    status = update_existing_cve(cve, stix_store, parsed_response)
                    if status == True:
                        total_update_count += 1

            logger.info(
                "Downloaded %d cves and updated %d cves",
                total_store_count,
                total_update_count,
            )

            if config.results_per_page * (start_index + 1) < total_results:
                time.sleep(5)

            backoff_time = 10
        start_date = end_date

        if start_date < config.end_date:
            time.sleep(5)

    store_error_logs_in_file()


def cpe_main(config: Config):

    start_date = config.start_date
    end_date = config.end_date
    total_results = math.inf
    start_index = -1
    backoff_time = 10

    logger.info(
        "Downloading CPEs from %s to %s",
        start_date.strftime("%Y-%m-%d"),
        end_date.strftime("%Y-%m-%d"),
    )

    while config.results_per_page * (start_index + 1) < total_results:

        start_index += 1

        logger.debug("Calling NVD CPE API with startIndex: %d", start_index)

        # Create CVE query and send request to NVD API
        query = {
            "apiKey": config.api_key,
            "modStartDate": get_date_string_nvd_format(start_date),
            "modEndDate": get_date_string_nvd_format(end_date),
            "addOns": "cves",
            "resultsPerPage": config.results_per_page,
            "sortOrder": "publishedDate",
            "startIndex": start_index * config.results_per_page,
        }

        try:

            response = requests.get(config.nvd_cpe_api_endpoint, query)

            if response.status_code != 200:
                logger.warning("Got response status code %d.", response.status_code)
                raise requests.ConnectionError

        except requests.ConnectionError as ex:
            logger.warning(
                "Got ConnectionError. Backing off for %d seconds.", backoff_time
            )
            start_index -= 1
            time.sleep(backoff_time)
            backoff_time *= 2
            continue

        content = response.json()
        logger.debug(
            "Got response from NVD API with status code: %d", response.status_code
        )

        parsed_responses = parse_cpe_api_response(content)
        logger.debug(
            "Parsed %s CVEs into vulnerability stix objects", len(parsed_responses)
        )

        total_results = content["totalResults"]

        stix_store = StixStore(
            config.stix2_objects_folder, config.stix2_bundles_folder
        )
        # Store CPEs in database
        store_cpes_in_database(parsed_responses, stix_store)

        total_store_count = 0

        # Store CPEs in stix store
        for software in parsed_responses:
            # CVE not present, so we download it
            stix_store.force_update_cpe_software(software)
            total_store_count += 1

        logger.info(
            "Downloaded %d cpes",
            total_store_count,
        )

        if config.results_per_page * (start_index + 1) < total_results:
            time.sleep(5)

        backoff_time = 10

    store_error_logs_in_file()


def main(config: Config):
    if config.type == "cve":
        cve_main(config)
    elif config.type == "cpe":
        cpe_main(config)
