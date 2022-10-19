"""
Main driver logic for cve2stix
"""

from dateutil import rrule
from dateutil.relativedelta import relativedelta
import logging
import math
import os
import requests
import time

from cve2stix.config import Config
from cve2stix.error_handling import store_error_logs_in_file
from cve2stix.helper import get_date_string_nvd_format
from cve2stix.parse_api_response import parse_cve_api_response
from cve2stix.stix_store import StixStore

logger = logging.getLogger(__name__)


def main(config: Config):

    if (
        os.path.exists(config.stix2_objects_folder) == True
        and len(os.listdir(config.stix2_objects_folder)) > 0
    ):
        logger.error(
            "%s folder is not empty. Please specify an empty folder in stix2-objects-folder field in download-settings.",
            config.stix2_objects_folder,
        )
        exit(1)

    for start_date in rrule.rrule(
        rrule.MONTHLY,
        dtstart=config.cve_backfill_start_date,
        until=config.cve_backfill_end_date,
    ):

        end_date = start_date + relativedelta(months=1)
        total_results = math.inf
        start_index = -1

        logger.info(
            "Getting CVEs from %s to %s",
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
        )

        while config.results_per_page * (start_index + 1) < total_results:

            start_index += 1

            logger.debug("Calling NVD CVE API with startIndex: %d", start_index)

            # Create CVE query and send request to NVD API
            query = {
                "apiKey": config.api_key,
                "pubStartDate": get_date_string_nvd_format(start_date),
                "pubEndDate": get_date_string_nvd_format(end_date),
                "addOns": "dictionaryCpes",
                "resultsPerPage": config.results_per_page,
                "sortOrder": "publishedDate",
                "startIndex": start_index,
            }
            response = requests.get(config.nvd_cve_api_endpoint, query)
            content = response.json()
            logger.debug(
                "Got response from NVD API with status code: %d", response.status_code
            )

            vulnerabilities = parse_cve_api_response(content)
            logger.debug(
                "Parsed %s CVEs into vulnerability stix objects", len(vulnerabilities)
            )

            total_results = content["totalResults"]

            # Store CVEs in stix store
            stix_store = StixStore()
            stix_store.store_objects_in_filestore(vulnerabilities)

            logger.info("Stored %d cves in stix2_objects folder", len(vulnerabilities))

            time.sleep(5)

    # for start_date in rrule.rrule(
    #     rrule.MONTHLY,
    #     dtstart=config.cve_backfill_start_date,
    #     until=config.cve_backfill_end_date,
    # ):

    #     end_date = start_date + relativedelta(months=1)
    #     total_results = math.inf
    #     start_index = -1

    #     logger.info(
    #         "Getting CPEs from %s to %s",
    #         start_date.strftime("%Y-%m-%d"),
    #         end_date.strftime("%Y-%m-%d"),
    #     )

    #     while config.results_per_page * (start_index + 1) < total_results:

    #         start_index += 1

    #         logger.debug("Calling NVD CPE API with startIndex: %d", start_index)

    #         # Create CVE query and send request to NVD API
    #         query = {
    #             "apiKey": config.api_key,
    #             "pubStartDate": get_date_string_nvd_format(start_date),
    #             "pubEndDate": get_date_string_nvd_format(end_date),
    #             "addOns": "cves",
    #             "resultsPerPage": config.results_per_page,
    #             "sortOrder": "publishedDate",
    #             "startIndex": start_index,
    #         }
    #         response = requests.get(config.nvd_cve_api_endpoint, query)
    #         content = response.json()
    #         logger.debug(
    #             "Got response from NVD API with status code: %d", response.status_code
    #         )

    #         vulnerabilities = parse_cve_api_response(content)
    #         logger.debug(
    #             "Parsed %s CVEs into vulnerability stix objects", len(vulnerabilities)
    #         )

    #         total_results = content["totalResults"]

    #         # Store CVEs in stix store
    #         stix_store = StixStore()
    #         stix_store.store_objects_in_filestore(vulnerabilities)

    #         logger.info("Stored %d cves in stix2_objects folder", len(vulnerabilities))

    store_error_logs_in_file()

    # CPE query
    # query = {
    #     "apiKey": config.api_key,
    #     "modStartDate": "2021-10-01T00:00:00:001 Z",
    #     "modEndDate": "2021-10-31T00:00:00:000 Z",
    #     "addOns": "cves"
    # }

    # response = requests.get(config.nvd_cve_api_endpoint, query)

    # print("Status Code:", response.status_code)

    # content = response.json()

    # print(content)
