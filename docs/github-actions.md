# Github Actions

This repository has been built with Github actions (to populate [cve2stix-output](https://github.com/signalscorps/cve2stix-output)). This page will explain how that's setup.

## Setup Github Actions for CPEs

### 1. Add API Key

Once you have your key, `NVD_API_key` as a repository variable (settings > secrets > actions) with your NVD API key as the value.

### 2. Decide how to run

There are generally two types of use-case for running the configored Github actions;

* automated
* manual

### 2.1. Automated

This is the typical way the script it used (and how cve2stix-output works). It is designed to backfill all historic CVEs and run every day to check for new CVEs and/or CVE updates.

In `https://github.com/signalscorps/cve2stix-output/.github/workflows` you will find a number of files that define this flow.

* `download-cves.yml`: Defines workflow for downloading CVEs between two date ranges. This workflow can be triggered manually if needed.
* `update-cves.yml`: Defines workflow for updating CVEs between two date ranges. This is a scheduled workflow, which runs every day (24 hours) at 5:30 AM UTC (this is time defined in the workflow .yml). This workflow can be triggered manually if needed.
* `backfill-cves.yml`: Defines a workflow for downloading all CVEs from 1990-01-01 upto now. This internally triggers the `download-cves.yml` workflow for different date ranges (essentially iterating through all years until today to backfill data). This workflow can be triggered manually if needed.
* `delete-stix2-output.yml`: Defines a workflow for delete stix2-output folder. This workflow should only be used if the stix2-output becomes inconsistent (beyond recovery).

Ignore, `docs.yml`, this file is used to generate the product docs.

#### 2.2. Manual

You can also download specific CVEs (using a date range) manually. This is better if you don't have access the the historic CVEs (e.g. cve2stix-output) and want to quickly grab some CVEs for the daterange.

This is achieved running `https://github.com/signalscorps/cve2stix-output/.github/workflows/download-cves.yml` workflow manually.

![](/docs/assets/img/github-actions-run-cve-download.png)

1. Go to GitHub Actions section and choose `download-cves` workflow.
2. Click on "Run Workflow" and provide start date and end date as input (in POSIX date format).
3. If the workflow completes successfully, then the new CVEs between the specified date ranges will be downloaded and committed into the repo.

## Setup Github Actions for CVEs

### 1. Add API Key

Once you have your key, `NVD_API_key` as a repository variable (settings > secrets > actions) with your NVD API key as the value.

### 2. Decide how to run

There are generally two types of use-case for running the configored Github actions;

* automated
* manual

### 2.1. Automated

This is the typical way the script it used (and how cpe2stix-output works). It is designed to backfill all historic CPEs and run every day to check for new CPEs and/or CPE updates.

In `https://github.com/signalscorps/cpe2stix-output/.github/workflows` you will find a number of files that define this flow.

* `download-cpes.yml`: Defines workflow for downloading (and updating) CPEs between two date ranges. This workflow can be triggered manually if needed.
* `backfill-cpes.yml`: Defines a workflow for downloading all CPEs from 1990-01-01 upto now. This internally triggers the `download-cpes.yml` workflow for different date ranges (essentially iterating through all years until today to backfill data). This workflow can be triggered manually if needed.
* `delete-stix2-output.yml`: Defines a workflow for delete stix2-output folder. This workflow should only be used if the stix2-output becomes inconsistent (beyond recovery).

Ignore, `docs.yml`, this file is used to generate the product docs.

#### 2.2. Manual

You can also download specific CPEs (using a date range) manually. This is better if you don't have access the the historic CPEs (e.g. cpe2stix-output) and want to quickly grab some CPEs for the daterange.

This is achieved running `https://github.com/signalscorps/cpe2stix-output/.github/workflows/download-cpes.yml` workflow manually.

1. Go to GitHub Actions section and choose `download-cpes` workflow.
2. Click on "Run Workflow" and provide start date and end date as input (in POSIX date format).
3. If the workflow completes successfully, then the new CPEs between the specified date ranges will be downloaded and committed into the repo.