# Github Actions

This repository has been built with Github actions (to populate [cve2stix-output](https://github.com/signalscorps/cve2stix-output)). This page will explain how that's setup.

## Setup Github Actions

### 1. Add API Key

Once you have your key, `NVD_API_key` as a repository variable (settings > secrets > actions) with your NVD API key as the value.

### 2. Check the Github actions

In `.github/workflows` you will find a number of files

* `download-cves.yml`: Defines workflow for downloading CVEs between two date ranges. This workflow can be triggerred manually.
* `update-cves.yml`: Defines workflow for updating CVEs between two date ranges. This is a scheduled workflow, which runs every day at 5:30 AM UTC. It can also be triggerred manually.
* `backfill-cves.yml`: Defines a workflow for downloading all CVEs from 1990-01-01 upto now. This internally triggers the `download-cves.yml` workflow for different date ranges. This workflow can be triggerred manually.
* `delete-stix2-output.yml`: Defines a workflow for delete stix2-output folder. This workflow should only be used if the stix2-output becomes inconsistent (beyond recovery).

Ignore, `docs.yml`, this file is used to generate the product docs.

#### 3. Run the Github actions

Below we describe running `download-cves.yml` workflow manually.

1. Go to GitHub Actions section and choose `download-cves` workflow.
2. Click on "Run Workflow" and provide start date and end date as input (in POSIX date format).
3. If the workflow completes successfully, then the new CVEs between the specified date ranges will be downloaded and committed into the repo.
