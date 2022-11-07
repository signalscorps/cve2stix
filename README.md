# cve2stix

![](/docs/assets/img/stix-cve-graph.png)

Turn CVEs enriched by the National Vulnerability database into STIX 2.1 Objects.

## cve2stix-output (avoid having to use this script)

This repository has a number of Github actions that run daily to populate [cve2stix-output](https://github.com/signalscorps/cve2stix-output) with historical CVE data (updated daily).

## Prerequisties

To use cve2stix you will need to obtain a free API key from NVD.

[You can get one here](https://nvd.nist.gov/developers/start-here).

## Usage

This repository has been built with Github actions (to populate [cve2stix-output](https://github.com/signalscorps/cve2stix-output)). If you want to understand how this works, [please read the documentation here](/docs/github-actions).

To run the script locally;

### Run locally

This script can be downloaded and run locally as follows;

#### 1. Add API Key

Once you have your key, create a file in the root of this repository by copying the `nvd-credentials.yml.schema` to a new file called `credentials.yml`. Enter your API key for the variable `nvd_api_key` in this file.

#### 2. Run the script

```shell
cve2stix --settings cve-settings.yml
```

Where;

* `--settings`: Path to YML file with settings for downloading (updating) cve2stix tool.

The YML settings file has the following fields
* `earliest-cve-date`: The datetime from which CVEs are downloaded (updated)
* `latest-cve-date`: The datetime upto which CVEs are downloaded (updated)
* `run-mode`: Possible value "download" or "update", denoting if new CVEs are to be downloaded or existing CVEs need to be updated.
* `stix2-objects-folder`: Folder where stix2 objects will be stored.
* `stix2-bundles-folder`: Folder where stix2 bundles are stored, grouped by CVE year and ID.

## Documentation

Please take a moment to review the comprehensive documentation included in this repository -- it covers almost all common questions people have about cve2stix.

[Read the documentation here](https://signalscorps.github.io/cve2stix/).

## Support

[Signals Corps are committed to providing best effort support via Slack](https://join.slack.com/t/signalscorps-public/shared_invite/zt-1exnc12ww-9RKR6aMgO57GmHcl156DAA).

If you notice a bug or have a feature request, [please submit them as issues on Github](https://github.com/signalscorps/cve2stix/issues).

## License

[MIT LICENSE](/LICENSE).

## Useful supporting tools

* [STIX Viewer](https://github.com/traut/stixview): Quickly load bundles produced from your report.
