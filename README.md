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

Once you have your key, create a file in the root of this repository by copying the `nvd-credentials.yml.schema` to a new file called `nvd-credentials.yml`. Enter your API key for the variable `nvd_api_key` in this file.

#### 2. Run the script

TODO

```shell
file2stix --download-settings /path/to/download-settings.yml --match-vulnerabilities
```

Where;

* `--download-settings`: Is a `download-settings.yml` that follows the schema defind in `download-settings.yml.schema`, with fields as follows
	* `--cve-id` (optional, default null): if you only want specific cves, use this flag to download the specific cve. Can be passed more than once.
	* `--cve-earliest-publish-date` (optional, default; excecution time minus 6 months): the earliest publish date for CVEs returned (in [ISO](https://www.iso.org/iso-8601-date-and-time-format.html) format). For eg., 2022-01-24
	* `--cve-latest-publish-date` (optional, default; excecution time): the latest publish date for CVEs returned (in [ISO](https://www.iso.org/iso-8601-date-and-time-format.html) format). For eg., 2022-01-24
	* `--stix2-objects-folder` (optional, default: `stix2_objects`): path to a new or empty
	folder for storing the downloaded CVEs (and CPEs). `cve2stix` will throw an error
	if the folder is not empty.
	* `--cpe-part` (optional, default; `*`): only downloads CVEs with CPE match strings that contain defined cpe part. More than one value can be passed, in which case are treated with logical OR.
	* `--cpe-vendor` (optional, default; `*`): only downloads CVEs with CPE match strings that contain defined cpe vendor. More than one value can be passed, in which case are treated with logical OR.
	* `--cpe-product` (optional, default; `*`): only downloads CVEs with CPE match strings that contain defined cpe product. More than one value can be passed, in which case are treated with logical OR.
	* `cve-cvss3-exploitabilityScore-min` (optional, default; `*`): defines the minimum cvss3.exploitabilityScore in the CVEs to be returned.
	* `cve-cvss3-impactScore-min` (optional, default; `*`): defines the minimum cvss3.impactScore in the CVEs to be returned. 
* `--match-vulnerabilities` (optional, default; false): if true, then the CPE match file will be compared to CVEs to generete alerts. If running for the second time with this flag, this will only consider CVEs with update date > last run time.

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