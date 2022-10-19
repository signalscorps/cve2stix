# cve2stix

![](/docs/assets/img/stix-cve-graph.png)

Turn CVEs and CPEs in the National Vulnerability database into STIX 2.1 Objects.

cve2stix was designed for two use-cases;

1. to match specific software (CPEs) to new and existing vulnerabilities (CVEs) to alert when vulnerablities exist
2. to feed Threat Intelligence Platforms with rich vulnerability information for research and analysis.


Use cve2stix to:

* Automatically converting CVEs into STIX format (as Indicators and Vulnerability Objects)
	* with valid STIX patterns for matching)
* Automatically converting CPEs into STIX format

Why use cve2stix;

## Prerequisties

To use cve2stix you will need to obtain a free API key from NVD.

You can get one here: https://nvd.nist.gov/developers/start-here

Once you have your key, create a file in the root of this repository copy the `nvd-credentials.yml.schema` to a new file called `nvd-credentials.yml` and enter your API key.

## Usage

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

### A note on CVSS v3 filtering

Note, newly published CVEs will generally do not have a CVSS score assigned until they are reviewed. This means cve2stix will not download these CVEs until the analysis by NVD to assign a CVSS v3 score is complete.

Secondly, CVEs before June 2015 do not have CVSS v3 scores (when CVSS v3 was released). Therefore using CVSS v3 filtering will not return any CVEs before June 2015.

### Important note on persistance

At present, file2stix is not designed for the `download-settings.yml` to be modified. Once run once, cve2stix expects the same `download-settings.yml` file to be run.

If you want to use a different settings, create a new `download-settings.yml` file with a new name (e.g. `download-settings-new.yml`) and run that. This will assume a clean environment, and cve2stix will assume the script is running for the first time.

## Documentation

Please take a moment to review the comprehensive documentation included in this repository -- it covers almost all common questions people have about cve2stix.

[Read the documentation here](/docs/index.md).

## Support

[Signals Corps are committed to providing best effort support via Slack](https://join.slack.com/t/signalscorps-public/shared_invite/zt-1exnc12ww-9RKR6aMgO57GmHcl156DAA).

If you notice a bug or have a feature request, [please submit them as issues on Github](https://github.com/signalscorps/cve2stix/issues).

## License

[MIT LICENSE](/LICENSE).

## Useful supporting tools

* [STIX Viewer](https://github.com/traut/stixview): Quickly load bundles produced from your report.