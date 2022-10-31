# NVD CVE API

## CVE Overview

In January 1999, the MITRE Corporation published “[Towards a Common Enumeration of Vulnerabilities](https://cve.mitre.org/docs/docs-2000/cerias.html)”.

Its aim; to identify, define, and catalog publicly disclosed cybersecurity vulnerabilities.

Very soon after this meeting, the original 321 Common Vulnerabilities and Exposures (CVE) Entries, including entries from previous years, was created and the CVE List was officially launched to the public in September 1999.

Each CVE has a unique ID. In its first iteration, 9,999 CVEs were allowed per year because CVE IDs were assigned using the format CVE-YYYY-NNNN (CVE-2001-1473). Currently, tens-of-thousands of CVEs are reported a year. To account for this explosion of CVEs, the CVE ID syntax was extended by adding one more digit to the N potion from four to five digits to CVE-YYYY-NNNNN in 2015.

The NVD is tasked with analysing each CVE once it has been published to the CVE List (MITREs list) using the reference information provided with the CVE and any publicly available information at the time of analysis to associate Reference Tags, Common Vulnerability Scoring System (CVSS) v2.0, CVSS v3.1, CWE, and CPE Applicability statements.

Once a CVE is published and NVD analysis is provided, there may also be additional maintenance or modifications made. References may be added, descriptions may be updated, or a request may be made to have a set of CVE IDs reorganised (such as one CVE ID being split into several). Furthermore, the validity of an individual CVE ID can be disputed by the vendor that can result in the CVE being revoked (e.g at the time of writing [CVE-2022-27948](https://nvd.nist.gov/vuln/detail/CVE-2022-27948) is disputed).

[The full process is described here](https://nvd.nist.gov/general/cve-process).

[You can browse the NVD CVE database here to see examples of the data the NVD team include with each CVE](https://nvd.nist.gov/vuln/search).

## NVD API Overview

The NVD CVE data can be also accessed [via their APIs](https://nvd.nist.gov/developers/products).

[To start using the NVD APIs you will need to request an API key here](https://nvd.nist.gov/developers/start-here).

Once you have your API key, you should add it to a file named `credentials.yml` at the root of this repository. You can see an example of the file schema in `credentials.yml.example`

cve2stix works two phases ([managed by GitHub actions](https://github.com/signalscorps/cve2stix/actions)):

1. an initial backfill to download CVE historic data up to time script is first run (Action: `cve-download`)
2. a regular poll for new or updated CVE data (Action: `cve-update`)

If viewing GitHub you will also see a delete action, which is generally only useful for testing -- it will delete all downloaded CVEs requiring backfill to be restarted.

## Backfill (`cve-download`)

To initially backfill data to put all current CVE records in the NVD database cve2stix pages through results using a mix of `pubStartDate` and `pubEndDate` parameters in addition to paging parameters. These map to `start-date` and `end-date` in the Github action.

Request 1 ([date of first CVE is 1st of October 1988](https://nvd.nist.gov/vuln/full-listing/1988/10))

```shell
GET https://services.nvd.nist.gov/rest/json/cves/1.0/?apiKey=<<APIKEY>>&pubStartDate=1988-10-01T00:00:00:001%20Z&pubEndDate=1988-10-31T00:00:00:000%20Z&addOns=dictionaryCpes&resultsPerPage=500&sortOrder=publishedDate&startIndex=0
```

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,

```

Until `resultsPerPage` * (`startIndex` + 1) is >= (is greater than or equal to) `totalResults`.

Note. (`startIndex` + 1) is to account for the zero rated index.

In the above example I would not paginate any further (using `startIndex=1`) because 1 * (0 + 1) = 1 which is equal to total results.

At which point I would move to the next calendar month, November 1999 (`pubStartDate=1999-11-01T00:00:00:001%20Z&pubEndDate=1999-12-01T00:00:00:000%20Z&`), and so on.

We have also designed cve2stix to be mindful of the NVD API when backfilling data.

Firstly, the NVD APIs can be unstable at times. Even more so the larger the response size, therefore cve2stix only requests 500 `resultsPerPage`.

cve2stix also backfills data on a month by month basis so that a more targeted amount of data is returned.

NVD also recommend your application sleeps for several seconds between requests so that legitimate requests are not denied by the server (which implements various controls to stop abuse). cve2stix waits for 5 seconds between each request. Whilst this increase backfill time, it prevents requests failing. On a stable connection, an entire backfill can take around 3 hours `((183475/500)*5)`, where 183475 is the total number of CVE records at the time of writing.

cve2stix also allows you to pass an earliest backfill date (using `start-date` and `end-date`). Generally very old CVEs are only useful to researchers. If you are unsure, I recommend an initial backfill of 5 years.

### Updates (`cve-update`)

NVD add new CVEs and updated CVEs to their database regularly.

Once the backfill is complete you can run cve2stix to check for CVE records that have been added or updated. Generally one request a day suffices as it appears NVD update records in batch once every working day (Mon - Fri).

For this daily check, cve2stix can use the `modStartDate` and `modEndDate` parameters where `modStartDate` is last run time, and `modEndDate` is time of request.

```shell
GET https://services.nvd.nist.gov/rest/json/cves/1.0/?apiKey=<<APIKEY>>&modStartDate=2022-04-01T00:00:00:001%20Z&modEndDate=2022-04-02T00:00:00:000%20Z&addOns=dictionaryCpes&includeMatchStringChange=true&resultsPerPage=500&startIndex=0
```

Note, this request also includes the parameter `includeMatchStringChange` to ensure CVEs with changes to match strings are also included.

Usually all new and updated results will fit on a single page (with 500 results), but you should still expect to page through pages using `startIndex`.

This API query will also capture new CVEs as even new CVEs have a `lastModifiedDate` value (which will equal `publishedDate`)