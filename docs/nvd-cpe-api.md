# NVD CPE API

## CPE Overview

Common Platform Enumerations are;

> CPE is a structured naming scheme for information technology systems, software, and packages. Based upon the generic syntax for Uniform Resource Identifiers (URI), CPE includes a formal name format, a method for checking names against a system, and a description format for binding text and tests to a name.

[CPEs were originally managed by MITRE](https://cpe.mitre.org/) but ownership has since been transferred to the [US National Institute of Standard of Technology (NIST)](https://nvd.nist.gov/products/cpe).

The most important part of a CPE is the URI -- a computer readable format to describe the details of operating systems, software applications, or hardware devices. 

Here is the CPE 2.3 URI schema;

```
cpe:2.3:<part>:<vendor>:<product>:
<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw:>:<target_hw>:<other>
```

Where:

* cpe: always `cpe`
* 2.3: the cpe version (currently latest is 2.3)
* `<part>`: The part attribute SHALL have one of these three string values:
    * `a` for applications,
    * `o` for operating systems,
    * `h` for hardware devices
* `<vendor>`: described or identifies the person or organisation that manufactured or created the product
* `<product>`: describes or identifies the most common and recognisable title or name of the product
* `<version>`: vendor-specific alphanumeric strings characterising the particular release version of the product
* `<update>`: vendor-specific alphanumeric strings characterising the particular update, service pack, or point release of the product.
* `<edition>` assigned the logical value ANY (`*`) except where required for backward compatibility with version 2.2 of the CPE
specification
* `<language>`:  valid language tags as defined by [RFC5646]
* `<sw_edition>`: characterises how the product is tailored to a particular market or class
of end users.
* `<target_sw>`: characterises the software computing environment within which the product operates.
* `<target_hw>`: characterises the instruction set architecture (e.g., x86) on which the product being described or identified operates
* `<other>`:  capture any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value

Here is an example of a CPE URI (for Apple Quicktime v7.71.80.42);

```
cpe:2.3:a:apple:quicktime:7.71.80.42:*:*:*:*:*:*:*
```

Where `*` equals ANY specified or unspecified option, and `-` means unspecified.

[You can browse CPEs here](https://nvd.nist.gov/products/cpe/search). Here is the record shown in the example above: https://nvd.nist.gov/products/cpe/detail/165622

## Downloading CPEs

### NVD CPE API Overview

The NVD CPE API takes the same crenentials created to access CVEs and stored in `credentials.yml`.

There is only once CPE endpoint;

```shell
GET https://services.nvd.nist.gov/rest/json/cpes/1.0/
```

It has a range of parameters to filter the results to find products. The key ones used by cve2stix are

* `apiKey`
* `modStartDate`
* `modEndDate`
* `includeDeprecated`
* `resultsPerPage`
* `startIndex`
* `addOns`

```shell
GET https://services.nvd.nist.gov/rest/json/cpes/1.0/?apiKey=<<APIKEY>>&modStartDate=2022-01-01T00:00:00:000%20Z&modEndDate=2022-02-01T00:00:00:000%20Z&addOns=cves
```

```json
            {
                "deprecated": false,
                "cpe23Uri": "cpe:2.3:a:rusqlite_project:rusqlite:0.26.0:*:*:*:*:rust:*:*",
                "lastModifiedDate": "2022-01-03T14:59Z",
                "titles": [
                    {
                        "title": "Rusqlite Project Rusqlite 0.26.0 for Rust",
                        "lang": "en_US"
                    }
                ],
                "refs": [
                    {
                        "ref": "https://github.com/rusqlite/rusqlite/releases",
                        "type": "Version"
                    },
                    {
                        "ref": "https://github.com/rusqlite/rusqlite",
                        "type": "Project"
                    },
                    {
                        "ref": "https://crates.io/crates/rusqlite",
                        "type": "Project"
                    }
                ],
                "deprecatedBy": [],
                "vulnerabilities": [
                    "CVE-2021-45713",
                    "CVE-2021-45714",
                    "CVE-2021-45715",
                    "CVE-2021-45716",
                    "CVE-2021-45717",
                    "CVE-2021-45718",
                    "CVE-2021-45719"
                ]
            },
```

### CPE Initial Backfill

The backfill is carried out by paging through all results using `startIndex`. e.g.

Request 1;

```shell
GET https://services.nvd.nist.gov/rest/json/cpes/1.0/?apiKey=<<APIKEY>>&startIndex=0&resultsPerPage=500&addOns=cves
```

```json
{
    "resultsPerPage": 500,
    "startIndex": 0,
    "totalResults": 861412,
```

Request 2;

```shell
GET https://services.nvd.nist.gov/rest/json/cpes/1.0/?apiKey=<<APIKEY>>&startIndex=1&resultsPerPage=500&addOns=cves
```


```json
{
    "resultsPerPage": 500,
    "startIndex": 1,
    "totalResults": 861412,
```

And so on until `resultsPerPage` * (`startIndex` + 1) is >= (is greater than or equal to) `totalResults`. Note, (`startIndex` + 1) is to account for the zero rated index.

We have also designed cve2stix to be mindful of the NVD API when backfilling data.

Firstly, the NVD APIs can be unstable at times. Even more so the larger the response size, therefore cve2stix only requests 500 `resultsPerPage`.

NVD also recommend your application sleeps for several seconds between requests so that legitimate requests are not denied by the server (which implements various controls to stop abuse). cve2stix waits for 5 seconds between each request. Whilst this increase backfill time, it prevents requests failing. On a stable connection, an entire backfill can take around 3 hours `((861412/500)*5)`, where 861412 is the total number of CPE records at the time of writing.

cve2stix also allows you to pass an earlist backfill date. Generally very old CPEs are only useful to researchers because software gets version updates regularly. We recommend an intial backfill of 5 years.

It is also recognised that some organisations are stuck using legacy software. As such, cve2stix also offers a more targetted approach to backfill, allowing you to pass full or partial CPE URIs to be downloaded. For example, download specific Apple Quicktime version `cpe:2.3:a:apple:quicktime:7.71.80.42:*:*:*:*:*:*:*`. Or Download all Apple Quicktime versions `cpe:2.3:a:apple:quicktime`.

### Downloading CPE updates

MITRE add new and deprecate CPEs on a regular basis.

Once the backfill is complete, adding new or updated CPE records can be achieved using the `modStartDate` and `modEndDate` parameters where `modStartDate` equals the last update check request time and `modEndDate` equals time the request is executed. 

e.g.

```shell
GET https://services.nvd.nist.gov/rest/json/cpes/1.0/?apiKey=<<APIKEY>>&includeDeprecated=true&modStartDate=2022-01-01T00:00:00:001%20Z&modEndDate=2022-01-02T00:00:00:000%20Z&startIndex=0&resultsPerPage=500
```

Note, the parameter `includeDeprecated=true` should be also passed in this request to identify any CPEs deprecated since the last run.