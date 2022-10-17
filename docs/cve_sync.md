# CVE Sync

## CVE Overview

In January 1999, the MITRE Corporation published “[Towards a Common Enumeration of Vulnerabilities](https://cve.mitre.org/docs/docs-2000/cerias.html)”.

Its aim; to identify, define, and catalog publicly disclosed cybersecurity vulnerabilities.

Very soon after this meeting, the original 321 Common Vulnerabilities and Exposures (CVE) Entries, including entries from previous years, was created and the CVE List was officially launched to the public in September 1999.

Each CVE has a unique ID. In its first iteration, 9,999 CVEs were allowed per year because CVE IDs were assigned using the format CVE-YYYY-NNNN (CVE-2001-1473). Currently, tens-of-thousands of CVEs are reported a year. To account for this explosion of CVEs, the CVE ID syntax was extended by adding one more digit to the N potion from four to five digits to CVE-YYYY-NNNNN in 2015.

The NVD is tasked with analysing each CVE once it has been published to the CVE List (MITREs list) using the reference information provided with the CVE and any publicly available information at the time of analysis to associate Reference Tags, Common Vulnerability Scoring System (CVSS) v2.0, CVSS v3.1, CWE, and CPE Applicability statements.

Once a CVE is published and NVD analysis is provided, there may also be additional maintenance or modifications made. References may be added, descriptions may be updated, or a request may be made to have a set of CVE IDs reorganised (such as one CVE ID being split into several). Furthermore, the validity of an individual CVE ID can be disputed by the vendor that can result in the CVE being revoked (e.g at the time of writing [CVE-2022-27948](https://nvd.nist.gov/vuln/detail/CVE-2022-27948) is disputed).

[The full process is described here](https://nvd.nist.gov/general/cve-process).

[You can browse the NVD CVE database here to see examples of the data the NVD team include with each CVE](https://nvd.nist.gov/vuln/search).

## Downloading CPEs

### NVD API Overview

The NVD CPE data can be also accessed [via their APIs](https://nvd.nist.gov/developers/products).

[To start using the NVD APIs you will need to request an API key here](https://nvd.nist.gov/developers/start-here).

Once you have your API key, you should add it to a file named `credentials.yml` at the root of this repository. You can see an example of the file schema in `credentials.yml.example`

### CPE Initial Backfill

To initially backfill data to put all current CVE records in the NVD database cve2stix pages through results using a mix of `pubStartDate` and `pubEndDate` parameters in addition to paging parameters.

My recommendation is to ingest data on a month by month basis like so;

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

In the above example I would not paginate any further (using `startIndex=1`)because 1 * (0 + 1) = 1 which is equal to total results.

At which point I would move to the next calendar month, November 1999 (`pubStartDate=1999-11-01T00:00:00:001%20Z&pubEndDate=1999-12-01T00:00:00:000%20Z&`), and so on.

We have also designed cve2stix to be mindful of the NVD API when backfilling data.

Firstly, the NVD APIs can be unstable at times. Even more so the larger the response size, therefore cve2stix only requests 500 `resultsPerPage`.

cve2stix also backfills data on a month by month basis so that a more targetted amount of data is returned.

NVD also recommend your application sleeps for several seconds between requests so that legitimate requests are not denied by the server (which implements various controls to stop abuse). cve2stix waits for 5 seconds between each request. Whilst this increase backfill time, it prevents requests failing. On a stable connection, an entire backfill can take around 3 hours `((183475/500)*5)`, where 183475 is the total number of CVE records at the time of writing.

cve2stix also allows you to pass an earlist backfill date. Generally very old CVEs are only useful to researchers. If you are unsure, I recommend an intial backfill of 5 years.

It is also recognised that some organisations are stuck using legacy software. As such, cve2stix also offers a more targetted approach to backfill, allowing you to pass full or partial CPE URIs to be downloaded. For example, download all CVEs related to specific Apple Quicktime version `cpe:2.3:a:apple:quicktime:7.71.80.42:*:*:*:*:*:*:*`. Or Download all Apple Quicktime versions `cpe:2.3:a:apple:quicktime`. This option uses the CVE API parameter `cpeMatchString`.

### Downloading CPE updates

MITRE add new and deprecate CPEs on a regular basis.

Once the backfill is complete you can run cve2stix to check for CVE records that have been added or updated. Genrerally one request a day suffices as it appears NVD update records in batch once every working day (Mon - Fri).

For this daily check, cve2stix can use the `modStartDate` and `modEndDate` parameters where `modStartDate` is last run time, and `modEndDate` is time of request.

```shell
GET https://services.nvd.nist.gov/rest/json/cves/1.0/?apiKey=<<APIKEY>>&modStartDate=2022-04-01T00:00:00:001%20Z&modEndDate=2022-04-02T00:00:00:000%20Z&addOns=dictionaryCpes&includeMatchStringChange=true&resultsPerPage=500&startIndex=0
```

Note, this request also includes the parameter `includeMatchStringChange` to ensure CVEs with changes to match strings are also included.

Usually all new and updated results will fit on a single page (with 500 results), but you should still expect to page through pages using `startIndex`.

This API query will also capture new CVEs as even new CVEs have a `lastModifiedDate` value (which will equal `publishedDate`)

## Modelling CVEs as STIX Objects

### CVEs as STIX 2.1 Vulnerability Objects

STIX 2.1 contains a Vulnerability SDO, [here is the specification for it](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_q5ytzmajn6re).

Below you can see the fields from the CVE API Response that are mapped to the Vulnerability Object Properties;

```json
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--<GENERATED BY STIX2 LIBRARY>",
      "created": "<CVE_Items.publishedDate>",
      "created_by_ref": "identity--<IDENTITY ID>",
      "modified": "<CVE_Items.lastModifiedDate>",
      "name": "<CVE_Items.cve.CVE_data_meta.ID>",
      "description": "<CVE_Items.cve.description.description_data.value>",
      "object_marking_refs": [
          "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
      ],
      "external_references": [
        {
          "source_name": "cve",
          "external_id": "<CVE_Items.cve.CVE_data_meta.ID>"
        },
        {
          "source_name": "cwe",
          "external_id": "<CVE_Items.cve.problemtype.problemtype_data.description.value[n]>"
        },
        { 
          "source_name": "<CVE_Items.cve.references.reference_data.name.[n]>",
          "url": "<CVE_Items.references.reference_data.url.[n]>",
        },
      ],
      "extensions": {
        "extension-definition--b76208eb-b943-4705-9fab-fffec50d030d": {
            "extension_type": "property-extension",
            "PRINTED JSON CVE FIELDS"
        }
      }
   }
```

As an example using CVE-2022-33678;

```json
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--52b24543-6731-47f0-bbff-2a66d8423e9e",
      "created_by_ref": "identity--<IDENTITY ID>",
      "created": "2022-07-12T23:15Z",
      "modified": "2022-08-30T22:43Z",
      "name": "CVE-2022-33678",
      "description": "Azure Site Recovery Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-33676.",
      "object_marking_refs": [
          "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
      ],
      "external_references": [
        {
          "source_name": "cve",
          "external_id": "CVE-2022-33678"
        },
        {
          "source_name": "cwe",
          "external_id": "NVD-CWE-noinfo"
        },
        { 
          "source_name": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2022-33678",
          "source": "MISC",
          "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2022-33678",
          "tags": [
              "Patch",
              "Vendor Advisory"
          ]
        },
      ],
      "extensions": {
        "extension-definition--b76208eb-b943-4705-9fab-fffec50d030d": {
            "extension_type": "property-extension",
			"cve": {
                    "data_type": "CVE",
                    "data_format": "MITRE",
                    "data_version": "4.0",
                    "CVE_data_meta": {
                        "ID": "CVE-2022-33678",
                        "ASSIGNER": "secure@microsoft.com"
                    },
                    "problemtype": {
                        "problemtype_data": [
                            {
                                "description": [
                                    {
                                        "lang": "en",
                                        "value": "NVD-CWE-noinfo"
                                    }
                                ]
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2022-33678",
                                "name": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2022-33678",
                                "refsource": "MISC",
                                "tags": [
                                    "Patch",
                                    "Vendor Advisory"
                                ]
                            }
                        ]
                    },
                    "description": {
                        "description_data": [
                            {
                                "lang": "en",
                                "value": "Azure Site Recovery Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-33676."
                            }
                        ]
                    }
                },
                "configurations": {
                    "CVE_data_version": "4.0",
                    "nodes": [
                        {
                            "operator": "OR",
                            "children": [],
                            "cpe_match": [
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:microsoft:azure_site_recovery:*:*:*:*:vmware_to_azure:*:*:*",
                                    "versionEndExcluding": "9.49.6395.1",
                                    "cpe_name": []
                                }
                            ]
                        }
                    ]
                },
                "impact": {
                    "baseMetricV3": {
                        "cvssV3": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "HIGH",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "availabilityImpact": "HIGH",
                            "baseScore": 7.2,
                            "baseSeverity": "HIGH"
                        },
                        "exploitabilityScore": 1.2,
                        "impactScore": 5.9
                    },
                    "baseMetricV2": {
                        "cvssV2": {
                            "version": "2.0",
                            "vectorString": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                            "accessVector": "NETWORK",
                            "accessComplexity": "LOW",
                            "authentication": "SINGLE",
                            "confidentialityImpact": "PARTIAL",
                            "integrityImpact": "PARTIAL",
                            "availabilityImpact": "PARTIAL",
                            "baseScore": 6.5
                        },
                        "severity": "MEDIUM",
                        "exploitabilityScore": 8.0,
                        "impactScore": 6.4,
                        "acInsufInfo": false,
                        "obtainAllPrivilege": false,
                        "obtainUserPrivilege": false,
                        "obtainOtherPrivilege": false,
                        "userInteractionRequired": false
                    }
                },
                "publishedDate": "2022-07-12T23:15Z",
                "lastModifiedDate": "2022-08-30T22:43Z"
            }
            }
            }
        ]
        }
      }
   }
```

### CVEs as STIX 2.1 Indicator Objects (and STIX Pattern Creation)

The `configurations` section in the CVE API response is the critical part of the CVE for matching to a users software.

These `configurations` are indicators of potential malicious activities. Whilst we include the raw CPE `configurations` data in the Vulnerability Object, to better represent this data cve2stix also uses the [STIX 2.1 Indicator SDO](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633).

STIX 2.1 Indicator Objects contain [STIX Patterns](/blog/2022/oasis-stix-2_1-103-patterns) that can be used to describe the CPE configuration logic defined in the CVE.

The STIX 2.1 Specification contains a Software SCO (CPEs) that can be used to construct these patterns, [here is the specification for it](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070740).

One Indicator Object exists for a CVE.

The actual node CPE data is captured in the `cpe_match.cpe23Uri` under either `nodes.cpe_match` or `nodes.children.cpe_match`. Each of these has its `operator` value. Both pieces of data determine how the STIX Pattern is written inside the Indicator SDO.

All `children` patterns and wrapped in parenthesis. Operators define how multiple `cpe23Uri`s are considered.

The general structure of the indicator object takes the form;

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created": "<CVE_Items.publishedDate>",
    "created_by_ref": "identity--<IDENTITY ID>",
    "modified": "<CVE_Items.lastModifiedDate>",
    "indicator_types": ["compromised"],
    "name": "<CVE_Items.cve.CVE_data_meta.ID>",
    "description": "<CVE_Items.cve.description.description_data.value>",
    "pattern": "[<CPE MATCH PATTERN>]",
    "pattern_type": "stix",
    "valid_from": "<CVE_Items.publishedDate>",
    "object_refs": [
    	"<SOFTWATE OBJECTS IDs Reference in pattern>"
    ],
    "extensions": {
      "extension-definition--b76208eb-b943-4705-9fab-fffec50d030d": {
          "extension_type": "property-extension",
          "vulnerable_cpeid": ["<VULNERABLE CPEs>"],
          "vulnerable_object_refs": ["<VULNERABLE CPEs AS OBJECT IDs>"]
      }
    }
  }
```

Each object in the pattern is also reprensted by a CPE. So CPEURIs that match CPEs created by cve2stix are listed under the `object_refs` property.

To create the `<CPE MATCH PATTERN>` and `<VULNERABLE CPEs>` let me demonstrate with some examples.

### Simple Relationships

CVE-2022-29098 offers a good example of simple relationships: https://nvd.nist.gov/vuln/detail/CVE-2022-29098

```json
"nodes": [
                        {
                            "operator": "OR",
                            "children": [],
                            "cpe_match": [
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2022-06-27T18:02Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2022-06-27T18:02Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2022-06-27T18:02Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2022-06-27T18:02Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2022-06-27T18:02Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2022-06-27T18:02Z"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
```

Note the top operator is `OR` and there are 5 `cpe_match` nodes inside it. All `cpe23Uri` are `"vulnerable": true`. There are no `children`.

Therefore the STIX `pattern` takes the structure;

```
[ (software.cpe='nodes.cpe_match[0].cpe23Uri' OR software.cpe='nodes.cpe_match[1].cpe23Uri' OR software.cpe='nodes.cpe_match[2].cpe23Uri' OR software.cpe='nodes.cpe_match[3].cpe23Uri' OR software.cpe='nodes.cpe_match[4].cpe23Uri') ]
```

Which printed inside the full indicator using the fields from the CVE gives;

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--aa0d8806-9ccf-4a9c-ab63-1063d188d55d",
    "created": "2022-06-01T15:15:00.000Z",
    "created_by_ref": "identity--<IDENTITY ID>",
    "modified": "2022-06-08T19:14:00.000Z",
    "indicator_types": ["compromised"],
    "name": "dell powerscale_onefs 9.0.0",
    "description": "Dell PowerScale OneFS versions 8.2.0.x through 9.3.0.x, contain a weak password requirement vulnerability. An administrator may create an account with no password. A remote attacker may potentially exploit this leading to a user account compromise",
    "pattern": "[software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*']",
    "pattern_type": "stix",
    "valid_from": "2022-06-01T15:15:00.000Z",
    "object_refs": [
    	"software--51aa29f1-9f74-41f1-a0ef-f2f58ef6acd2",
    	"software--5ac7347b-062c-45f0-af4e-7b33fe3d4c1a",
    	"software--c02b98ba-e120-441a-bafe-a7cadb0e0f73",
    	"software--bf34ffc4-37f6-43cf-b9dd-f772c72d4ab3",
    	"software--09daf266-c46b-45b5-8d30-5aaf153e43b3",
    	"software--5f038772-836c-4544-96ca-81ee225f4ee6"
    ],
    "extensions": {
      "extension-definition--b76208eb-b943-4705-9fab-fffec50d030d": {
          "extension_type": "property-extension",
          "vulnerable_cpeid": [
          	"cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
          	"cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*",
          	"cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*",
          	"cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*",
          	"cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*",
          	"cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*"
          ],
        "vulnerable_object_refs": [
            "software--51aa29f1-9f74-41f1-a0ef-f2f58ef6acd2",
            "software--5ac7347b-062c-45f0-af4e-7b33fe3d4c1a",
            "software--c02b98ba-e120-441a-bafe-a7cadb0e0f73",
            "software--bf34ffc4-37f6-43cf-b9dd-f772c72d4ab3",
            "software--09daf266-c46b-45b5-8d30-5aaf153e43b3",
            "software--5f038772-836c-4544-96ca-81ee225f4ee6"
        ],
      }
    }
  }
```

### Running On/With Relationships

Let me demonstrate how more complex Relationships are modelled using the example CVE-2022-27948: https://nvd.nist.gov/vuln/detail/CVE-2022-27948

```json
			"configurations": {
                    "CVE_data_version": "4.0",
                    "nodes": [
                        {
                            "operator": "AND",
                            "children": [
                                {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [
                                        {
                                            "vulnerable": true,
                                            "cpe23Uri": "cpe:2.3:o:tesla:model_s_firmware:*:*:*:*:*:*:*:*",
                                            "versionEndIncluding": "2022-03-26",
                                            "cpe_name": []
                                        },
                                        {
                                            "vulnerable": true,
                                            "cpe23Uri": "cpe:2.3:o:tesla:model_x_firmware:*:*:*:*:*:*:*:*",
                                            "versionEndIncluding": "2022-03-26",
                                            "cpe_name": [
                                                {
                                                    "cpe23Uri": "cpe:2.3:o:tesla:model_x_firmware:-:*:*:*:*:*:*:*",
                                                    "lastModifiedDate": "2021-06-30T18:26Z"
                                                },
                                                {
                                                    "cpe23Uri": "cpe:2.3:o:tesla:model_x_firmware:2020-11-23:*:*:*:*:*:*:*",
                                                    "lastModifiedDate": "2021-06-30T18:26Z"
                                                }
                                            ]
                                        },
                                        {
                                            "vulnerable": true,
                                            "cpe23Uri": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
                                            "versionEndIncluding": "2022-03-26",
                                            "cpe_name": [
                                                {
                                                    "cpe23Uri": "cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*",
                                                    "lastModifiedDate": "2020-08-26T22:42Z"
                                                }
                                            ]
                                        }
                                    ]
                                },
                                {
                                    "operator": "OR",
                                    "children": [],
                                    "cpe_match": [
                                        {
                                            "vulnerable": false,
                                            "cpe23Uri": "cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*",
                                            "cpe_name": [
                                                {
                                                    "cpe23Uri": "cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*",
                                                    "lastModifiedDate": "2020-08-26T22:42Z"
                                                }
                                            ]
                                        },
                                        {
                                            "vulnerable": false,
                                            "cpe23Uri": "cpe:2.3:h:tesla:model_x:-:*:*:*:*:*:*:*",
                                            "cpe_name": [
                                                {
                                                    "cpe23Uri": "cpe:2.3:h:tesla:model_x:-:*:*:*:*:*:*:*",
                                                    "lastModifiedDate": "2021-08-17T17:09Z"
                                                }
                                            ]
                                        },
                                        {
                                            "vulnerable": false,
                                            "cpe23Uri": "cpe:2.3:h:tesla:model_s:-:*:*:*:*:*:*:*",
                                            "cpe_name": []
                                        }
                                    ]
                                }
                            ],
                            "cpe_match": []
                        }
                    ]
                },
```

Note the top operator is `AND` and the `children` operators are `OR`. In this case, we get a pattern like so;

```
[ ((software.cpe='nodes.children[0].cpe_match[0].cpe23Uri' OR software.cpe='nodes.children[0].cpe_match[1].cpe23Uri' OR software.cpe='nodes.children[0].cpe_match[2].cpe23Uri') AND (software.cpe='nodes.children[1].cpe_match[0].cpe23Uri' OR software.cpe='nodes.children[1].cpe_match[1].cpe23Uri' OR software.cpe='nodes.children[1].cpe_match[2].cpe23Uri')) ]
```
Note how the 2 children nodes get wrapped in parenthesis `()`.

Also note how in `software.cpe='nodes.children[1]` all `cpe23Uri`s are `"vulnerable": false` which gives an Indicator SDO with properties;

```json
    "pattern": "[ (software.cpe='cpe:2.3:o:tesla:model_s_firmware:*:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:o:tesla:model_x_firmware:*:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*') AND (software.cpe='cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:h:tesla:model_x:-:*:*:*:*:*:*:*' OR software.cpe='cpe:2.3:h:tesla:model_s:-:*:*:*:*:*:*:*') ]",
    "pattern_type": "stix",
    "valid_from": "2022-06-01T15:15:00.000Z",
    "extensions": {
      "extension-definition--b76208eb-b943-4705-9fab-fffec50d030d": {
          "extension_type": "property-extension",
          "vulnerable_cpeid": [
            "cpe:2.3:o:tesla:model_s_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:tesla:model_x_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*"
        ],
          "vulnerable_object_refs": [
            "software--09daf266-c46b-45b5-8d30-5aaf153e43b3",
            "software--0cd54a2a-b0b3-4b12-87ba-a5d0661ebe4e",
            "software--c6099362-e5c8-455b-be91-0762ffd9c08d"
        ]
      }
```

### Advanced Relationships

I will use CVE-2019-18939 to demonstrate another more complex `configuration`: https://nvd.nist.gov/vuln/detail/CVE-2019-18939

```json
 "configurations": {
                    "CVE_data_version": "4.0",
                    "nodes": [
                        {
                            "operator": "AND",
                            "children": [],
                            "cpe_match": [
                                {
                                    "vulnerable": false,
                                    "cpe23Uri": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T16:04Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T19:19Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T19:19Z"
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "operator": "AND",
                            "children": [],
                            "cpe_match": [
                                {
                                    "vulnerable": false,
                                    "cpe23Uri": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T16:04Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T19:31Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T19:19Z"
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "operator": "AND",
                            "children": [],
                            "cpe_match": [
                                {
                                    "vulnerable": false,
                                    "cpe23Uri": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T16:04Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T19:31Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T19:19Z"
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "operator": "AND",
                            "children": [],
                            "cpe_match": [
                                {
                                    "vulnerable": false,
                                    "cpe23Uri": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T16:04Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T19:19Z"
                                        }
                                    ]
                                },
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                    "cpe_name": [
                                        {
                                            "cpe23Uri": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                            "lastModifiedDate": "2020-04-10T19:19Z"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
```

Note there are 4 top operators all with the `AND` operator and each with 1 `cpe_match` node inside them. Each CPE match are 3 `cpe23Uri`. Note, each `cpe_match` is implicitly joined by an `OR` statement. Which gives a pattern structure like so

```
[ ((software.cpe='nodes.cpe_match[0].cpe23Uri[0] AND software.cpe='nodes.cpe_match[0].cpe23Uri[1] AND software.cpe='nodes.cpe_match[0].cpe23Uri[2]) OR (software.cpe='nodes.cpe_match[1].cpe23Uri[0] AND software.cpe='nodes.cpe_match[1].cpe23Uri[1] AND software.cpe='nodes.cpe_match[1].cpe23Uri[2]) OR (software.cpe='nodes.cpe_match[2].cpe23Uri[0] AND software.cpe='nodes.cpe_match[2].cpe23Uri[1] AND software.cpe='nodes.cpe_match[2].cpe23Uri[2]) OR (software.cpe='nodes.cpe_match[3].cpe23Uri[0] AND software.cpe='nodes.cpe_match[3].cpe23Uri[1] AND software.cpe='nodes.cpe_match[3].cpe23Uri[2])) ]
```

Which give a Indicator Object

```json
    "pattern": "[ ((software.cpe='cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*' AND software.cpe='cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*' AND software.cpe='cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*' AND software.cpe='cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*' AND software.cpe='cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*' AND software.cpe='cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*' AND software.cpe='cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*' AND software.cpe='cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*' AND software.cpe='cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*')) ]",
    "pattern_type": "stix",
    "valid_from": "2022-06-01T15:15:00.000Z",
    "extensions": {
      "extension-definition--b76208eb-b943-4705-9fab-fffec50d030d": {
          "extension_type": "property-extension",
          "vulnerable_cpeid": [
          	"cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
          	"cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
          	"cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
          	"cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*"
          ]
      }
```

Note how some `cpeuri`s appear as vulnerable more than once, but only show once under the `vulnerable_cpeid` property.

### Linking CVEs and Indicators

To create the Vulnerability to Indicator Relationship the following Relationship Object is used;

```json
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--<GENERATED BY STIX2 LIBRARY>",
      "created": "<publishedDate of cve>",
      "created_by_ref": "identity--<IDENTITY ID>",
      "modified": "<lastModifiedDate cve>",
      "relationship_type": "identifies",
      "source_ref": "indicator--<Indicator STIX Object>",
      "target_ref": "vulnerability--<Vulnerability STIX Object>"
    }
```