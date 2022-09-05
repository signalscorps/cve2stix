# cve2stix Documentations

In short; cve2stix converts CVEs from the NVD into STIX 2.1 Objects. Once STIX 2.1 Objects are created for each CVE, users can compare their own products against them to identify those that are vulnerable.

In this documentation you will find each of these steps between input and output explained. 

* [Ingest CPEs as STIX 2.1](/cve_sync.md): CVEs refer to CPEs. Therefore a copy of all CPEs in the NVD database are imported/updated by cve2stix and converted to STIX 2.1 Software Objects. This section of the documentation explains how this works.
* [Ingest CVEs as STIX 2.1](/cpe_sync.md): cve2stix can be used to download CVEs in the NVD database. On import/update it converts them to STIX 2.1 ulnerability Objects and Indicator Objects (with STIX Patterns). This section of the documentation explains how this works.
* [Enrich CVE data with ATT&CK and CAPEC](/enrichments.md): cve2stix also adds additional context to CVEs using ATT&CK and CAPEC STIX 2.1 Objects. This section of the documentation explains how this works.
* [Alerting](/alerts.md): cve2stix also periodically checks CPEs defined by a user against those that exist in CVE records downloaded by cpe2stix. This section of the documentation explains how alerting works.
* [Backends](backends.md): Backends allow you to store STIX Objects in a database of your choice in addition to the local filesystem. This section of the documentation shows available backends and how to configure them.
