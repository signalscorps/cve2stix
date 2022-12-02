# Backends

Backends allow you to store STIX Objects in a database of your choice in addition to the local filesystem. This section of the documentation shows available backends and how to configure them.

## Backend struture

Each Backend ships with a default initialization script that is used to create the database schema cve2stix will write to. This is executed the first time the backend is used.

Backends authentication is specified using a backend `<CONFIG>.yml`.

This configoration file is passed when running cve2stix commands.

## Local filesystem

The default backend is filesystem storage.

The Indicator SDO, Vulnerability SDO, and Relationship SRO (and STIX bundle) for each CVE ID are each stored as unique json file in the repo in a subdirectory based on the year as well as the numeric portion of the id, truncated by 1,000.

For example, 2017/3xxx is for CVE-2017-3000 - CVE-2017-3999, and 2017/1002xxx is for CVE-2017-1002000 - CVE-2017-1002999.

The structure is as follows;

* `stix2_objects/`
	* `indicator`
		* `indicator-ID`
			* `version`
	* `vulnerability`
		* `vulnerability-ID`
			* `version`
	* `relationship`
		* `relationship-ID`
			* `version`
	* `software`
		* `software-ID`
			* `version`
* `stix2_bundles/`
	* `YEAR`
		* `<XXXX>`
			* `<CVE_ID>`
				* `bundle`
					* _Bundle contains latest versions of Indicator, Vulnerabilty, Relationship and enrichment objects. Each time an object in a bundle is updated (or new object added), a new bundle is generated (with new `id`). Only latest bundle version exists in this directory._

This backend is always used as the json files saved are used to populate other backends.