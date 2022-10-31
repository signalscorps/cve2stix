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
		* `version`
	* `vulnerability`
		* `version`
	* `relationship`
		* `version`
* `stix2_bundles/`
	* `YEAR`
		* `<XXXX>`
			* `<CVE_ID>`
				* `bundle`
					* _Only contains most recent bundle version with latest versions of Indicator, Vulnerabilty, Relationship and enrichment objects_

This backend is always used as the json files saved are used to populate other backends.

## ArangoDB (`arangodb`)

This backend is built to support the ArangoDB community version.

To do this user should supply a config file named `arangodb.yml` with the following structure

```yml
host: # optional, default if blank: 'http://127.0.0.1:8529'
username: # optional, default if blank: root
password: # optional, default if blank: ''
```

The intialization script `/backends/arangodb/arangodb.py` configures the following in the ArangoDB instance;

* 1x Database named `cve2stix`
* 1x Document Collection in the `cve2stix` Database named `stix_objects`
* 1x Edge Collection in the `cve2stix` Database named `stix_relationships`

cve2stix stores files in each Collection as follows;

* All STIX 2.1 Objects with type `relationship` are stored in the `stix_relationships` Edge Collection
* All other STIX 2.1 Objects types are stored in `stix_objects` Document Collection.

[This implementation is described in more detail here](https://www.signalscorps.com/blog/2021/storing-stix-2_1-objects-database/).