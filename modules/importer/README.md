# Importer

## Server configuration

The `importer` service is started using `trustd`, e.g.

```shell
trustd importer --concurrency=4 --working-dir=".trustify/importer"
```

The default value for `concurrency` is 1. This is the maximum number
of importer jobs run simultaneously by the service.

The `importer` should be started with the same database and storage
options as the associated `api` service. Run the following to see what
those are:

```shell
trustd importer --help
```

## Client API

### Create a new CSAF importer

```shell
http POST localhost:8080/api/v2/importer/redhat-csaf csaf[source]=https://redhat.com/.well-known/csaf/provider-metadata.json csaf[disabled]:=false csaf[onlyPatterns][]="^cve-2023-" csaf[period]=30s csaf[v3Signatures]:=true
```

### Create a new OSV importer

```shell
http POST localhost:8080/api/v2/importer/osv-r osv[source]=https://github.com/RConsortium/r-advisory-database osv[path]=vulns osv[disabled]:=false osv[period]=30s
```

### Create a new SBOM importer

Quarkus & RHEL 9 data:

```shell
http POST localhost:8080/api/v2/importer/redhat-sbom sbom[source]=https://security.access.redhat.com/data/sbom/v1/spdx/ sbom[keys][]=https://security.access.redhat.com/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4 sbom[disabled]:=false sbom[onlyPatterns][]=quarkus sbom[onlyPatterns][]=rhel-9 sbom[period]=30s sbom[v3Signatures]:=true
```

### Get all importers

```shell
http GET localhost:8080/api/v2/importer
```

### Get a specific importer

```shell
http GET localhost:8080/api/v2/importer/redhat-csaf
http GET localhost:8080/api/v2/importer/redhat-sbom
```

### Get reports

```shell
http GET localhost:8080/api/v2/importer/redhat-csaf/report
http GET localhost:8080/api/v2/importer/redhat-sbom/report
```

### Update an importer configuration

```shell
http PUT localhost:8080/api/v2/importer/redhat-csaf csaf[source]=https://redhat.com/.well-known/csaf/provider-metadata.json csaf[disabled]:=false csaf[period]=30s csaf[v3Signatures]:=true csaf[fetchRetries]:=50
```

Or, updating the existing configuration (requires `jq`). To preview the changes:

```shell
http GET localhost:8080/api/v2/importer/redhat-csaf/report | jq .configuration | jq .csaf.fetchRetries=50
```

To execute:

```shell
http GET localhost:8080/api/v2/importer/redhat-csaf | jq .configuration | jq .csaf.fetchRetries=50 | http PUT localhost:8080/api/v2/importer/redhat-csaf
```

### Patch an importer configuration

```shell
http PATCH localhost:8080/api/v2/importer/redhat-csaf "Content-Type:application/merge-patch+json" csaf[fetchRetries]:=50
```

### Delete an importer

```shell
http DELETE localhost:8080/api/v2/importer/redhat-csaf
http DELETE localhost:8080/api/v2/importer/redhat-sbom
```

### Set the enabled state of an importer

```shell
echo true | http PUT localhost:8080/api/v2/importer/redhat-sbom/enabled
```

### Force an importer run

```shell
http PUT localhost:8080/api/v2/importer/redhat-sbom/force
```
