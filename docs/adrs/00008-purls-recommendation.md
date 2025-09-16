# 00007. PURL recommendations endpoint

## Status

ACCEPTED

## Context

The goal is to provide API endpoint compatible with Trustification v1 [exhort/recommend](https://github.com/trustification/trustification/blob/1d65f2c1cce303a89f1f9ca1e8cd6285f1d23de0/exhort/api/src/server.rs#L165) endpoint that provides recommendations and remediations for requested packages.

A recommendation is a vendor-specific build or vendor-patched dependency that can replace the current open source dependency in order to get a build from a trusted source. It's just a suggestion.

A remediation is a vendor-specific build or vendor-patched dependency that even having the same version it has been patched and is not affected by any known vulnerability. In this case users are encouraged to move to the remediation.

The endpoint receives a list of purls to be analyzed. An example of the request can be found in [Exhort tests](https://github.com/trustification/exhort/blob/main/src/test/resources/__files/trustedcontent/maven_request.json).

For each of the purls, the endpoint will try to find the "trusted" version of it. It is the package of the same version (up to the patch level) but an alternative coming from a trusted source. It is usually done with a suffix (examples `.redhat-xxx`, `-atlassian-x` or `.release` (Spring))

Example:

```
pkg:maven/io.quarkus/quarkus-resteasy/3.20.2
```
The productized/trusted package is:

```
pkg:maven/io.quarkus/quarkus-resteasy/3.20.2.redhat-00004
```

For every such package, the endpoint needs to find all known vulnerability statuses and return them. The full example of the response can be found in [Exhort tests](https://github.com/trustification/exhort/blob/main/src/test/resources/__files/trustedcontent/maven_report.json).

## Decision

The endpoint can be implemented using mostly existing services. The new endpoint accompanies the existing [`analyze` method](https://github.com/guacsec/trustify/blob/main/modules/fundamental/src/vulnerability/endpoints/mod.rs).

The [purl search service](https://github.com/guacsec/trustify/blob/3818788ca7f893d3d9bfa03bd71b03216017a857/modules/fundamental/src/purl/service/mod.rs#L291) is used to find appropriate purls

The example query can look like this

```
purl:namespace=io.quarkus&purl:name=quarkus-core&purl:version>2.13.9.Final&purl:version<2.13.10.Final
```

After obtaining all purls, the further filtering is done (like using Red Hat pattern from v1, but the more general pattern matching must be developed to cover more use cases).

For each purl that's returned, the call to [purl service `versioned_purl_by_uuid`](https://github.com/guacsec/trustify/blob/7656e1390617fc1d4d34365ec9a7047f9c5b398a/modules/fundamental/src/purl/service/mod.rs#L190) function returns all advisories for the given purl. This response is then transformed into the endpoint response format.


## Open items

* Provide a way to return different patterns of recommended purls, so users can adapt this functionality to their versioning scheme.
* Implement function(s) that will optimize the performance of the endpoint. For example, return advisories for a list of purls instead of doing it one by one in the loop.
* Ingest remediation information from advisories and use them to provide more data to results of this endpoint (requires a separate ADR).

## Consequences

* We add a simple, stateless endpoint for retrieving recommended versions (with their advisories) for the list of purls.


