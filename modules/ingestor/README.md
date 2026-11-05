# Ingestor

## Upload an SBOM

```shell
cat file.sbom | http POST localhost:8080/api/v3/sbom location==cli
```

## Upload a dataset

```shell
http POST localhost:8080/api/v3/dataset @file-to-upload
```

## Red Hat Lightwell OSV advisories

OSV records whose `affected[].package.ecosystem` is `Red Hat Lightwell:<ecosystem>`
(for example `Red Hat Lightwell:Maven` or `Red Hat Lightwell:PyPI`) are unwrapped to
their native ecosystem for PURL inference and `ECOSYSTEM` range version ordering.
Explicit `SEMVER` and `GIT` ranges and explicit `versions` lists are handled as for
any other OSV record.

Ordinary (non-Lightwell) OSV records are unchanged: they keep both the inferred and
the stated PURL candidates, without reconciliation or warnings.

For Lightwell entries only, the inferred and stated PURLs are reconciled into a single
PURL:

* An invalid stated PURL is ignored with a warning, and a version in a stated PURL is
  removed with a warning.
* Type, namespace and name must agree (NuGet names are compared case-insensitively,
  and the inferred spelling is used). On a mismatch, a warning is emitted and the
  `affected` entry is skipped.
* A `repository_url` qualifier is kept from either source. If both sources state
  different repositories, a warning is emitted and the `affected` entry is skipped.
* If no usable PURL remains, a warning is emitted and the `affected` entry is skipped.

Other `affected` entries of the same record are still processed.

On this branch, vulnerabilities and package statuses are keyed on CVE IDs. Lightwell
records list their CVEs in `upstream` rather than `aliases`, so for records with a
Lightwell package the `CVE-` entries of `upstream` are used in addition to those of
`aliases`. The `RHLW-…` record ID identifies the advisory, not a vulnerability.

Repository qualifiers are not used for matching: package statuses are stored against
the base PURL (type, namespace and name), so repository information does not provide
repository-aware matching.

See [`package_purls()`](src/service/advisory/osv/loader.rs) for the policy and
[`osv_lightwell.rs`](tests/osv_lightwell.rs) for database regression coverage.
