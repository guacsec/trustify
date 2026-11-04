# Ingestor

## Upload an SBOM

```shell
cat file.sbom | http POST localhost:8080/api/v3/sbom location==cli
```

## Upload a dataset

```shell
http POST localhost:8080/api/v3/dataset @file-to-upload
```

## OSV package identity and repository handling

An OSV `affected` entry can identify a package through both its ecosystem/name and
an explicitly stated PURL. For Maven, a repository URL can appear in the ecosystem
suffix or in the PURL's `repository_url` qualifier. These descriptions are
reconciled rather than always preferring one or retaining both as alternatives.
The same policy applies to ordinary and Red Hat Lightwell ecosystems.

### Reconciliation policy

When both PURLs are available, their type, namespace and name must agree, allowing
for NuGet's case-insensitive package names. Compatible identities produce one PURL,
retaining the stated qualifiers and adding an inferred repository when needed:

| Inferred repository qualifier | Stated repository qualifier | Result |
| --- | --- | --- |
| Absent | A | Retain A |
| A | Absent | Retain A |
| A | A | Retain one PURL with A |
| A | B | Warn; create no package-status assertions for this affected entry |

Here, "absent" means no repository qualifier: Maven's default Central repository
is not emitted as an inferred qualifier. Repository values are compared directly;
mirror or URL-alias equivalence is not inferred.

Conflicting package identities are also warned about and skipped. Other affected
entries continue to be processed. If only one usable PURL is available, it is used;
an invalid stated PURL produces a warning, as does having no usable PURL. A version
in a stated PURL is removed with a warning, since OSV describes versions separately.

### Why conflicting repositories are not combined

Disagreement between two fields does not establish that both repositories are
affected. It might indicate incorrect input, a mirror, or different notions of
origin. Saving both as active alternatives would turn an ambiguous assertion into
an assertion of applicability to both repositories. Combining values into a single
`repository_url` is not supported by the current string-valued qualifier model.
Adding provenance qualifiers would also change the qualified PURL's identity.

The conservative policy is therefore to warn and skip the ambiguous package-status
assertion. This can omit useful coverage, but avoids guessing the source's intent.
The original advisory remains available in document storage. If two repositories
are explicitly affected, they can be represented by separate, internally consistent
`affected` entries. Preserving unresolved claims as structured assertion metadata
is a possible follow-up, not part of this policy.

### Storage is not matching isolation

A reconciled repository is stored in `qualified_purl.qualifiers` under
`repository_url`, and in the canonical JSON in `qualified_purl.purl`.
`purl_status.qualified_purl_id` links the advisory assertion to that PURL.
`base_purl` contains only type, namespace and name, not repository qualifiers.

Preserving repository information does **not** guarantee repository-aware matching.
Maven/PyPI correlation currently ignores qualifiers, and matching on base PURL
identity alone does not distinguish repositories. Repository/provider applicability
requires separate matching semantics; it must not be inferred from storage alone.

### Public Lightwell coverage

At [Lightwell snapshot `4b5c35d`](https://github.com/project-lightwell/lightwell-osv/tree/4b5c35ddd26f0832a308db5943d40b1ca8e14225/advisories),
all 234 advisories (232 Maven, two PyPI) have stated PURLs but no repository
qualifiers or explicit ecosystem repository suffixes. No repository conflicts were
found. Repository-preservation and conflict regressions use constructed variations,
not conflicting public advisories. No vendor repository URL is invented from the
Lightwell ecosystem label; repository URLs alone cannot provide vendor isolation
for these records.

See [`package_purls()`](src/service/advisory/osv/loader.rs) for the policy and
[`osv_lightwell.rs`](tests/osv_lightwell.rs) for database regression coverage.
