# Correlation

Links SBOM components to advisory vulnerability assertions through evidence,
then resolves the evidence into verdicts.

See [ADR 00023](../../docs/adrs/00023-correlation-engine.md) for the design.

## API

### Get correlation verdicts for an SBOM

```shell
http GET localhost:8080/api/v3/correlation/sbom/{sbom_id}
```

Example:

```shell
http GET localhost:8080/api/v3/correlation/sbom/550e8400-e29b-41d4-a716-446655440000
```

### Query advisories by identifier

```shell
http GET localhost:8080/api/v3/correlation/query kind==cpe q=='cpe:2.3:o:wago:wago_os_linux:4.8.9:*:*:*:*:*:*:*'
```

CPEs are matched against the CPE patterns (and version ranges) of advisories.
CPE 2.2 URIs (`cpe:/o:wago:wago_os_linux:4.8.9`) are accepted as well.

## Verdict resolution

All applicable evidence remains visible. Eligible statements are compared in this fixed order:

1. **Provider relationship:** same resolved provider, same unverified provider name,
   providerless, then other or unresolved provider.
2. **Assertion origin:** stated or explicit default, then inferred, publisher interpretation,
   or unknown origin.
3. **Original match confidence:** higher first.
4. **Status:** affected, fixed, not_affected, then under_investigation.
5. **Stable evidence reference:** selects deterministically between equivalent statements.

Each criterion takes precedence over every later criterion. For example, low-confidence inference
from the component's provider takes precedence over a high-confidence direct statement from another
provider. Within one provider tier, a direct regression takes precedence over an inferred earlier fix.
There are no configurable weights or rankings. Duplicates cannot accumulate influence.

Recommended and zero-confidence statements remain visible but do not select a verdict. Match
confidence must be finite and within [0, 1]. Without eligible evidence, the verdict is `none`,
confidence is zero, and there is no selected statement.

Verdicts retain `confidence`, the selected statement's original match confidence, and `has_conflict`.
Any eligible statement giving a different status sets the conflict flag, even in a lower provider
tier. Conflict does not reduce match confidence; confidence measures the match rather than agreement
between sources.

The UI explains the product-match multiplier using its source confidence and CPE wildcard
multiplier, including intermediate rounding. A confirmed product can still reduce confidence:
confirmation establishes compatibility, while the source and matching method determine the
multiplier. These values are matching heuristics, not vulnerability probabilities. Older stored
evidence lacks this breakdown; re-extract correlation evidence to record it. Scores are unchanged.

### Provider identity

The provider is who supplied the SBOM component; document authors are not providers. An explicit
component supplier wins over upstream identity, so a distribution's patched build of another
vendor's software prefers that distribution's assertions. Missing component suppliers can inherit the product
supplier. Distribution/build and package namespace mappings precede this fallback; a configured
upstream CPE mapping is only used afterward. Unresolved explicit suppliers remain unidentified.

Names require exact configured aliases after case/whitespace normalization and removal of the
SPDX `Organization:` prefix to resolve to a provider. Without an alias, an assertion stating the
same name as the component still counts as an unverified match, unless both
sides resolve to different providers. Namespace identities trim trailing slashes. CVE organization IDs
and CNA/ADP container identities are preserved per assertion. Explicit alias mappings can join
names, namespaces, organization IDs, PURL namespaces, distributions, and CPE vendors. Conflicting
identities are diagnosed rather than guessed. Red Hat and SUSE mappings are seeded.

### Provider aliases, explanations, and temporary context

`/api/v3/correlation/provider-alias` supports GET/POST; `/{id}` supports PUT/DELETE,
using the correlation-option permissions. Alias changes immediately re-resolve current evidence.
Extraction interpretation options still require re-extraction.

Ordinary SBOM and identifier GETs accept `include_explanation=true`. SBOM GETs also accept
`node_id` and `vulnerability_id`; identifier GETs accept `provider` and `vulnerability_id`.
Explanations include the component and source providers, attribution diagnostics, every evidence
item in precedence order, the winning and strongest opposing evidence, and the first deciding
criterion. Each item reports its provider relationship, origin, original confidence, outcome
(selected, supporting, conflicting, or non-voting), and selection reason.

POST `/api/v3/correlation/preview` recalculates using temporary context without saving changes:

```json
{
  "target": {"kind": "identifier", "identifier": {"kind": "purl", "value": "pkg:generic/library@1.0"}},
  "resolution": {
    "include_explanation": true,
    "component_provider": "https://supplier.example"
  }
}
```

The target may instead be `{"kind":"sbom","sbom_id":"…"}`. Resolution accepts optional
`node_id` (SBOM only), `vulnerability_id`, and `product_context` (CPEs or RPM PURLs for identifier
queries only). An explicit component provider overrides automatic supplier resolution for that
request only. Contextual queries retain the extraction product-compatibility rules.

Counts use the same resolver with batched provider inputs. The UI retains **Why this verdict?**,
provider alias editing, and temporary context previews. It labels the selected match confidence as
**Confidence** and displays conflicts separately. Explanations describe the current calculation;
`resolution_revision` fingerprints the resolver version, aliases, and resolution context.

### Removal of weighting: breaking changes

The weight-policy endpoints, policy scopes and inheritance, and all multiplier controls are removed.
`ResolutionRequest.overrides` is replaced by the standalone `component_provider` field; policy
`group_id` is removed. Obsolete request fields return HTTP 400. Weight-policy routes return HTTP 404.

Responses no longer contain `decision_weight`, factors, weighted status totals, effective settings,
policy origins, opposing weights, or confidence penalties. `policy_revision` is replaced by
`resolution_revision`. Explanations report `status`, `deciding_criterion`, and readable `reason`;
evidence items use `provider_relationship`, `outcome`, and `selection_reason`.

Deploy the matching backend and UI together. Existing evidence is resolved with the new rules on
its next read; this change requires no re-ingestion or re-extraction.

### Existing data

`m0002610` backfills known historical extractor origins, leaving unknown future origins alone.
`m0002620` adds supplier/source metadata and provider aliases.
`m0002630` removes the obsolete weight-policy table and its data, preserving aliases and evidence.
Downgrading `m0002630` recreates an empty policy table; discarded policies are not restored. Old merged CVE evidence is marked
`unavailable`, uses the other/unresolved provider tier, and explains that source attribution
was lost. Existing component suppliers cannot be reconstructed safely from document authors.
Re-ingest the original documents through a path that actually replaces their stored assertions
and packages, then re-extract evidence to recover metadata; a duplicate-upload response or
re-extraction alone does not restore information ingestion discarded. Rolling back the older `m0002620` migration removes its
metadata and merges evidence sources to restore the previous unique key.
