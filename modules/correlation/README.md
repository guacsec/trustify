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

## Weighted resolution

Applicable evidence remains visible. Each voting statement receives a decision weight:

```
match confidence × provider relation × provider preference × directness
                 × match method preference × rule preference
```

The maximum weight for each status decides; duplicate statements cannot add votes. Weights
are rounded to six decimals before comparison. Equal weights use affected, fixed, not_affected,
then under_investigation. Recommended statements do not vote. Zero-weight evidence remains
visible but does not vote. All multipliers must be finite and nonnegative.

| Factor | Default |
|---|---:|
| Same provider as the SBOM component | 2 |
| Same provider name as the SBOM component, unverified | 1.5 |
| Providerless, with matching-provider evidence | 1 |
| Providerless fallback, without matching-provider evidence | 2 |
| Other or unidentified provider | 0.5 |
| Direct statement, normative boundary, or explicit default | 1.25 |
| Inferred statement or publisher interpretation | 1 |
| Provider, match method, or rule preference | 1 |
| Conflict sensitivity | 0.5 |

Matching-provider evidence must have a positive voting weight to suppress the generic fallback
boost. Explicit defaults apply when no listed direct version/range matches within that assertion
source. Inference does not suppress defaults. Strong generic evidence can outweigh weak
matching-provider inference. A strong unrelated provider is still eligible to win.

Verdicts include `decision_weight`, `confidence`, and `has_conflict`. Evidence match confidence
is unchanged. Verdict confidence is `C × (1 − sensitivity × O / W)`, where C is the winning
statement's match confidence, W its decision weight, and O the strongest opposing status weight.
Sensitivity ranges from zero to below one, so a tie retains positive confidence.

### Provider identity

The provider is who supplied the SBOM component; document authors are not providers. An explicit
component supplier wins over upstream identity, so a distribution's patched build of another
vendor's software favors that distribution. Missing component suppliers can inherit the product
supplier. Distribution/build and package namespace mappings precede this fallback; a configured
upstream CPE mapping is only used afterward. Unresolved explicit suppliers remain unidentified.

Names require exact configured aliases after case/whitespace normalization and removal of the
SPDX `Organization:` prefix to resolve to a provider. Without an alias, an assertion stating the
same name as the component still counts as an unverified match, with its own weight, unless both
sides resolve to different providers. Namespace identities trim trailing slashes. CVE organization IDs
and CNA/ADP container identities are preserved per assertion. Explicit alias mappings can join
names, namespaces, organization IDs, PURL namespaces, distributions, and CPE vendors. Conflicting
identities are diagnosed rather than guessed. Red Hat and SUSE mappings are seeded.

### Saved and temporary settings

`/api/v3/correlation/weight-policy` and `/api/v3/correlation/provider-alias` support GET/POST;
their `/{id}` paths support PUT/DELETE, using the correlation-option permissions.

For example, POST a component policy:

```json
{
  "scope": {"kind": "component", "sbom_id": "550e8400-e29b-41d4-a716-446655440000", "node_id": "library"},
  "weights": {"matching_provider": 3, "providers": {"https://supplier.example": 1.5}, "rules": {"purl_any_version": 0.8}}
}
```

Scopes inherit in order: instance, ancestor groups, descendant groups, SBOM, component, request.
A setting replaces the same inherited setting; unrelated dimensions multiply. Map entries inherit
individually. Group priority orders policies at the same depth; different settings for the same
knob at equal depth and priority return 409. Supply `group_id` to select an assigned group and
its ancestors. Group cycles are rejected. Settings and alias changes immediately re-resolve
current evidence. Extraction interpretation options still require re-extraction.

POST `/api/v3/correlation/preview` recalculates without saving settings or evidence:

```json
{
  "target": {"kind": "identifier", "identifier": {"kind": "purl", "value": "pkg:generic/library@1.0"}},
  "resolution": {"include_explanation": true, "overrides": {"component_provider": "https://supplier.example", "direct": 1.5}}
}
```

The target may instead be `{"kind":"sbom","sbom_id":"…"}`. Resolution accepts optional
`node_id`, `vulnerability_id`, `group_id`, and `product_context` (CPEs or RPM PURLs for an
identifier query). Contextual queries apply the extraction product compatibility rules.

Ordinary SBOM and identifier GETs accept `include_explanation=true`. SBOM GETs also accept
`node_id`, `vulnerability_id`, and `group_id`; identifier GETs accept `provider` and
`vulnerability_id`. Explanations expose component/source provider identities and diagnostics,
all factors with setting origins, maximum weights per status, the winning/opposing evidence,
the conflict calculation, and a fingerprint of the effective policy and aliases. Counts use
the same resolver with batched provider inputs. The UI offers **Why this verdict?**, temporary
weight previews, and saved policy/alias editors. Preview results are labeled as current
calculations so a later policy change cannot silently explain an earlier table result.

### Existing data

`m0002610` backfills known historical extractor origins, leaving unknown future origins alone.
`m0002620` adds supplier/source metadata and policy tables. Old merged CVE evidence is marked
`unavailable`, receives the unidentified-provider weight, and explains that source attribution
was lost. Existing component suppliers cannot be reconstructed safely from document authors.
Re-ingest the original documents through a path that actually replaces their stored assertions
and packages, then re-extract evidence to recover metadata; a duplicate-upload response or
re-extraction alone does not restore information ingestion discarded. Rollback removes the new
metadata and merges evidence sources to restore the previous unique key.
