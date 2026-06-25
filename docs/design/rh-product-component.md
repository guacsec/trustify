# Red Hat Product-Component Model

How Trustify links Red Hat product SBOMs to the component SBOMs they ship.

## Overview

Red Hat product SBOMs declare which components they include via CycloneDX `provides` (or `dependsOn`)
relationships. Unlike CycloneDX and SPDX external references, which use document IDs or hashes to name
the target SBOM directly, the RH model uses **bom-ref matching** at ingestion time and **checksum matching**
at query time to find the actual component SBOM.

The flow has three stages:

1. **Ingestion** -- the `rh_prod_comp` processor detects Red Hat SBOMs and creates external node records.
2. **Materialization** -- `populate_ancestors` links product and component SBOMs via shared checksums.
3. **Query-time resolution** -- `batch_resolve_direct_cpe_matches` looks up component nodes to build
   the ranked CPE results.

## Example SBOMs

### Product SBOM

A Red Hat product SBOM declares itself as supplier "Red Hat", has a CPE on its root component,
and uses `provides` to list the components it ships:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:product-001",
  "metadata": {
    "supplier": { "name": "Red Hat" },
    "component": {
      "name": "Red Hat build of Quarkus",
      "type": "framework",
      "bom-ref": "quarkus-product",
      "evidence": {
        "identity": [{
          "field": "cpe",
          "concludedValue": "cpe:/a:redhat:quarkus:2.13"
        }]
      }
    }
  },
  "components": [{
    "name": "quarkus-bom",
    "bom-ref": "pkg:maven/com.redhat.quarkus/quarkus-bom@2.13.9",
    "type": "library",
    "hashes": [{ "alg": "SHA-256", "content": "abc123..." }]
  }],
  "dependencies": [{
    "ref": "quarkus-product",
    "provides": ["pkg:maven/com.redhat.quarkus/quarkus-bom@2.13.9"]
  }]
}
```

### Component SBOM

A separate SBOM for the component itself. Its root has the **same bom-ref** as the product's
component entry, and the **same checksum** so that `populate_ancestors` can link them:

```json
{
  "bomFormat": "CycloneDX",
  "serialNumber": "urn:uuid:component-001",
  "metadata": {
    "component": {
      "name": "quarkus-bom",
      "bom-ref": "pkg:maven/com.redhat.quarkus/quarkus-bom@2.13.9",
      "hashes": [{ "alg": "SHA-256", "content": "abc123..." }]
    }
  }
}
```

## Stage 1: Ingestion (`rh_prod_comp` processor)

The processor activates when `metadata.supplier.name` is `"Red Hat"` (case-insensitive).

It scans all relationships and picks those where:

- The **source node** (`left_node_id`) is a "top-level" component (described by the SBOM document
  and has at least one CPE), **and**
- The relationship is `Generates` (CycloneDX `provides`) or `Package`.
- `Variant` relationships are also processed regardless of the source node.

For each matching relationship it creates:

| What | Value | Example |
|------|-------|---------|
| Synthetic node ID | `{prod_node_id}:{comp_node_id}` | `quarkus-product:pkg:maven/.../quarkus-bom@2.13.9` |
| `external_node_ref` | `comp_node_id` (the component's bom-ref) | `pkg:maven/.../quarkus-bom@2.13.9` |
| `external_type` | `RedHatProductComponent` (2) | |
| `discriminator` | `None` | |

This inserts two database rows:

```
sbom_node:
  sbom_id  = <product>
  node_id  = "quarkus-product:pkg:maven/.../quarkus-bom@2.13.9"   (synthetic)
  name     = "pkg:maven/.../quarkus-bom@2.13.9"

sbom_external_node:
  sbom_id            = <product>
  node_id            = "quarkus-product:pkg:maven/.../quarkus-bom@2.13.9"
  external_node_ref  = "pkg:maven/.../quarkus-bom@2.13.9"
  external_type      = 2  (RedHatProductComponent)
```

It also adds a `Package` relationship from the component bom-ref to the synthetic node,
so the component is connected to the external reference in the relationship graph.

### What makes a node "top-level"?

A node is top-level when **all** of these hold:

1. The SBOM document **describes** it (there is a `Describes` relationship from the document node).
2. It has **at least one CPE** -- unless the SBOM contains any `Variant` relationship
   (image-index case), in which case CPEs are not required.

In practice, this means the root `metadata.component` with a CPE.

## Stage 2: Materialization (`populate_ancestors`)

After ingestion, `populate_ancestors` runs a SQL query that:

1. Finds the **checksum** of the node referenced by `external_node_ref` in the product SBOM.
2. Looks for **other SBOMs** that have a node with the **same checksum value**.
3. Inserts `(child_sbom_id, ancestor_sbom_id)` rows into `sbom_ancestor`.

This is how the product-to-component link is established -- not by document ID, but by
matching the binary artifact's hash across SBOMs.

```
sbom_ancestor:
  sbom_id          = <component>    (child)
  ancestor_sbom_id = <product>      (ancestor)
```

## Stage 3: Query-time resolution (`batch_resolve_direct_cpe_matches`)

When ranking SBOMs by CPE, the system needs to find which component name a product SBOM
references. This is done by `batch_resolve_direct_cpe_matches`:

1. **Find external nodes with CPEs** -- joins `sbom_external_node` with `sbom_describing_cpe`
   for the product SBOM. This gives `(sbom_id, external_node_ref, cpe_ids[])`.

2. **Look up target nodes** -- queries `sbom_node WHERE node_id = external_node_ref`.
   Since `external_node_ref` is the component's bom-ref (e.g. a purl), this finds every
   `sbom_node` across all SBOMs that has this bom-ref as its `node_id`.

3. **Pick a candidate** -- from the matching nodes, picks the first one whose `sbom_id`
   differs from the product SBOM. The selected node's `name` becomes `matched_name`.

4. **Build ranked results** -- uses `matched_name` to partition SBOMs in `apply_rank`
   via `DENSE_RANK() OVER (PARTITION BY cpe_id, matched_name)`.

### Visual: resolution flow

```
Product SBOM (has CPE)
  │
  └─ sbom_external_node
       external_node_ref = "pkg:maven/.../quarkus-bom@2.13.9"
       │
       ▼ lookup: sbom_node WHERE node_id = "pkg:maven/.../quarkus-bom@2.13.9"
       │
       ├─ Component SBOM  →  name = "quarkus-bom"     ← correct target
       └─ Decoy SBOM      →  name = "decoy-thing"     ← wrong target
```

## Known issue: node_id collision

**The candidate selection in step 3 is insertion-order dependent.**

The code picks the first `sbom_node` whose `sbom_id != product_sbom_id`:

```rust
let node = candidates
    .iter()
    .find(|n| n.sbom_id != matched.sbom_id)
    .unwrap_or(&candidates[0]);
```

When multiple SBOMs contain a node with the same bom-ref (which is common -- the same
package appears in many SBOMs), the result depends on which SBOM was ingested first.
If a "decoy" SBOM was ingested before the real component SBOM, the wrong name is returned.

### Why it hasn't caused visible failures (yet)

In the RH model, the same component across different SBOMs typically has the **same name**
(e.g. `quarkus-bom` is always called `quarkus-bom`). Since `apply_rank` only uses
`matched_name` for partitioning, picking the wrong SBOM's node still produces the same
partition key. The final output uses `matched_sbom_id` (the product SBOM's own ID), which
is always correct regardless of which candidate was chosen.

The bug would surface when two SBOMs share a bom-ref but have **different component names**
-- an unlikely but possible scenario.

### Reproducer test

The test `rh_node_id_collision` in `modules/analysis/src/service/load/rank.rs` demonstrates
this with three minimal SBOMs:

| SBOM | bom-ref | Component name |
|------|---------|----------------|
| product.json | `shared-comp` (in `provides`) | -- |
| component.json | `shared-comp` (root) | SharedLib |
| decoy.json | `shared-comp` (root) | DecoyLib |

Ingesting the decoy **before** the component causes the code to pick "DecoyLib"
instead of "SharedLib". The test is marked `#[ignore]` because it exposes this bug.

```bash
# Run the reproducer (expected to fail):
cargo test -p trustify-module-analysis rh_node_id_collision -- --ignored
```

## Comparison with other external reference models

| | SPDX | CycloneDX | RH Product-Component |
|-|------|-----------|---------------------|
| **How the target SBOM is identified** | SHA-256 of the source document | `urn:cdx:{serial}/{version}` document ID | Checksum matching via `sbom_node_checksum` |
| **Discriminator** | `Sha256` hash | `CycloneDxVersion` version number | None |
| **`external_node_ref`** | Node ID in the external doc | Component bom-ref in the external doc | Component bom-ref (same namespace as local nodes) |
| **`target_sbom_id`** | Not populated | Not populated | Not populated |
| **Resolution path** | `source_document.sha256` lookup | `sbom.document_id` lookup | `sbom_node_checksum.value` matching |

The `target_sbom_id` column on `sbom_external_node` was intended to cache the resolved
target SBOM for SPDX/CycloneDX references, but it has never been populated or read.
