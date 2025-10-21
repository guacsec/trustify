# 00009. Conservative PURL Garbage Collection

Date: 2025-10-21

## Status

APPROVED

## Context

Trustify maintains a normalized three-tier PURL (Package URL) hierarchy in the database:

1. **`base_purl`**: Contains package type, namespace, and name (e.g., `pkg:maven/io.quarkus/quarkus-core`)
2. **`versioned_purl`**: References a `base_purl` and adds version information (e.g., `@3.2.11.Final`)
3. **`qualified_purl`**: References a `versioned_purl` and adds qualifiers like architecture, distro, etc.

When SBOMs are ingested, they create references to packages via the `sbom_package_purl_ref` join table. When SBOMs are deleted, these references are removed via database CASCADE constraints, potentially leaving orphaned PURL records that no SBOM references.

Additionally, security advisories create entries in the `purl_status` table that reference `base_purl_id` to track which packages have known vulnerabilities. These advisory references represent critical security information that must be preserved.

The challenge is determining which orphaned PURLs should be deleted during SBOM deletion and which should be preserved because they represent packages with security significance.

### Assumptions

* Remove orphaned PURL records when SBOMs are deleted to prevent unbounded database growth
* Preserve PURL records for packages that have security advisories referencing them
* Maintain referential integrity across the three-tier PURL hierarchy

### Technical Constraints

* **Transaction ordering**: GC must execute BEFORE the SBOM delete statement, as SBOM deletion triggers CASCADE deletes on `sbom_package_purl_ref` which the GC query relies on
* **Foreign key relationships**: The database enforces CASCADE constraints from `base_purl` → `versioned_purl` → `qualified_purl`
* **Advisory preservation**: Any `base_purl` referenced in `purl_status` must be preserved along with ALL its versions and qualifiers

## Decision

Implement a **conservative garbage collection approach** that preserves all versions and qualifiers of a package if ANY advisory references its base PURL.

The GC process:

1. Identifies `qualified_purl` records that will become orphaned after SBOM deletion by checking `sbom_package_purl_ref`
2. Traces from `qualified_purl` → `versioned_purl` → `base_purl` to identify the base package
3. **Conservatively excludes** ANY `base_purl` that has entries in `purl_status` (advisory references)
4. Deletes only the `qualified_purl` records that are orphaned AND whose base package has no advisory references

### Conservative Nature

The approach is "conservative" because:

* If `pkg:maven/io.quarkus/quarkus-core` (base) is referenced by ANY advisory
* Then ALL versions are preserved: `@3.2.11`, `@3.2.12`, `@3.3.0`, etc.
* And ALL qualifiers are preserved: `?type=jar`, `?arch=x86_64`, etc.

All versions are preserved because it cannot be determined the versioned and qualified PURLs ingested during advisory ingestion.

## Alternative Approaches

### Deferred/Batch GC

Separate GC from SBOM deletion, running it as a periodic background job:

**Pros:**
* Simpler SBOM deletion endpoint logic
* Could optimize GC across multiple deletions

**Cons:**
* Temporary database bloat between deletions and GC runs
* More complex orchestration and monitoring
* Risk of orphaned records persisting indefinitely if GC job fails
* Transaction boundaries become unclear - harder to reason about consistency

### No GC - Keep All PURLs

Never delete PURL records, treating them as a cumulative knowledge base:

**Pros:**
* Simplest implementation
* Complete historical record
* No risk of data loss

**Cons:**
* Unbounded database growth
* Performance degradation over time
* Violates user expectations for data deletion
* Wasted storage on truly orphaned packages

## Consequences

### Benefits

* **Safety first**: No risk of deleting vulnerability information - if there's ANY doubt, the package is preserved
* **Transactional consistency**: GC and deletion happen atomically
* **Aligned with schema**: Works naturally with `purl_status.base_purl_id` foreign key

### Trade-offs

* **Storage overhead**: (potentially) Retains more data than strictly necessary, i.e. unreferenced versions of vulnerable packages persist
* **Imprecise cleanup**: Cannot distinguish between versions with and without vulnerabilities for the same base package
* **Package-level granularity only**: All-or-nothing at the base package level

### Future Considerations

* If storage becomes a concern, we could evolve to per-version GC, but this would require additional logic to handle version ranges from advisories
* The conservative approach provides a safe foundation that can be refined