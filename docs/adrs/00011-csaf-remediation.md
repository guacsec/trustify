# 00011. CSAF Remediation Support

## Status

ACCEPTED

## Context

Trustify ingests CSAF advisories and exposes which packages are affected by vulnerabilities through the `purl_status` and `product_status` tables. However, CSAF documents also contain **remediation** guidance that tells users HOW to fix vulnerabilities (e.g., "upgrade to version X", "apply workaround Y").

### Current Limitation

When a user queries for vulnerability status, they receive information about WHAT is affected:
- Package X version 1.2.3 is **affected** by CVE-2024-1234
- Package X version 2.0.0 is **fixed**

But they don't receive actionable guidance on HOW to fix it:
- "Upgrade to version 2.0.0 or apply workaround described at https://..."
- "Restart required after upgrade"
- "Workaround: disable feature Y"

### CSAF Remediation Structure

CSAF remediations are linked to specific `product_ids` within the advisory, which resolve to specific packages during ingestion. Each remediation includes:
- **Category**: `vendor_fix`, `workaround`, `mitigation`, `no_fix_planned`, `none_available`, `will_not_fix`
- **Details**: Human-readable description of the remediation
- **URL**: Link to detailed guidance
- **Metadata**: Restart requirements, dates, entitlements

## Decision

Add remediation support by creating a `remediation` table with junction tables linking to specific `purl_status` and `product_status` records.

### Schema Design

**Remediation category enum (SeaORM):**
```rust
#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, ToSchema)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "remediation_category")]
#[serde(rename_all = "snake_case")]
pub enum RemediationCategory {
    #[sea_orm(string_value = "vendor_fix")]
    VendorFix,
    #[sea_orm(string_value = "workaround")]
    Workaround,
    #[sea_orm(string_value = "mitigation")]
    Mitigation,
    #[sea_orm(string_value = "no_fix_planned")]
    NoFixPlanned,
    #[sea_orm(string_value = "none_available")]
    NoneAvailable,
    #[sea_orm(string_value = "will_not_fix")]
    WillNotFix,
}
```

**Core remediation table:**
```sql
CREATE TABLE remediation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id UUID NOT NULL,
    vulnerability_id VARCHAR NOT NULL,
    category remediation_category NOT NULL,
    details TEXT,
    url VARCHAR,
    data JSONB,  -- {restart_required, date, entitlements, ...}

    FOREIGN KEY (advisory_id, vulnerability_id)
        REFERENCES advisory_vulnerability(advisory_id, vulnerability_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_remediation_advisory_vuln
    ON remediation(advisory_id, vulnerability_id);
```

**Junction tables linking remediations to specific status records:**
```sql
CREATE TABLE remediation_purl_status (
    remediation_id UUID REFERENCES remediation(id) ON DELETE CASCADE,
    purl_status_id UUID REFERENCES purl_status(id) ON DELETE CASCADE,
    PRIMARY KEY (remediation_id, purl_status_id)
);

CREATE INDEX idx_remediation_purl_status_purl
    ON remediation_purl_status(purl_status_id);

CREATE TABLE remediation_product_status (
    remediation_id UUID REFERENCES remediation(id) ON DELETE CASCADE,
    product_status_id UUID REFERENCES product_status(id) ON DELETE CASCADE,
    PRIMARY KEY (remediation_id, product_status_id)
);

CREATE INDEX idx_remediation_product_status_product
    ON remediation_product_status(product_status_id);
```

**JSONB data field structure:**
```json
{
  "restart_required": {"category": "none|system|zone|service|parent|dependencies|..."},
  "date": "2024-03-15T10:30:00Z",
  "entitlements": ["premium-support"],
}
```

### Design Choices

- Remediations link to **specific purl_status/product_status records**
- Use PostgreSQL ENUM for category field to ensure type safety at the database level. The CSAF spec constrains valid values, so an enum provides better validation than VARCHAR.
- Normalize only important remediation fields, while keeping the rest in JSON blob

### Ingestion Approach

During CSAF ingestion:
1. `StatusCreator` resolves product_ids - creates purl_status/product_status records
2. Track which records were created for each product_id
3. `RemediationCreator` uses this mapping to create junction table entries

This follows the existing `StatusCreator` pattern and reuses the `ResolveProductIdCache`.

### API Exposure

**New API Model:**
```rust
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct RemediationSummary {
    pub category: RemediationCategory,
    pub details: Option<String>,
    pub url: Option<String>,
    pub data: serde_json::Value,  // Value::Null when empty
}
```

**Targeted Endpoint Integration:**

Rather than adding remediations to all status endpoints, we introduce them to endpoints where users actively seek fix guidance:

| Endpoint | Response Model Modified | Rationale |
|----------|------------------------|-----------|
| `POST /v3/vulnerability/analyze` | `AnalysisPurlStatus` (new wrapper) | Users checking vulnerabilities need to know how to fix them |
| `POST /v3/purl/recommend` | `VulnerabilityStatus` | Users explicitly asking "what should I use instead?" |

**Leave unchanged:**
- `POST /v2/vulnerability/analyze` - v2 API remains stable
- `POST /v2/purl/recommend` - v2 API remains stable
- `GET /v2/purl/{key}` - uses `PurlStatus` directly, no remediations yet

**New wrapper struct for v3 analyze:**

To avoid modifying the shared `PurlStatus` struct, we create a wrapper that adds remediations:

```rust
// modules/fundamental/src/vulnerability/model/analyze.rs

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct AnalysisPurlStatus {
    #[serde(flatten)]
    pub status: PurlStatus,
    pub remediations: Vec<RemediationSummary>,
}

// Update AnalysisDetails to use the new struct
pub struct AnalysisDetails {
    #[serde(flatten)]
    pub head: VulnerabilityHead,
    pub purl_statuses: Vec<AnalysisPurlStatus>,  // Changed from Vec<PurlStatus>
}
```

**VulnerabilityStatus change (for recommend endpoint):**

Unlike `PurlStatus`, `VulnerabilityStatus` is only used by the recommend endpoint. We can add remediations directly:

```rust
// modules/fundamental/src/purl/model/mod.rs

pub struct VulnerabilityStatus {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<VexStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<VexJustification>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub remediations: Vec<RemediationSummary>,  // New field
}
```

**Phase 1 - Initial Endpoints:**
- `POST /v3/vulnerability/analyze` - use `AnalysisPurlStatus` wrapper with remediations
- `POST /v3/purl/recommend` - add `remediations` field directly to `VulnerabilityStatus`

**Phase 2 - Future Endpoints (as needed):**
- `GET /v2/purl/{key}` - add to `PurlStatus`
- `GET /v2/sbom/{id}/advisory` - add to `SbomStatus`

**Example Response (v3 analyze endpoint):**
```json
{
  "pkg:maven/io.quarkus/quarkus-core@3.2.11.Final-redhat-00001": {
    "details": [
      {
        "identifier": "CVE-2024-1234",
        "title": "Remote code execution in Quarkus REST handler",
        "purl_statuses": [
          {
            "vulnerability": {"identifier": "CVE-2024-1234", "title": "..."},
            "advisory": {"identifier": "RHSA-2024:2705", "issuer": "Red Hat"},
            "status": "affected",
            "average_severity": "high",
            "average_score": 8.1,
            "version_range": {"low_version": "3.0.0", "high_version": "3.2.12"},
            "remediations": [
              {
                "category": "vendor_fix",
                "details": "Upgrade to Red Hat build of Quarkus 3.2.12.Final",
                "url": "https://access.redhat.com/errata/RHSA-2024:2705",
                "data": {"restart_required": {"category": "none"}}
              },
              {
                "category": "workaround",
                "details": "Disable the vulnerable REST endpoint",
                "url": null,
                "data": null
              }
            ]
          }
        ]
      }
    ],
    "warnings": []
  }
}
```

**Example Response (v3 recommend endpoint):**
```json
{
  "recommendations": {
    "pkg:maven/io.quarkus/quarkus-core@3.2.11.Final": [
      {
        "package": "pkg:maven/io.quarkus/quarkus-core@3.2.12.Final-redhat-00001",
        "vulnerabilities": [
          {
            "id": "CVE-2024-1234",
            "status": "Fixed",
            "remediations": [
              {
                "category": "vendor_fix",
                "details": "Upgrade to Red Hat build of Quarkus 3.2.12.Final",
                "url": "https://access.redhat.com/errata/RHSA-2024:2705",
                "data": {"restart_required": {"category": "none"}}
              }
            ]
          }
        ]
      }
    ]
  }
}
```

**Query Strategy:**

Remediations are queried by (advisory_id, vulnerability_id) which is already available in both endpoints:
```sql
SELECT r.category, r.details, r.url, r.data
FROM remediation r
WHERE r.advisory_id = ? AND r.vulnerability_id = ?;
```

The junction tables (`remediation_purl_status`, `remediation_product_status`) enable finer-grained queries when needed (e.g., "remediations for this specific purl_status") but are not required for the initial endpoint integration.

## Consequences

### Positive

- Users receive actionable remediation guidance alongside vulnerability status
- Follows Trustify's existing junction table pattern (e.g., `sbom_package_purl_ref`)
- Maintains proper data integrity with FK constraints and CASCADE delete
- Enables querying remediations independently ("all vendor_fix remediations")
- Supports multiple remediations per package (vendor_fix + workaround)

### Trade-offs

- Ingestion complexity: must track created status record IDs for junction tables
- Adding new remediation categories requires a database migration (ALTER TYPE)
- Phased rollout means some endpoints won't have remediation data initially

### Future Optimizations

- Can denormalize if query performance becomes an issue
- Expand to additional endpoints (Phase 2) as user needs are identified

## Related ADRs

- [ADR 00007](00007-purl-report.md): PURL vulnerability report - defines the `analyze` endpoint that will include remediations
- [ADR 00008](00008-purls-recommendation.md): PURL recommendations endpoint - this ADR fulfills its open item: "Ingest remediation information from advisories and use them to provide more data to results of this endpoint"
- [ADR 00010](00010-version-range-in-responses.md): Version range in responses - this ADR fulfills its future task: "Extract remediation information from advisories and add them to the responses"

## References

- CSAF v2.0 Spec: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3212-vulnerabilities-property---remediations
- Test data: [rhsa-2024-2705.json](../../etc/test-data/csaf/rhsa-2024-2705.json)
