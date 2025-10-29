# 00010. Add Version Range to purl status responses

## Status

APPROVED

## Context

The current API responses for `PurlStatus` and `AnalysisDetails` lack explicit version range information. This makes it difficult for clients to understand the precise version range for which a particular status or vulnerability analysis is relevant. To improve clarity and provide more context, the version range should be included in these API responses. This will also allow API clients and UI to provide first information about vulnerability remediation.

## Details

Currently, `PurlStatus` is used in `PurlDetails` to show the status of a package, and `AnalysisDetails` provides a map of statuses to advisories. Both would benefit from having explicit version range information for the status.

The current `AnalysisDetails` response looks like this:

```json
{
  "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar": [
    {
      "normative": true,
      "identifier": "CVE-2022-42003",
      "title": "In FasterXML jackson-databind before versions 2.13.4.1 and 2.12.17.1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.",
      "description": "In FasterXML jackson-databind before versions 2.13.4.1 and 2.12.17.1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.",
      "status": {
        "affected": [
          {
            "uuid": "urn:uuid:355800f5-7dc0-4ccd-9b67-4a3376c9aa27",
            "identifier": "GHSA-jjjh-jjxp-wpff",
            "document_id": "GHSA-jjjh-jjxp-wpff",
            "title": "Uncontrolled Resource Consumption in Jackson-databind",
          }
        ]
      }
    }
  ]
}
```

This response is not ideal because it doesn't clearly indicate the version range for which the vulnerability is applicable. It also doesn't provide a clear path to remediation.

The advisory `GHSA-jjjh-jjxp-wpff` contains the following information about affected versions:

```json
"affected": [
  {
    "package": {
      "ecosystem": "Maven",
      "name": "com.fasterxml.jackson.core:jackson-databind"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          { "introduced": "2.4.0-rc1" },
          { "fixed": "2.12.7.1" }
        ]
      }
    ]
  },
  {
    "package": {
      "ecosystem": "Maven",
      "name": "com.fasterxml.jackson.core:jackson-databind"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          { "introduced": "2.13.0" },
          { "fixed": "2.13.4.2" }
        ]
      }
    ]
  }
]
```

This information should be reflected in the API response.

## Decision

We will introduce a new `VersionRange` struct to represent version ranges in a structured way. This struct will be used in both `PurlStatus` and `AnalysisDetails` to provide consistent and clear versioning information.

### 1. Create a `VersionRange` Struct

A new struct `VersionRange` can be created in `modules/fundamental/src/purl/model/details/version_range.rs` and mirror the database schema. Something along the lines of

```rust
// modules/fundamental/src/purl/model/details/version_range.rs

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
enum VersionRange {
  Full {
    left: String,
    left_inclusive: bool,
    right: String,
    right_inclusive: bool,
  },
  Left {
    left: String,
    left_inclusive: String,
  },
  Right {
    right: String,
    right_inclusive: bool,
 }
}
```

### 2. Enhance `PurlStatus`

The `PurlStatus` struct will be updated to include the `VersionRange`.

```rust
// modules/fundamental/src/purl/model/details/purl.rs
use super::version_range::VersionRange;

#[derive(Serialize, Deserialize, Debug, ToSchema, PartialEq)]
pub struct PurlStatus {
    pub vulnerability: VulnerabilityHead,
    pub average_severity: Severity,
    pub average_score: f64,
    pub status: String,
    #[schema(required)]
    pub context: Option<StatusContext>,
    pub version_range: Option<VersionRange>,
}
```

### 3. Refactor `AnalysisDetails`

The `AnalysisDetails` struct will be refactored to replace the `status` map with a list of `PurlStatus` objects, aligning it with the `PurlDetails` response and simplifying the structure.

```rust
// modules/fundamental/src/vulnerability/model/analyze.rs
use crate::purl::model::details::purl::PurlStatus;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct AnalysisDetails {
    #[serde(flatten)]
    pub head: VulnerabilityHead,
    pub purl_statuses: Vec<PurlStatus>,
}
```

The `AnalysisAdvisory` struct will be removed as it is no longer needed.

The `PurlAdvisory` struct will also be updated to include the `PurlStatus` with the `version_range`.

```rust
// modules/fundamental/src/purl/model/details/purl.rs

#[derive(Serialize, Deserialize, Debug, ToSchema, PartialEq)]
pub struct PurlAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub status: Vec<PurlStatus>,
}
```

### 4. Data Flow

The database queries and service logic will be updated to fetch and propagate the `version_range` information correctly, ensuring it is available in both `PurlDetails` and `AnalysisDetails` responses.

With these changes, the `AnalysisDetails` response will look something like this:

```json
{
  "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar": [
    {
      "normative": true,
      "identifier": "CVE-2022-42003",
      "title": "In FasterXML jackson-databind before versions 2.13.4.1 and 2.12.17.1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.",
      "description": "In FasterXML jackson-databind before versions 2.13.4.1 and 2.12.17.1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.",
      "purl_statuses": [
        {
          "vulnerability": { ... },
          "status": "affected",
          "version_range": {
            "version_scheme_id": "semver",
            "low_version": "2.13.0",
            "low_inclusive": true,
            "high_version": "2.13.4.2",
            "high_inclusive": false
          }
        },
        {
          "vulnerability": { ... },
          "status": "fixed",
          "version_range": {
            "version_scheme_id": "semver",
            "low_version": "2.13.4.2",
            "low_inclusive": true,
            "high_version": null,
            "high_inclusive": false
          }
        }
      ]
    }
  ]
}
```

And the `PurlAdvisory` response will look like this:

```json
{
  "uuid": "urn:uuid:355800f5-7dc0-4ccd-9b67-4a3376c9aa27",
  "identifier": "GHSA-jjjh-jjxp-wpff",
  "document_id": "GHSA-jjjh-jjxp-wpff",
  "title": "Uncontrolled Resource Consumption in Jackson-databind",
  "status": [
    {
      "vulnerability": { ... },
      "status": "affected",
      "version_range": {
        "version_scheme_id": "semver",
        "low_version": "2.13.0",
        "low_inclusive": true,
        "high_version": "2.13.4.2",
        "high_inclusive": false
      }
    }
  ]
}
```

Note that all statuses don't need to be present in responses as that depends on the actual query that is used.

## Consequences

*   The API will provide clearer, more consistent, and strongly-typed version range information.
*   Clients will be able to determine the exact version range for which a status or vulnerability is relevant.
*   The `AnalysisDetails` response will be more consistent with `PurlDetails`, improving API usability.
*   The `AnalysisAdvisory` struct will be removed, simplifying the codebase.
*   The API will be able to provide remediation information by including `PurlStatus` objects with a `status` of `"fixed"` and a `version_range` that specifies the versions in which the fix is available.
*   There should be no performance degradation of current APIs as this information is already returned by the queries.

## Future tasks

*   Extract remediation information from advisories and add them to the responses.
*   Evaluate if we can find recommended purls that match remediation information.