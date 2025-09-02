# 00009. Create New Field in License

Date: 2025-07-27

## Status

DRAFT

## Context

In the new license search requirements, there is a section called license summary, which requires collecting usage statistics for all licenses that appear, including how many packages and SBOMs use each license.

## The Current Status of Licenses in Trustify

Currently, Trustify's support for licenses is as follows:

In SPDX, there are two types of licenses: licenseDeclared and licenseConcluded, and the representation is mainly in the form of license expressions, which can include custom license references (licenseRef).

CycloneDX uses only one type, licenseDeclared, but offers three ways to represent it:

- ID: This is a standard SPDX license ID.
- License expression: Similar to SPDX, it supports license expressions.
- Name: This is similar to a custom license reference, allowing for user-defined license names.

In Trustify, the handling is as follows:

When processing SPDX, Trustify parses the license expression into standard SPDX license IDs and exceptions, and stores them in spdx_licenses and spdx_license_exceptions. All custom license references (LicenseRef) are filtered out, while the original expression is preserved in the text field.

When processing CycloneDX, there are three scenarios:

- If the license is an ID, the value is saved directly in the text field and spdx_licenses.
- If the license is a name: The value is saved directly in the text field, stores them in spdx_licenses.
- If the license is an expression: Trustify parses it into standard SPDX license IDs and exceptions, stores them in spdx_licenses and spdx_license_exceptions, and also preserves the original expression in the text field.

## The Current Issue

- In SPDX, when a license expression contains a custom license ID, Trustify also saves it only in a text field, and filters out the custom license ID during the process of parsing it into standard SPDX license IDs and exceptions.
- In SPDX, when a license expression includes a custom license ID, the custom license ID itself is meaningless and only has significance within the current SBOM, so it cannot be used for statistics or searches.

## Decision

Add a new field named `custom_license_refs` to the license table. Its type is a list, which includes licenses of type name appearing in CycloneDX, as well as license expressions that contain custom licenses in SPDX.

```sql
ALTER TABLE license ADD COLUMN custom_license_refs text[];
ALTER TABLE license ADD COLUMN custom_document_license_refs text[];
```
### The current table structure vs. the changed table structure

- Current table structure
```rust
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize)]
#[sea_orm(table_name = "license")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub text: String,
    pub spdx_licenses: Option<Vec<String>>,
    pub spdx_license_exceptions: Option<Vec<String>>,
}
```

- Changed table structure

```rust
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize)]
#[sea_orm(table_name = "license")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub text: String,
    pub spdx_licenses: Option<Vec<String>>,
    pub spdx_license_exceptions: Option<Vec<String>>,
    pub custom_license_refs: Option<Vec<String>>,
}
```

### SPDX

License expression:

```json
{
  "SPDXID": "SPDXRef-2a02a923-8a04-489d-9cbc-80f2d23de5ea",
  "copyrightText": "NOASSERTION",
  "downloadLocation": "https://access.redhat.com/downloads/content/package-browser",
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE_MANAGER",
      "referenceLocator": "pkg:rpm/redhat/foreman-bootloaders-redhat@202102220000-1.el8sat?arch=src",
      "referenceType": "purl"
    }
  ],
  "filesAnalyzed": false,
  "licenseConcluded": "NOASSERTION",
  "licenseDeclared": "LicenseRef-2 AND LicenseRef-11 AND LicenseRef-BSD",
  "name": "foreman-bootloaders-redhat",
  "originator": "NOASSERTION",
  "packageFileName": "foreman-bootloaders-redhat-202102220000-1.el8sat.src.rpm",
  "supplier": "Organization: Red Hat",
  "versionInfo": "202102220000-1.el8sat"
}
```

Custom licenses:

```json
[
  {
    "comment": "External License Info is obtained from a build system which predates the SPDX specification and is not strict in accepting valid SPDX licenses.",
    "extractedText": "The license info found in the package meta data is: GPLv2+. See the specific package info in this SPDX document or the package itself for more details.",
    "licenseId": "LicenseRef-2",
    "name": "GPLv2+"
  },
  {
    "comment": "External License Info is obtained from a build system which predates the SPDX specification and is not strict in accepting valid SPDX licenses.",
    "extractedText": "The license info found in the package meta data is: GPLv3+. See the specific package info in this SPDX document or the package itself for more details.",
    "licenseId": "LicenseRef-11",
    "name": "GPLv3+"
  },
  {
    "comment": "External License Info is obtained from a build system which predates the SPDX specification and is not strict in accepting valid SPDX licenses.",
    "extractedText": "The license info found in the package meta data is: BSD. See the specific package info in this SPDX document or the package itself for more details.",
    "licenseId": "LicenseRef-BSD",
    "name": "BSD"
  }
]
```

`custom_license_refs`: Concatenate the custom license ID and the custom license name with a colon (":").

```json
{
  "LicenseRef-2:GPLv2+",
  "LicenseRef-11:GPLv3+",
  "LicenseRef-BSD:BSD",
}
```

## Consequences
- Positive: Enables complete license statistics and search functionality
- Negative: Increases storage overhead and requires data migration handling

## Alternatives Considered
- Using JSONB to store complete license mappings (rejected: high query complexity)
- Maintaining status quo without handling custom licenses (rejected: fails business requirements)

## Success Metrics
- Ability to count packages containing custom licenses
- Support for searching by custom license ID


## Known Issues

There are two types of custom licenses:

- Ones that are defined within the current SBOM, for example those with the "LicenseRef" prefix.
- Ones that reference other SBOM documents, for example those with the "DocumentRef" prefix.

Previously, we only handled the first type of custom license. The second type cannot be processed currently.
If we want to handle the second type, we need to add a new field, `custom_document_license_refs`, to store the complete reference, such as "DocumentRef-spdx-tool-1.2:LicenseRef-BSD"[1], in this field.

[1] Where "DocumentRef" is the prefix and "spdx-tool-1.2" refers to another SPDX SBOM, "LicenseRef-BSD" is the custom license reference within that SBOM.
