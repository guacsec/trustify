# S19 — Hardware identifiers (JBL Flip 4)

Correlation by product identifiers of hardware: SKUs, model and serial numbers. The advisory
states a firmware as affected *installed on* a device. The firmware matches by its model number;
the device's SKUs only tell which product the statement is about.

## Data

### HBSA-2025-0003 (CVE-2025-41725)

Based on Harman's published HBSA-2025-0003 (via CERT@VDE), reduced to the affected combination:
two of its 22 SKUs, without the fixed product (firmware 4.1.0 on the same device).

| product | identification |
|---|---|
| CSAFPID-11001 JBL Flip 4 (device) | SKUs `6925281924439`, `050036337366` |
| CSAFPID-21001 JBL Flip 4 Firmware `vers:semver/<4.1.0` | model number `Flip 4` |
| CSAFPID-31001 firmware `installed_on` device | SKUs `6925281924439`, `050036337366` |

`known_affected`: CSAFPID-31001.

### HBSA-2025-0004 (CVE-2026-50001)

Synthetic, modelled on HBSA-2025-0003, for CSAF wildcards: the device series has the SKU
`6925281*`, the firmware `vers:semver/<5.0.0` the model number `Flip ?`. `known_affected`: the
firmware installed on the series.

## How a relationship is read

A SKU or model number of hardware tells *where* a component is installed, not which version of it
(CSAF 2.0, 3.1.3.3.3 and 3.1.3.3.7). For a relationship, ingestion therefore:

- states only the component's identifiers as affected, here model number `Flip 4`;
- stores the platform (`JBL Flip 4`) as the product the statement is about, with the SKUs of the
  platform and of the relationship itself.

Correlation confirms that product if the component or anything above it in the SBOM has one of its
SKUs: the own node 1.0, a parent 0.9, decreasing per hop. Without that, the evidence keeps ×0.7 and
records the product as "not confirmed", with the SKUs which would have confirmed it.

## Expected

Two synthetic CycloneDX SBOMs of the same speaker:

- `sbom/jbl_flip4.cdx.json`: the device (SKUs, serial number), the firmware (`cdx:device:gs1:gmn`
  `Flip 4`, version 2.3.1) and a library, all depending on the root. The device is a sibling of
  the firmware.
- `sbom/jbl_flip4_assembly.cdx.json`: the firmware nested in the device, the library nested in the
  firmware. Nesting is ingested as *contains*.

| SBOM | CVE | component | verdict | product |
|---|---|---|---|---|
| `jbl_flip4` | CVE-2025-41725 | `comp-flip4-fw` | affected, 0.7 | not confirmed (`sku:050036337366, sku:6925281924439`) |
| `jbl_flip4` | CVE-2026-50001 | `comp-flip4-fw` | affected, 0.7 | not confirmed (`sku:6925281*`) |
| `jbl_flip4_assembly` | CVE-2025-41725 | `comp-flip4-fw` | affected, 0.9 | confirmed by the parent's SKUs |
| `jbl_flip4_assembly` | CVE-2026-50001 | `comp-flip4-fw` | affected, 0.9 | confirmed by the parent's SKU `6925281924439` |

The device itself gets no evidence: it isn't stated as affected. Querying a SKU finds nothing,
querying model number `Flip 5` finds CVE-2026-50001 (`Flip ?`).

Covered by `extractor/product_identifier`, `service/test.rs` and the CSAF loader test
`relationship_hardware_identifiers`.

## Known limitation

The product identifier rule ignores the firmware's version range: model number `Flip 4` matches
firmware 2.3.1 without checking `<4.1.0`. With the published HBSA-2025-0003, which also states
firmware 4.1.0 on the same device as `fixed` with the same model number, the firmware would get
both an affected and a fixed statement, whatever its version.

## Files

- SBOMs: `sbom/jbl_flip4.cdx.json`, `sbom/jbl_flip4_assembly.cdx.json` (synthetic)
- Advisories: `vex/hbsa-2025-0003.json` (reduced from the published one),
  `vex/hbsa-2025-0004.json` (synthetic)
