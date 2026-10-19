# S19 — Hardware identifiers (JBL Flip 4, Flip 5)

Correlation by product identifiers of hardware: SKUs, model and serial numbers. HBSA-2025-0003
states a firmware as affected *installed on* a device. The firmware matches by its model number and
its version; the device's SKUs only tell which product the statement is about. HBSA-2025-0002
states devices as affected by their own SKUs.

## Data

### HBSA-2025-0003 (CVE-2025-41725), published

Harman's advisory via CERT@VDE, unmodified:

| product | identification | versions |
|---|---|---|
| CSAFPID-11001 JBL Flip 4 (device) | 22 SKUs | — |
| CSAFPID-21001 JBL Flip 4 Firmware | model number `Flip 4` | `vers:semver/<4.1.0` |
| CSAFPID-22001 JBL Flip 4 Firmware | model number `Flip 4` | `4.1.0` |
| CSAFPID-31001 21001 `installed_on` 11001 | the 22 SKUs | — |
| CSAFPID-32001 22001 `installed_on` 11001 | the 22 SKUs | — |

`known_affected`: CSAFPID-31001, `fixed`: CSAFPID-32001.

### HBSA-2025-0002 (CVE-2024-2105), published

Harman's advisory via CERT@VDE, unmodified: JBL Flip 5, Flip 6, Pulse 4, Pulse 5, Boombox 2,
Boombox 3 and Xtreme 3, each a `product_name` with its SKUs, all `known_affected`, without versions.

### HBSA-2025-0004 (CVE-2026-50001), synthetic

Not published; the CVE is fictional. It is modelled on HBSA-2025-0003 to cover CSAF wildcards,
which no published advisory found uses: the device series has the SKU `6925281*`, the firmware
`vers:semver/<5.0.0` the model number `Flip ?`. `known_affected`: the firmware installed on the
series.

## How a relationship is read

A SKU or model number of hardware tells *where* a component is installed, not which version of it
(CSAF 2.0, 3.1.3.3.3 and 3.1.3.3.7). For a relationship, ingestion therefore:

- states only the component's identifiers, here model number `Flip 4`, with the component's
  versions (`<4.1.0` affected, `4.1.0` fixed);
- stores the platform (`JBL Flip 4`) as the product the statement is about, with the SKUs of the
  platform and of the relationship itself.

Correlation matches the model number, and then requires the component's own version to be in the
statement's versions. It confirms the product if the component or anything above it in the SBOM has
one of its SKUs: the own node 1.0, a parent 0.9, decreasing per hop. Without that, the evidence keeps
×0.7 and records the product as "not confirmed", with the SKUs which would have confirmed it.

## Expected

Synthetic CycloneDX SBOMs:

- `jbl_flip4.cdx.json`: the device (2 of the SKUs, serial number), the firmware 2.3.1
  (`cdx:device:gs1:gmn` `Flip 4`) and a library, all depending on the root. The device is a sibling
  of the firmware.
- `jbl_flip4_assembly.cdx.json`: the firmware 2.3.1 nested in the device, the library nested in the
  firmware. Nesting is ingested as *contains*.
- `jbl_flip4_assembly_fw_4.1.0.cdx.json`: the same with firmware 4.1.0.
- `jbl_flip5.cdx.json`: a Flip 5 device with one of its SKUs.

| SBOM | advisory | component | verdict | product |
|---|---|---|---|---|
| `jbl_flip4` | 0003 | `comp-flip4-fw` | affected, 0.7 | not confirmed (the 22 SKUs) |
| `jbl_flip4_assembly` | 0003 | `comp-flip4-fw` | affected, 0.9 | confirmed by the parent's SKUs |
| `jbl_flip4_assembly_fw_4.1.0` | 0003 | `comp-flip4-fw` | fixed, 0.9 | confirmed by the parent's SKUs |
| `jbl_flip5` | 0002 | `comp-flip5-device` | affected, 1.0 | — (stated for the device itself) |
| `jbl_flip4` | 0004 | `comp-flip4-fw` | affected, 0.7 | not confirmed (`sku:6925281*`) |

The Flip 4 device itself gets no evidence from HBSA-2025-0003: it isn't stated as affected. A
component without a version satisfies no version range.

Covered by `extractor/product_identifier`, `service/test.rs`, the CSAF loader test
`relationship_hardware_identifiers` and the CycloneDX test `firmware_is_package`.

## Files

- SBOMs: `sbom/*.cdx.json` (synthetic)
- Advisories: `vex/hbsa-2025-0002.json`, `vex/hbsa-2025-0003.json` (published, unmodified),
  `vex/hbsa-2025-0004.json` (synthetic)
