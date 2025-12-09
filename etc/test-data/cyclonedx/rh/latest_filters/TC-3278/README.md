# Analysis of fresh_mix SBOM Structure

A test package has been injected in all of these:
  "pkg:rpm/redhat/openssl-synthetic-test@"

## Requirements Check

### ✅ 1. Product Types Present
- **RPM**: `webkit2gtk3` folder
- **Container**: `cnv-4.17` folder  
- **Maven**: `quarkus-3.20` folder

### ✅ 2. Two Releases with Same CPE

#### Maven (quarkus-3.20)
- ✅ Both files have the same CPE: `cpe:/a:redhat:quarkus:3.20::el8`
  - `28954C62C811417.json` (advisory 155081, version 3.20.3)
  - `EDA6638AD2F4451.json` (advisory 156615, version 3.20.4)

#### Container (cnv-4.17)
- ✅ Both product files have the same CPE: `cpe:/a:redhat:container_native_virtualization:4.17::el9`
  - `D05BF995974542F.json` (advisory 156271, tag v4.17.35-2)
  - `ED1F188BB5C94D8.json` (advisory 156526, tag v4.17.36-3)

#### RPM (webkit2gtk3)
- ⚠️ Both product files have the same CPEs, but they're RHEL CPEs, not RPM-specific:
  - `A9F140D67EB2408.json` (advisory 156970)
  - `7764C2C0C91542B.json` (advisory 154820)
  - Both have: `cpe:/a:redhat:enterprise_linux:9.7::appstream` and `cpe:/a:redhat:enterprise_linux:9::appstream`
  - **Note**: These are OS-level CPEs, not specific to the webkit2gtk3 RPM package

### ✅ 3. Nested/Linked SBOMs

#### Container (cnv-4.17)
- ✅ **Product SBOMs**: `D05BF995974542F.json`, `ED1F188BB5C94D8.json`
- ✅ **Image-index SBOMs**: `693F980C32C444A.json`, `CBE2989E64414F5.json`
  - Both are for `virt-handler-rhel9` image (same image name)
  - `693F980C32C444A.json`: tag v4.17.36-3
  - `CBE2989E64414F5.json`: tag v4.17.35-2
- ✅ **Binary SBOMs**: 4 files in `binary/` subdirectory
  - All are for `virt-handler-rhel9` image (same image name)
  - Different architectures (amd64, arm64, etc.)

#### RPM (webkit2gtk3)
- ✅ **Product SBOMs**: `A9F140D67EB2408.json`, `7764C2C0C91542B.json`
- ✅ **Release SBOMs**: `3705CE313B0F437.json`, `CC595A02EB3545E.json`
  - All are for `webkit2gtk3` package (same package name)
  - Product SBOMs reference the RPM package in their components
  - Release SBOMs contain detailed RPM package information

## Summary
1. All three product types are present (RPM, Container, Maven)
2. Two releases with same CPE exist for Maven and Container
3. Nested/linked SBOMs exist for both Container and RPM:
   - Container: Product → Image-index → Binary (all for same image name: `virt-handler-rhel9`)
   - RPM: Product → Release (all for same package name: `webkit2gtk3`)



