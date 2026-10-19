# S24 — RHEL 10 minor streams: a real UBI 10 image (syft)

Real-world regression check for **RHEL 10 mainline minors** and **Red Hat `fixed` read as
`first_fixed`**. The SBOM is a syft scan of a UBI 10 based image (`distro=rhel-10.2`), trimmed to
four RPMs and the operating-system component (`cpe:2.3:o:redhat:enterprise_linux:10.2`).

RHEL 10 mainline products carry the minor in their CPE (`enterprise_linux:10.1`, `10.2`), while an
RPM's product from its PURL is `enterprise_linux:10`. The mainline minors are one line, so a
statement of another minor is used when the advisory states nothing for the build's own stream.
Extended support of a minor (`enterprise_linux_eus:10.0`, "E2S") is a separate product.

## Data — Red Hat VEX statements for RHEL 10

| CVE | Package | Statement (product → fixing build) |
|---|---|---|
| CVE-2026-19499 | glibc | `10.2` → `2.39-142.el10_2` |
| CVE-2026-5435 | glibc | `10.2` → `2.39-128.el10_2` |
| CVE-2026-0915 | glibc | `10.1` → `2.39-58.el10_1.7` (nothing for 10.2) |
| CVE-2026-40356 | krb5 | `10.2` → `1.21.3-10.el10_2` (source RPM only) |
| CVE-2025-3576 | krb5 | `10.0` → `1.21.3-8.el10_0` (source RPM only, nothing for 10.2) |
| CVE-2025-6170 | libxml2 | `10.2` → `2.12.5-10.el10_2.2`; `eus:10.0` → `2.12.5-9.el10_0.2` |
| CVE-2026-84782 | openssl | `10.2` → `1:3.5.8-2.el10_2` |

## Expected (component × CVE) — matches `expected.json`

| Component (installed) | Verdicts |
|---|---|
| `glibc` `2.39-128.el10_2` | CVE-2026-19499 affected (below the fix), CVE-2026-5435 fixed (at the fix), CVE-2026-0915 fixed (10.1 fix, older minor) |
| `krb5-libs` `1.21.3-10.el10_2` | CVE-2026-40356 fixed (at the fix), CVE-2025-3576 fixed (10.0 fix, older minor) |
| `libxml2` `2.12.5-10.el10_2.4` | CVE-2025-6170 fixed (above the 10.2 fix; the EUS statement is another product) |
| `openssl-libs` `1:3.5.8-1.el10_2` | CVE-2026-84782 affected (below the fix) |
| OS component `rhel` `10.2` | — (no verdict) |

## TODO

- [ ] **Statements of another minor.** CVE-2026-0915 states nothing for 10.2, as 10.2 had the fix
  from the beginning. Still, `glibc` `2.39-128.el10_2` gets `fixed` evidence (0.55) from the 10.1
  fix `2.39-58.el10_1.7` (`purl_fixed_as_first_fixed`, stream relation `minor`), where no evidence
  is expected. The same applies to CVE-2025-3576 (`krb5-libs`, a 10.0 fix used for 10.2). Decide
  if and how a statement of another minor applies (never; only below its fix; only from a newer
  minor), then update the expectations above and `expected.json`.

## Files

- SBOM: `sbom/ubi10_syft.cdx.json` (syft 1.54.0, trimmed; syft properties removed).
- Advisories: `vex/*.json.xz` (Red Hat CSAF VEX, as published).
