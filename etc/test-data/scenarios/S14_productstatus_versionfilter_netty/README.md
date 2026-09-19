# S14 — Don't version-filter a bare component-in-product (netty)

Guards the discriminator for `product_status`: a bare component under a product CPE is scoped by
**CPE-context (product identity)**, not by comparing the component's version to the product's stream range
(standard §4.5/§5). The product range is the *product's* CPE-major stream, not the component's version
line — so version-matching drops genuine matches.

## Data (CVE-2021-37136)
`netty-codec-http` `known_affected` in **Red Hat Single Sign-On 7** (`cpe:/a:redhat:red_hat_single_sign_on:7`),
bare component → `product_status`, all versions affected (§8.1). The derived range `[7.0.0, 8.0.0)` describes
**RH-SSO 7**, not netty. SBOM declares the RH-SSO 7 CPE on its describing node and ships
`netty-codec-http@4.1.45.Final-redhat-00001`.

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM | describing CPE | netty-codec-http | CVE-2021-37136 |
|---|---|---|---|
| `sbom_netty_rhsso7` | `red_hat_single_sign_on:7` | `4.1.45.Final-redhat-00001` | affected |

- **Correct** — SBOM's describing CPE matches the advisory's product context (§5) → **affected** (bare KA;
  no version comparison is valid).
- **Why version-matching is wrong here** — comparing netty's installed `4.1.45…` against the range
  `[7.0.0, 8.0.0)` fails: netty's 4.1 line is unrelated to the RH-SSO **7** product stream. Filtering on it
  would drop a genuine match (false negative). The correct scope is product identity, not version.

## Relationship to other scenarios
- **S2** — same `product_status` shape, but the SBOM is *not* the product → not affected. S2 shows the leak
  to avoid; S14 shows the genuine match that a version-filter would wrongly drop.
- **S5** — where `version_matches` *is* correct: a versioned purl (`purl_status`, component-vs-component).
- **S11** — a bare `known_affected` with no product CPE → no matchable row at all (a different failure).

## Files
- SBOM: `sbom_netty_rhsso7.{cdx,spdx}.json`.
- Advisory: `vex/CVE-2021-37136.json` (Red Hat CSAF structure).
