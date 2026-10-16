# S29 — Installed build provider weighting

Synthetic documents; CVE-2026-99992 is a test identifier. One CVE has provider A CNA affected evidence and provider B ADP not-affected evidence about the same package. A providerless OSV record also states affected. The A bundle contains an A build of upstream B software, a component supplied directly by B, and a component inheriting the bundle supplier.

Configure aliases `name:Provider A` → `A` and `name:Provider B` → `B`. Both SBOM formats and ingestion orders must yield affected for the A build and inherited build, and not_affected for the B build. All three sources remain visible. Request, component, SBOM, group and instance weights are exercised by the service tests; counts and preview explanations must agree with ordinary resolution.
