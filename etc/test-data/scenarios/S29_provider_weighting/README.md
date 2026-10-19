# S29 — Installed build provider precedence

Synthetic documents; CVE-2026-99992 is a test identifier. One CVE has provider A CNA affected evidence and provider B ADP not-affected evidence about the same package. A providerless OSV record also states affected. The A bundle contains an A build of upstream B software, a component supplied directly by B, and a component inheriting the bundle supplier.

Configure aliases `name:Provider A` → `A` and `name:Provider B` → `B`. Both SBOM formats and ingestion orders must yield affected for the A build and inherited build, and not_affected for the B build. All three sources remain visible. Fixed provider precedence and temporary provider context are exercised by the service tests; alias changes re-resolve existing evidence, and counts and preview explanations agree with ordinary resolution. Conflicts remain visible without reducing the selected match confidence.
