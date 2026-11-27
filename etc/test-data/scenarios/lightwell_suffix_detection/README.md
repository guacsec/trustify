# lightwell_suffix_detection — all three `rhlw` suffix shapes are detected

Snapshot: `lightwell-osv` @ `ae0cbae` (2026-11-13, 288 advisories). Rule: `--rule scoped`.
Encodes `docs/README.md` §6.2 — **and records a defect in it.**

No subject in the directory name: this scenario covers the whole dataset rather than one package.

## The defect

Docs §6.2 describes the remediated-build marker as the literal `.rhlw-NNNNN`. The snapshot contains
three distinct shapes:

| Shape | Count | Example |
|---|---|---|
| `.rhlw-` | 239 | `6.0.3.rhlw-00001` |
| `-rhlw-` | 31 | `4.1.132.Final-rhlw-00002` |
| `+rhlw.` | 18 | `3.0.1+rhlw.1` |

A literal `.rhlw-` rule misses **49 of 288 records (17%)**. The rule must normalize to a
case-insensitive `rhlw` **token**, not a literal separator-plus-`rhlw-` string.

This matters beyond parsing: suffix detection is what lets a consumer resolve the contradiction in
`lightwell_upstream_false_positive_woodstox`. A build whose suffix is not recognised is treated as
a plain upstream version, and the false positive stands.

## Data
One advisory per shape, so that all three are exercised in a single correlation run:

| Shape | Advisory | Provenance |
|---|---|---|
| `.rhlw-` | `advisories/RHLW-2026-403d1e66c95ef9bb.json` | vendored verbatim |
| `-rhlw-` | `../../osv/RHLW-2026-02416b185203289c.json` | **reused** existing Trustify fixture |
| `+rhlw.` | `../../osv/RHLW-2026-821eaab8409c2a61.json` | **reused** existing Trustify fixture |

The two reused records are already exercised for *ingestion* by
`modules/ingestor/tests/osv_lightwell.rs::lightwell_native_ranges`; this scenario adds the
*correlation* half without vendoring a second copy.

## Expected (component × advisory) — matches `expected.json`
| Shape | Component | Version | Verdict |
|---|---|---|---|
| `.rhlw-` | `woodstox-6.0.3` | `6.0.3` | `…403d` affected |
| `.rhlw-` | `woodstox-6.0.3-rhlw` | `6.0.3.rhlw-00001` | — |
| `-rhlw-` | `netty-4.1.132` | `4.1.132.Final` | `…0241` affected |
| `-rhlw-` | `netty-4.1.132-rhlw` | `4.1.132.Final-rhlw-00002` | — |
| `+rhlw.` | `pypdf2-3.0.1` | `3.0.1` | `…821e` affected |
| `+rhlw.` | `pypdf2-3.0.1-rhlw` | `3.0.1+rhlw.1` | — |

Each shape contributes one affected base and one excluded remediated build. The three "—" rows are
the assertion: for every shape, the remediated build must sort **above** its base and fall outside
the exclusive `fixed` bound.

## Related ordering guard (plan §6.2)

The `-rhlw-` shape is the fragile one. `mavenver_cmp_up.sql` decides qualifier ordering with
`if array_length(left_parts,1) > 3 then return -1 else return +1`. The `>3` heuristic is correct
for the four-component `.Final-rhlw-` forms that make up all 31 current hyphen records, and wrong
for a plain three-component base with a hyphen suffix. See
`modules/ingestor/tests/version/mavenver.rs` for the guard that pins this.
