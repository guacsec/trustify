# pqc_strict.rego
# Allowlist: ML-KEM, ML-DSA, SLH-DSA only (all parameter sets)
# Everything else is a FAIL.

package pqc.strict

import future.keywords.in
import future.keywords.contains
import future.keywords.if

pqc_allowed := {"ML-KEM", "ML-DSA", "SLH-DSA"}

crypto_algorithms := [c |
    c := input.components[_]
    c.type == "cryptographic-asset"
    c.cryptoProperties.assetType == "algorithm"
]

violations contains v if {
    c := crypto_algorithms[_]
    family := c.cryptoProperties.algorithmProperties.algorithmFamily
    not family in pqc_allowed

    v := {
        "rule":      "NOT_PQC_APPROVED",
        "severity":  "FAIL",
        "component": c.name,
        "family":    family,
        "message":   sprintf("'%v' (family: %v) is not in the approved PQC set {ML-KEM, ML-DSA, SLH-DSA}.", [c.name, family]),
    }
}

compliant := count(violations) == 0

summary := {
    "compliant":       compliant,
    "total_algorithms": count(crypto_algorithms),
    "violation_count": count(violations),
    "violations":      violations,
}
