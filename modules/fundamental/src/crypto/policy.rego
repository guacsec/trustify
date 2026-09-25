package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Each entry in input.algorithms is:
#   { "node_id": str, "sbom_id": str, "name": str, "oid": str|null, "properties": obj }
#
# Conforma maps deny → violations, warn → warnings.
# The "node_id" field in each result's metadata is used by trustify to match
# violations back to individual AlgorithmPolicyResult rows.

deny contains result if {
    algo := input.algorithms[_]
    _is_non_compliant(algo)
    result := {
        "msg": sprintf("Algorithm '%v' is non-compliant (weak or broken)", [algo.name]),
        "node_id": algo.node_id,
    }
}

warn contains result if {
    algo := input.algorithms[_]
    not _is_pqc_safe(algo.name)
    not _is_non_compliant(algo)
    result := {
        "msg": sprintf("Algorithm '%v' is not PQC-safe (classical — consider migration)", [algo.name]),
        "node_id": algo.node_id,
    }
}

# ── PQC-safe detection ────────────────────────────────────────────────────────

_is_pqc_safe(name) if {
    normalized := upper(replace(name, "-", ""))
    some pattern in {"MLKEM", "KYBER", "MLDSA", "DILITHIUM", "SLHDSA", "SPHINCS"}
    contains(normalized, pattern)
}

# ── Non-compliant detection ───────────────────────────────────────────────────

_is_non_compliant(algo) if {
    normalized := upper(replace(algo.name, "-", ""))
    some pattern in {"MD5", "RC4", "RC2"}
    contains(normalized, pattern)
}

_is_non_compliant(algo) if {
    _is_sha1(algo.name)
}

# DES but not 3DES / Triple-DES / DESede
_is_non_compliant(algo) if {
    normalized := upper(replace(algo.name, "-", ""))
    contains(normalized, "DES")
    not contains(normalized, "3DES")
    not contains(normalized, "TDES")
    not contains(normalized, "TRIPLE")
    not contains(normalized, "DESEDE")
}

# RSA with key size <= 1024
_is_non_compliant(algo) if {
    normalized := upper(replace(algo.name, "-", ""))
    contains(normalized, "RSA")
    to_number(algo.properties.algorithmProperties.parameterSetIdentifier) <= 1024
}

# DSA (exact match) with key size <= 1024
_is_non_compliant(algo) if {
    upper(replace(algo.name, "-", "")) == "DSA"
    to_number(algo.properties.algorithmProperties.parameterSetIdentifier) <= 1024
}

# ── SHA-1 helper ──────────────────────────────────────────────────────────────
# Matches SHA1 / SHA-1 but NOT SHA128, SHA256, SHA384, SHA512, etc.

_is_sha1(name) if {
    normalized := upper(replace(name, "-", ""))
    # Contains "SHA1" not immediately followed by a digit
    regex.match(`.*SHA1([^0-9].*)?$`, normalized)
}
