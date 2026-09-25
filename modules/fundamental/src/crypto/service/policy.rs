use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Compliant,
    Warning,
    NonCompliant,
}

struct AlgorithmProps<'a> {
    parameter_set_identifier: Option<&'a str>,
}

impl<'a> AlgorithmProps<'a> {
    fn from_value(v: &'a serde_json::Value) -> Self {
        let ap = &v["algorithmProperties"];
        Self {
            parameter_set_identifier: ap["parameterSetIdentifier"].as_str(),
        }
    }

    fn key_size(&self) -> Option<u32> {
        self.parameter_set_identifier
            .and_then(|s| s.parse::<u32>().ok())
    }
}

pub fn evaluate_algorithm(name: &str, properties: &serde_json::Value) -> PolicyVerdict {
    let upper = name.to_uppercase();
    let props = AlgorithmProps::from_value(properties);

    // PQC-safe algorithms → Compliant
    if is_pqc_safe(&upper) {
        return PolicyVerdict::Compliant;
    }

    // Weak/broken algorithms → NonCompliant
    if is_weak(&upper, &props) {
        return PolicyVerdict::NonCompliant;
    }

    // Everything else (classical in transition + unknown) → Warning
    PolicyVerdict::Warning
}

fn is_pqc_safe(upper_name: &str) -> bool {
    let normalized = upper_name.replace('-', "");
    let pqc_patterns = ["MLKEM", "KYBER", "MLDSA", "DILITHIUM", "SLHDSA", "SPHINCS"];
    pqc_patterns
        .iter()
        .any(|pattern| normalized.contains(pattern))
}

fn is_weak(upper_name: &str, props: &AlgorithmProps<'_>) -> bool {
    let normalized = upper_name.replace('-', "");

    if normalized.contains("MD5") || normalized.contains("RC4") || normalized.contains("RC2") {
        return true;
    }

    // SHA-1 / SHA1 but not SHA-128, SHA-256, etc.
    if is_sha1(&normalized) {
        return true;
    }

    // DES but not 3DES / Triple-DES / DESede
    if normalized.contains("DES")
        && !normalized.contains("3DES")
        && !normalized.contains("TDES")
        && !normalized.contains("TRIPLE")
        && !normalized.contains("DESEDE")
    {
        return true;
    }

    // RSA / DSA with small key size
    if (normalized.contains("RSA") || normalized == "DSA")
        && matches!(props.key_size(), Some(size) if size <= 1024)
    {
        return true;
    }

    false
}

fn is_sha1(normalized: &str) -> bool {
    // Match SHA1 but not SHA128, SHA256, SHA384, SHA512, etc.
    if let Some(pos) = normalized.find("SHA1") {
        let after = &normalized[pos + 4..];
        return after.is_empty() || !after.starts_with(|c: char| c.is_ascii_digit());
    }
    false
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;
    use test_log::test;

    fn props_with_param(param: &str) -> serde_json::Value {
        json!({
            "algorithmProperties": {
                "parameterSetIdentifier": param
            }
        })
    }

    fn props_with_primitive(primitive: &str) -> serde_json::Value {
        json!({
            "algorithmProperties": {
                "primitive": primitive
            }
        })
    }

    fn empty_props() -> serde_json::Value {
        json!({})
    }

    #[test]
    fn pqc_algorithms_are_compliant() {
        let props = empty_props();
        assert_eq!(
            evaluate_algorithm("ML-KEM", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("ML-KEM-768", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("MLKEM", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("Kyber", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("ML-DSA", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("MLDSA-65", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("Dilithium", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("SLH-DSA", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("SLHDSA", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("SPHINCS+", &props),
            PolicyVerdict::Compliant
        );
    }

    #[test]
    fn pqc_case_insensitive() {
        let props = empty_props();
        assert_eq!(
            evaluate_algorithm("ml-kem", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("kyber", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("ml-dsa", &props),
            PolicyVerdict::Compliant
        );
        assert_eq!(
            evaluate_algorithm("slh-dsa", &props),
            PolicyVerdict::Compliant
        );
    }

    #[test]
    fn weak_algorithms_are_noncompliant() {
        let props = empty_props();
        assert_eq!(
            evaluate_algorithm("MD5", &props),
            PolicyVerdict::NonCompliant
        );
        assert_eq!(
            evaluate_algorithm("RC4", &props),
            PolicyVerdict::NonCompliant
        );
        assert_eq!(
            evaluate_algorithm("RC2", &props),
            PolicyVerdict::NonCompliant
        );
        assert_eq!(
            evaluate_algorithm("DES", &props),
            PolicyVerdict::NonCompliant
        );
    }

    #[test]
    fn sha1_is_noncompliant() {
        let props = props_with_primitive("hash");
        assert_eq!(
            evaluate_algorithm("SHA1", &props),
            PolicyVerdict::NonCompliant
        );
        assert_eq!(
            evaluate_algorithm("SHA-1", &props),
            PolicyVerdict::NonCompliant
        );
        // SHA-256 and SHA-512 should NOT be non-compliant
        assert_eq!(evaluate_algorithm("SHA256", &props), PolicyVerdict::Warning);
        assert_eq!(evaluate_algorithm("SHA512", &props), PolicyVerdict::Warning);
        assert_eq!(
            evaluate_algorithm("SHA-384", &props),
            PolicyVerdict::Warning
        );
    }

    #[test]
    fn des_but_not_3des() {
        let props = empty_props();
        assert_eq!(
            evaluate_algorithm("DES", &props),
            PolicyVerdict::NonCompliant
        );
        assert_eq!(evaluate_algorithm("3DES", &props), PolicyVerdict::Warning);
        assert_eq!(
            evaluate_algorithm("Triple-DES", &props),
            PolicyVerdict::Warning
        );
    }

    #[test]
    fn rsa_key_size_discrimination() {
        assert_eq!(
            evaluate_algorithm("RSA", &props_with_param("1024")),
            PolicyVerdict::NonCompliant
        );
        assert_eq!(
            evaluate_algorithm("RSA", &props_with_param("512")),
            PolicyVerdict::NonCompliant
        );
        assert_eq!(
            evaluate_algorithm("RSA", &props_with_param("2048")),
            PolicyVerdict::Warning
        );
        assert_eq!(
            evaluate_algorithm("RSA", &props_with_param("4096")),
            PolicyVerdict::Warning
        );
        // RSA without key size info defaults to Warning
        assert_eq!(
            evaluate_algorithm("RSA", &empty_props()),
            PolicyVerdict::Warning
        );
    }

    #[test]
    fn classical_algorithms_are_warning() {
        let props = empty_props();
        assert_eq!(evaluate_algorithm("ECDSA", &props), PolicyVerdict::Warning);
        assert_eq!(evaluate_algorithm("ECDH", &props), PolicyVerdict::Warning);
        assert_eq!(
            evaluate_algorithm("Ed25519", &props),
            PolicyVerdict::Warning
        );
        assert_eq!(evaluate_algorithm("AES", &props), PolicyVerdict::Warning);
        assert_eq!(
            evaluate_algorithm("AES-128-GCM", &props),
            PolicyVerdict::Warning
        );
    }

    #[test]
    fn unknown_algorithms_default_to_warning() {
        let props = empty_props();
        assert_eq!(
            evaluate_algorithm("SomeUnknownAlgo", &props),
            PolicyVerdict::Warning
        );
        assert_eq!(
            evaluate_algorithm("CHACHA20", &props),
            PolicyVerdict::Warning
        );
    }

    #[test]
    fn keycloak_cbom_algorithms() {
        // Real algorithms from keycloak-cbom.json fixture
        assert_eq!(
            evaluate_algorithm(
                "SHA1",
                &json!({
                    "algorithmProperties": {
                        "primitive": "hash",
                        "parameterSetIdentifier": "160"
                    }
                })
            ),
            PolicyVerdict::NonCompliant
        );
        assert_eq!(
            evaluate_algorithm(
                "ECDH",
                &json!({
                    "algorithmProperties": {
                        "primitive": "key-agree"
                    }
                })
            ),
            PolicyVerdict::Warning
        );
        assert_eq!(
            evaluate_algorithm(
                "EC-secp521r1",
                &json!({
                    "algorithmProperties": {
                        "primitive": "pke",
                        "curve": "secp521r1"
                    }
                })
            ),
            PolicyVerdict::Warning
        );
    }

    #[test]
    fn missing_properties_handled() {
        assert_eq!(
            evaluate_algorithm("AES", &json!(null)),
            PolicyVerdict::Warning
        );
        assert_eq!(
            evaluate_algorithm("AES", &json!({})),
            PolicyVerdict::Warning
        );
        assert_eq!(
            evaluate_algorithm("RSA", &json!(null)),
            PolicyVerdict::Warning
        );
    }
}
