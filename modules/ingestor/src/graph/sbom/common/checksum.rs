use serde_cyclonedx::cyclonedx::v_1_6::{Hash, HashAlg};
use spdx_rs::models::Algorithm;
use std::borrow::Cow;

/// Common type for working with checksum value and type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checksum {
    pub r#type: Cow<'static, str>,
    pub value: String,
}

impl Checksum {
    pub const NONE: [Self; 0] = [];
}

impl From<Hash> for Checksum {
    fn from(value: Hash) -> Self {
        Self {
            r#type: match value.alg {
                HashAlg::Md5 => "MD5",
                HashAlg::Sha1 => "SHA-1",
                HashAlg::Sha256 => "SHA-256",
                HashAlg::Sha384 => "SHA-384",
                HashAlg::Sha512 => "SHA-512",
                HashAlg::Sha3256 => "SHA3-256",
                HashAlg::Sha3384 => "SHA3-384",
                HashAlg::Sha3512 => "SHA3-512",
                HashAlg::Blake2B256 => "BLAKE2b-256",
                HashAlg::Blake2B384 => "BLAKE2b-384",
                HashAlg::Blake2B512 => "BLAKE2b-512",
                HashAlg::Blake3 => "BLAKE3",
            }
            .into(),
            value: value.content,
        }
    }
}

impl From<(Algorithm, String)> for Checksum {
    fn from(value: (Algorithm, String)) -> Self {
        Self {
            r#type: match value.0 {
                Algorithm::SHA1 => "SHA-1",
                Algorithm::SHA224 => "SHA-224",
                Algorithm::SHA256 => "SHA-256",
                Algorithm::SHA384 => "SHA-384",
                Algorithm::SHA512 => "SHA-512",
                Algorithm::MD2 => "MD2",
                Algorithm::MD4 => "MD4",
                Algorithm::MD5 => "MD5",
                Algorithm::MD6 => "MD6",
                Algorithm::SHA3256 => "SHA3-256",
                Algorithm::SHA3384 => "SHA3-384",
                Algorithm::SHA3512 => "SHA3-512",
                Algorithm::BLAKE2B256 => "BLAKE2b-256",
                Algorithm::BLAKE2B384 => "BLAKE2b-384",
                Algorithm::BLAKE2B512 => "BLAKE2b-512",
                Algorithm::BLAKE3 => "BLAKE3",
                Algorithm::ADLER32 => "ADLER32",
            }
            .into(),
            value: value.1,
        }
    }
}

impl From<spdx_rs::models::Checksum> for Checksum {
    fn from(value: spdx_rs::models::Checksum) -> Self {
        (value.algorithm, value.value).into()
    }
}
