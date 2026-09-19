use serde::de::DeserializeOwned;

/// Abstraction over JSON input sources, allowing code to accept both
/// raw bytes and pre-parsed `serde_json::Value` uniformly.
pub trait JsonSource {
    /// Deserialize a value of type `T` from this JSON source.
    fn parse_json<T: DeserializeOwned>(self) -> Result<T, serde_json::Error>;
}

impl JsonSource for &[u8] {
    fn parse_json<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(self)
    }
}

impl JsonSource for serde_json::Value {
    fn parse_json<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self)
    }
}
