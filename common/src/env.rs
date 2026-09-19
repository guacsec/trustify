use std::env::VarError;

/// Abstraction over the environment variable lookup mechanism, injectable for testing.
pub trait EnvSource {
    fn lookup(&self, name: &str) -> Result<String, VarError>;
}

impl EnvSource for () {
    fn lookup(&self, name: &str) -> Result<String, VarError> {
        std::env::var(name)
    }
}

impl EnvSource for &[(&str, &str)] {
    fn lookup(&self, name: &str) -> Result<String, VarError> {
        self.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.to_string())
            .ok_or(VarError::NotPresent)
    }
}

impl<const N: usize> EnvSource for &[(&str, &str); N] {
    fn lookup(&self, name: &str) -> Result<String, VarError> {
        self.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.to_string())
            .ok_or(VarError::NotPresent)
    }
}
