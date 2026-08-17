use serde::Deserialize;

/// The CISA KEV catalog document, as served at
/// <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevCatalog {
    pub title: Option<String>,
    /// Required, unlike the other descriptive fields, because format detection
    /// keys on it: `vulnerabilities` alone is too generic a top-level key to
    /// fingerprint a catalog with (CSAF documents carry one too). Detection may
    /// only rely on fields the schema treats as mandatory, or a document could
    /// parse yet never be recognised without an explicit format hint.
    pub catalog_version: String,
    pub date_released: Option<String>,
    pub count: Option<u64>,
    pub vulnerabilities: Vec<KevEntry>,
}

/// A single vulnerability entry of a KEV catalog.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    pub vendor_project: Option<String>,
    pub product: Option<String>,
    pub vulnerability_name: Option<String>,
    pub date_added: Option<String>,
    pub short_description: Option<String>,
    pub required_action: Option<String>,
    pub due_date: Option<String>,
    pub known_ransomware_campaign_use: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub cwes: Vec<String>,
}
