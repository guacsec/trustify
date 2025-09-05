use bytesize::ByteSize;
use std::{collections::HashSet, time::Duration};
use trustify_module_importer::model::{
    ClearlyDefinedImporter, ClearlyDefinedPackageType, CveImporter, CweImporter,
    DEFAULT_SOURCE_CLEARLY_DEFINED_CURATION, DEFAULT_SOURCE_CVEPROJECT, DEFAULT_SOURCE_CWE_CATALOG,
    DEFAULT_SOURCE_QUAY, QuayImporter,
};
use trustify_module_importer::{
    model::{
        ClearlyDefinedCurationImporter, CommonImporter, CsafImporter,
        DEFAULT_SOURCE_CLEARLY_DEFINED, ImporterConfiguration, OsvImporter, SbomImporter,
    },
    service::{Error, ImporterService},
};
use url::Url;

async fn add(
    importer: &ImporterService,
    name: &str,
    config: ImporterConfiguration,
) -> anyhow::Result<()> {
    Ok(importer
        .create(name.into(), config)
        .await
        .or_else(|err| match err {
            Error::AlreadyExists => Ok(()),
            err => Err(err),
        })?)
}

async fn add_osv(
    importer: &ImporterService,
    name: &str,
    source: &str,
    base: Option<&str>,
    branch: Option<&str>,
    start_year: Option<u16>,
    description: &str,
) -> anyhow::Result<()> {
    add(
        importer,
        name,
        ImporterConfiguration::Osv(OsvImporter {
            common: CommonImporter {
                disabled: true,
                period: Duration::from_secs(300),
                description: Some(description.into()),
                labels: Default::default(),
            },
            source: source.to_string(),
            branch: branch.map(ToString::to_string),
            path: base.map(|s| s.into()),
            years: Default::default(),
            start_year,
        }),
    )
    .await
}

async fn add_cve(
    importer: &ImporterService,
    name: &str,
    start_year: Option<u16>,
    description: &str,
) -> anyhow::Result<()> {
    add(
        importer,
        name,
        ImporterConfiguration::Cve(CveImporter {
            common: CommonImporter {
                disabled: true,
                period: Duration::from_secs(300),
                description: Some(description.into()),
                labels: Default::default(),
            },
            source: DEFAULT_SOURCE_CVEPROJECT.into(),
            years: HashSet::default(),
            start_year,
        }),
    )
    .await
}

async fn add_clearly_defined_curations(
    importer: &ImporterService,
    name: &str,
    description: &str,
) -> anyhow::Result<()> {
    add(
        importer,
        name,
        ImporterConfiguration::ClearlyDefinedCuration(ClearlyDefinedCurationImporter {
            common: CommonImporter {
                disabled: true,
                // once an hour is plenty
                period: Duration::from_secs(60 * 60),
                description: Some(description.into()),
                labels: Default::default(),
            },
            source: DEFAULT_SOURCE_CLEARLY_DEFINED_CURATION.into(),
            types: ClearlyDefinedPackageType::all(),
        }),
    )
    .await
}

async fn add_clearly_defined(
    importer: &ImporterService,
    name: &str,
    description: &str,
) -> anyhow::Result<()> {
    add(
        importer,
        name,
        ImporterConfiguration::ClearlyDefined(ClearlyDefinedImporter {
            common: CommonImporter {
                disabled: true,
                // once an hour is plenty
                period: Duration::from_secs(60 * 60),
                description: Some(description.into()),
                labels: Default::default(),
            },
            source: DEFAULT_SOURCE_CLEARLY_DEFINED.into(),
            types: ClearlyDefinedPackageType::all(),
        }),
    )
    .await
}

async fn add_cwe(importer: &ImporterService, name: &str, description: &str) -> anyhow::Result<()> {
    add(
        importer,
        name,
        ImporterConfiguration::Cwe(CweImporter {
            common: CommonImporter {
                disabled: true,
                // once a day is plenty
                period: Duration::from_secs(60 * 60 * 24),
                description: Some(description.into()),
                labels: Default::default(),
            },
            source: DEFAULT_SOURCE_CWE_CATALOG.into(),
        }),
    )
    .await
}

async fn add_quay(
    importer: &ImporterService,
    name: &str,
    description: &str,
    namespace: &str,
) -> anyhow::Result<()> {
    add(
        importer,
        name,
        ImporterConfiguration::Quay(QuayImporter {
            common: CommonImporter {
                disabled: true,
                period: Duration::from_secs(60 * 10),
                description: Some(description.into()),
                labels: Default::default(),
            },
            source: DEFAULT_SOURCE_QUAY.into(),
            namespace: Some(namespace.into()),
            size_limit: Some(ByteSize::mib(1).into()),
            ..Default::default()
        }),
    )
    .await
}

pub async fn sample_data(db: trustify_common::db::Database) -> anyhow::Result<()> {
    let importer = ImporterService::new(db);

    add(&importer, "redhat-sbom",  ImporterConfiguration::Sbom(SbomImporter {
        common: CommonImporter {
            disabled: true,
            period: Duration::from_secs(300),
            description: Some("All Red Hat SBOMs".into()),
            labels: Default::default(),
        },
        source: "https://access.redhat.com/security/data/sbom/beta/".to_string(),
        keys: vec![
            Url::parse("https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4")?
        ],
        v3_signatures: true,
        only_patterns: vec![],
        size_limit: None,
        fetch_retries: Some(50),
        ignore_missing: false,
    })).await?;

    add(
        &importer,
        "redhat-csaf",
        ImporterConfiguration::Csaf(CsafImporter {
            common: CommonImporter {
                disabled: true,
                period: Duration::from_secs(300),
                description: Some("All Red Hat CSAF data".into()),
                labels: Default::default(),
            },
            source: "redhat.com".to_string(),
            v3_signatures: true,
            only_patterns: vec![],
            fetch_retries: Some(50),
            ignore_missing: false,
        }),
    )
    .await?;

    add(
        &importer,
        "redhat-csaf-vex-2024",
        ImporterConfiguration::Csaf(CsafImporter {
            common: CommonImporter {
                disabled: true,
                period: Duration::from_secs(300),
                description: Some("Red Hat VEX files from 2024".into()),
                labels: Default::default(),
            },
            source: "redhat.com".to_string(),
            v3_signatures: true,
            only_patterns: vec!["^cve-2024-".into()],
            fetch_retries: Some(50),
            ignore_missing: false,
        }),
    )
    .await?;

    add_cwe(&importer, "cwe", "Common Weakness Enumeration").await?;

    add_quay(
        &importer,
        "quay",
        "Quay SBOM Attachments",
        "redhat-user-workloads",
    )
    .await?;

    add_cve(&importer, "cve", None, "CVE List V5").await?;
    add_cve(
        &importer,
        "cve-from-2024",
        Some(2024),
        "CVE List V5 (starting 2024)",
    )
    .await?;

    add_clearly_defined_curations(
        &importer,
        "clearly-defined-curations",
        "Community-curated ClearlyDefined licenses",
    )
    .await?;

    add_clearly_defined(&importer, "clearly-defined", "ClearlyDefined Definitions").await?;

    add_osv(
        &importer,
        "osv-pypa",
        "https://github.com/pypa/advisory-database",
        Some("vulns"),
        None,
        None,
        "Python Packaging Advisory Database",
    )
    .await?;

    add_osv(
        &importer,
        "osv-psf",
        "https://github.com/psf/advisory-database",
        Some("advisories"),
        None,
        None,
        "Python Software Foundation Advisory Database",
    )
    .await?;

    add_osv(
        &importer,
        "osv-r",
        "https://github.com/RConsortium/r-advisory-database",
        Some("vulns"),
        None,
        None,
        "RConsortium Advisory Database",
    )
    .await?;

    add_osv(
        &importer,
        "osv-oss-fuzz",
        "https://github.com/google/oss-fuzz-vulns",
        Some("vulns"),
        None,
        None,
        "OSS-Fuzz vulnerabilities",
    )
    .await?;

    add_osv(
        &importer,
        "osv-rustsec",
        "https://github.com/rustsec/advisory-db",
        Some("crates"),
        Some("osv"),
        None,
        "RustSec Advisory Database",
    )
    .await?;

    add_osv(
        &importer,
        "osv-github",
        "https://github.com/github/advisory-database",
        Some("advisories"),
        None,
        None,
        "GitHub Advisory Database",
    )
    .await?;

    add_osv(
        &importer,
        "osv-github-2024",
        "https://github.com/github/advisory-database",
        Some("advisories"),
        None,
        Some(2024),
        "GitHub Advisory Database (starting 2024)",
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    /// Ensure that examples can be added without failures
    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn add_samples(ctx: TrustifyContext) -> anyhow::Result<()> {
        sample_data(ctx.db.clone()).await?;

        let service = ImporterService::new(ctx.db.clone());
        let result = service.list().await?;

        assert_eq!(result.len(), 16);

        Ok(())
    }
}
