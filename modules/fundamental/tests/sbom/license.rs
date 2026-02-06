use flate2::read::GzDecoder;
use sea_orm::EntityTrait;
use std::io::Read;
use tar::Archive;
use test_context::test_context;
use test_log::test;
use trustify_common::id::Id;
use trustify_entity::sbom_package_license::LicenseCategory;
use trustify_entity::{sbom_package, sbom_package_license};
use trustify_module_fundamental::license::{
    model::sbom_license::SbomNameId,
    service::{LicenseService, license_export::LicenseExporter},
};
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("cyclonedx/application.cdx.json")
        .await?;

    assert_eq!(
        Some("urn:uuid:da67396d-a1a3-3983-9570-6f8b96ac7392/1"),
        result.clone().document_id.as_deref()
    );
    let license_service = LicenseService::new();
    let license_result = license_service
        .license_export(Id::parse_uuid(result.id)?, &ctx.db)
        .await?;

    let sp: Vec<sbom_package::Model> = sbom_package::Entity::find().all(&ctx.db).await?;

    let spl: Vec<sbom_package_license::Model> =
        sbom_package_license::Entity::find().all(&ctx.db).await?;

    assert_eq!(89, sp.len());
    assert_eq!(96, spl.len());
    assert_eq!(96, license_result.sbom_package_license.len());
    assert_eq!(0, license_result.extracted_licensing_infos.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("spdx/SATELLITE-6.15-RHEL-8.json")
        .await?;

    assert_eq!(
        Some("https://access.redhat.com/security/data/sbom/spdx/SATELLITE-6.15-RHEL-8"),
        result.clone().document_id.as_deref()
    );
    let license_service = LicenseService::new();
    let license_result = license_service
        .license_export(Id::parse_uuid(result.id)?, &ctx.db)
        .await?;

    let sp: Vec<sbom_package::Model> = sbom_package::Entity::find().all(&ctx.db).await?;

    let spl: Vec<sbom_package_license::Model> =
        sbom_package_license::Entity::find().all(&ctx.db).await?;

    assert_eq!(4168, license_result.sbom_package_license.len());

    let cpes_result = license_result
        .sbom_package_license
        .iter()
        .filter(|sl| sl.name == "SATELLITE-6.15-RHEL-8")
        .collect::<Vec<_>>();
    // Verify that the part of all CPEs is the string "a"
    assert_eq!(8, cpes_result[0].cpe.len());
    assert_eq!(
        8,
        cpes_result[0]
            .cpe
            .iter()
            .filter(|c| c.part == Some("a".into()))
            .count()
    );

    let package_license_result = license_result
        .sbom_package_license
        .into_iter()
        .filter(|sl| sl.name == "rubygem-bundler_ext")
        .collect::<Vec<_>>();
    // there are 4 with the same name but different qualifiers: two has 'arch=src' and
    // the other two have 'arch=noarch'.
    // Each qualifier appears twice: once for the declared license and once for the concluded one.
    assert_eq!(4, package_license_result.len());
    assert_eq!(
        2,
        package_license_result
            .iter()
            .filter(|plr| plr.license_text == Some("LicenseRef-0".to_string())
                && plr.license_type == Some(LicenseCategory::Declared))
            .count()
    );
    assert_eq!(
        2,
        package_license_result
            .iter()
            .filter(
                |plr| plr.license_text == Some("Apache-2.0 AND MIT".to_string())
                    && plr.license_type == Some(LicenseCategory::Concluded)
            )
            .count()
    );
    assert_eq!(2084, sp.len());
    assert_eq!(4168, spl.len());
    assert_eq!(49, license_result.extracted_licensing_infos.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_license_export_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("spdx/mtv-2.6.json").await?;

    assert_eq!(
        Some("https://access.redhat.com/security/data/sbom/spdx/MTV-2.6"),
        result.clone().document_id.as_deref()
    );
    let license_service = LicenseService::new();
    let license_result = license_service
        .license_export(Id::parse_uuid(result.id)?, &ctx.db)
        .await?;

    let sbom_name_group_version = license_result
        .sbom_name_group_version
        .unwrap_or_else(SbomNameId::default);
    let exporter = LicenseExporter::new(
        sbom_name_group_version.sbom_id,
        sbom_name_group_version.sbom_name,
        license_result.sbom_package_license.clone(),
        license_result.extracted_licensing_infos.clone(),
    );
    assert_eq!(45, license_result.extracted_licensing_infos.len());
    assert_eq!(10776, license_result.sbom_package_license.len());

    let compressed_data = exporter
        .generate()
        .unwrap_or_else(|_| panic!("generate failed"));

    let mut licenses_csv_found = false;
    let mut licenses_ref_csv_found = false;
    let decoder = GzDecoder::new(&compressed_data[..]);
    let mut archive = Archive::new(decoder);
    for archive_entry in archive.entries()? {
        let mut entry = archive_entry?;
        match entry.path() {
            Ok(path) if path.file_name().unwrap_or_default() == "MTV-2.6_sbom_licenses.csv" => {
                licenses_csv_found = true;
                let mut sbom_licenses = String::new();
                entry.read_to_string(&mut sbom_licenses)?;
                assert_eq!(21554, sbom_licenses.matches("MTV-2.6").count());
                assert_eq!(
                    10776,
                    sbom_licenses
                        .matches("https://access.redhat.com/security/data/sbom/spdx/MTV-2.6")
                        .count()
                );
                assert_eq!(56, sbom_licenses.matches("pkg:oci/").count());
                assert_eq!(3952, sbom_licenses.matches("pkg:npm/").count());
                assert_eq!(4370, sbom_licenses.matches("pkg:golang/").count());
                assert_eq!(2382, sbom_licenses.matches("pkg:rpm/").count());
                assert_eq!(8972, sbom_licenses.matches("NOASSERTION").count());
                assert_eq!(5388, sbom_licenses.matches("Declared").count());
                assert_eq!(5388, sbom_licenses.matches("Concluded").count());
            }
            Ok(path) if path.file_name().unwrap_or_default() == "MTV-2.6_license_ref.csv" => {
                licenses_ref_csv_found = true;
                let mut license_refs = String::new();
                entry.read_to_string(&mut license_refs)?;
                assert_eq!(45, license_refs.matches("\"LicenseRef-").count());
                assert_eq!(45, license_refs.matches("External License Info is obtained from a build system which predates the SPDX specification and is not strict in accepting valid SPDX licenses.").count());
                assert_eq!(1, license_refs.matches("\"LicenseRef-11\"	\"(FTL or GPLv2+) and BSD and MIT and Public Domain and zlib with acknowledgement\"	\"The license info found in the package meta data is: (FTL or GPLv2+) and BSD and MIT and Public Domain and zlib with acknowledgement. See the specific package info in this SPDX document or the package itself for more details.\"	\"External License Info is obtained from a build system which predates the SPDX specification and is not strict in accepting valid SPDX licenses.\"").count());
            }
            _ => {
                return Err(anyhow::Error::msg(format!(
                    "Unexpected archive entry: {:?}",
                    entry.path()?
                )));
            }
        }
    }
    assert!(licenses_csv_found);
    assert!(licenses_ref_csv_found);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_license_export_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("cyclonedx/application.cdx.json")
        .await?;

    assert_eq!(
        Some("urn:uuid:da67396d-a1a3-3983-9570-6f8b96ac7392/1"),
        result.clone().document_id.as_deref()
    );
    let license_service = LicenseService::new();
    let license_result = license_service
        .license_export(Id::parse_uuid(result.id)?, &ctx.db)
        .await?;

    let sbom_name_group_version = license_result
        .sbom_name_group_version
        .unwrap_or_else(SbomNameId::default);
    let exporter = LicenseExporter::new(
        sbom_name_group_version.sbom_id,
        sbom_name_group_version.sbom_name,
        license_result.sbom_package_license.clone(),
        license_result.extracted_licensing_infos.clone(),
    );
    assert_eq!(0, license_result.extracted_licensing_infos.len());
    assert_eq!(96, license_result.sbom_package_license.len());

    let compressed_data = exporter
        .generate()
        .unwrap_or_else(|_| panic!("generate failed"));

    let mut licenses_csv_found = false;
    let mut licenses_ref_csv_found = false;
    let decoder = GzDecoder::new(&compressed_data[..]);
    let mut archive = Archive::new(decoder);
    for archive_entry in archive.entries()? {
        let mut entry = archive_entry?;
        match entry.path() {
            Ok(path)
                if path.file_name().unwrap_or_default() == "spring-petclinic_sbom_licenses.csv" =>
            {
                licenses_csv_found = true;
                let mut sbom_licenses = String::new();
                entry.read_to_string(&mut sbom_licenses)?;
                assert_eq!(98, sbom_licenses.matches("spring-petclinic").count());
                assert_eq!(
                    2,
                    sbom_licenses.matches("org.springframework.samples").count()
                );
                assert_eq!(2, sbom_licenses.matches("3.3.0-SNAPSHOT").count());
                assert_eq!(96, sbom_licenses.matches("pkg:maven/").count());
                // check some PURLs appear multiple times because they have multiple licenses
                assert_eq!(
                    2,
                    sbom_licenses
                        .matches("pkg:maven/ch.qos.logback/logback-classic@1.5.8?type=jar")
                        .count()
                );
                assert_eq!(
                    2,
                    sbom_licenses
                        .matches("pkg:maven/ch.qos.logback/logback-core@1.5.8?type=jar")
                        .count()
                );
                assert_eq!(
                    2,
                    sbom_licenses
                        .matches(
                            "pkg:maven/jakarta.annotation/jakarta.annotation-api@2.1.1?type=jar"
                        )
                        .count()
                );
                assert_eq!(
                    2,
                    sbom_licenses
                        .matches("pkg:maven/org.hdrhistogram/HdrHistogram@2.2.2?type=jar")
                        .count()
                );
                assert_eq!(63, sbom_licenses.matches("Apache-2.0").count());
            }
            Ok(path)
                if path.file_name().unwrap_or_default() == "spring-petclinic_license_ref.csv" =>
            {
                licenses_ref_csv_found = true;
            }
            _ => {
                return Err(anyhow::Error::msg(format!(
                    "Unexpected archive entry: {:?}",
                    entry.path()?
                )));
            }
        }
    }
    assert!(licenses_csv_found);
    assert!(licenses_ref_csv_found);
    Ok(())
}
