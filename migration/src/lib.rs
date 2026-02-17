use crate::data::{
    Migration, MigrationTraitWithData, MigrationWithData, Migrations, MigratorWithData,
};
pub use sea_orm_migration::prelude::*;

pub mod data;

mod m0000010_init;
mod m0000020_add_sbom_group;
mod m0000030_perf_adv_vuln;
mod m0000040_create_license_export;
mod m0000050_perf_adv_vuln2;
mod m0000060_perf_adv_vuln3;
mod m0000070_perf_adv_vuln4;
mod m0000080_get_purl_refactor;
mod m0000090_release_perf;
mod m0000100_perf_adv_vuln5;
mod m0000970_alter_importer_add_heartbeat;
mod m0000980_get_purl_fix;
mod m0000990_sbom_add_suppliers;
mod m0001000_sbom_non_null_suppliers;
mod m0001010_alter_mavenver_cmp;
mod m0001020_alter_pythonver_cmp;
mod m0001030_perf_adv_gin_index;
mod m0001040_alter_pythonver_cmp;
mod m0001050_foreign_key_cascade;
mod m0001060_advisory_vulnerability_indexes;
mod m0001070_vulnerability_scores;
mod m0001100_remove_get_purl;
mod m0001110_sbom_node_checksum_indexes;
mod m0001120_sbom_external_node_indexes;
mod m0001130_gover_cmp;
mod m0001140_expand_spdx_licenses_function;
mod m0001150_case_license_text_sbom_id_function;
mod m0001160_improve_expand_spdx_licenses_function;
mod m0001170_non_null_source_document_id;
mod m0001180_expand_spdx_licenses_with_mappings_function;
mod m0001190_optimize_product_advisory_query;
mod m0001200_source_document_fk_indexes;
mod m0001210_csaf_remediations;
mod m0002000_add_sbom_properties;
mod m0002010_add_advisory_scores;
mod m0002020_add_sbom_group;
mod m0002030_create_ai;
mod m0002040_create_crypto;
mod m0002050_add_sbom_revision;
mod m0002060_add_sbom_group_field;
mod m0002070_alter_sbom_group_restrict_parent;

pub trait MigratorExt: Send {
    fn build_migrations() -> Migrations;

    fn into_migrations() -> Vec<Box<dyn MigrationTrait>> {
        // Get all migrations, wrap data migrations. This will initialize the storage config.
        Self::build_migrations()
            .into_iter()
            .map(|migration| match migration {
                Migration::Normal(migration) => migration,
                Migration::Data(migration) => Box::new(MigrationWithData::new(migration)),
            })
            .collect()
    }
}

pub struct Migrator;

impl MigratorExt for Migrator {
    fn build_migrations() -> Migrations {
        Migrations::new()
            .normal(m0000010_init::Migration)
            .normal(m0000020_add_sbom_group::Migration)
            .normal(m0000030_perf_adv_vuln::Migration)
            .normal(m0000040_create_license_export::Migration)
            .normal(m0000050_perf_adv_vuln2::Migration)
            .normal(m0000060_perf_adv_vuln3::Migration)
            .normal(m0000070_perf_adv_vuln4::Migration)
            .normal(m0000080_get_purl_refactor::Migration)
            .normal(m0000090_release_perf::Migration)
            .normal(m0000100_perf_adv_vuln5::Migration)
            .normal(m0000970_alter_importer_add_heartbeat::Migration)
            .normal(m0000980_get_purl_fix::Migration)
            .normal(m0000990_sbom_add_suppliers::Migration)
            .normal(m0001000_sbom_non_null_suppliers::Migration)
            .normal(m0001010_alter_mavenver_cmp::Migration)
            .normal(m0001020_alter_pythonver_cmp::Migration)
            .normal(m0001030_perf_adv_gin_index::Migration)
            .normal(m0001040_alter_pythonver_cmp::Migration)
            .normal(m0001050_foreign_key_cascade::Migration)
            .normal(m0001060_advisory_vulnerability_indexes::Migration)
            .normal(m0001070_vulnerability_scores::Migration)
            .normal(m0001100_remove_get_purl::Migration)
            .normal(m0001110_sbom_node_checksum_indexes::Migration)
            .normal(m0001120_sbom_external_node_indexes::Migration)
            .normal(m0001130_gover_cmp::Migration)
            .normal(m0001140_expand_spdx_licenses_function::Migration)
            .normal(m0001150_case_license_text_sbom_id_function::Migration)
            .normal(m0001160_improve_expand_spdx_licenses_function::Migration)
            .normal(m0001170_non_null_source_document_id::Migration)
            .normal(m0001180_expand_spdx_licenses_with_mappings_function::Migration)
            .normal(m0001190_optimize_product_advisory_query::Migration)
            .normal(m0001200_source_document_fk_indexes::Migration)
            .normal(m0001210_csaf_remediations::Migration)
            .data(m0002000_add_sbom_properties::Migration)
            .data(m0002010_add_advisory_scores::Migration)
            .normal(m0002020_add_sbom_group::Migration)
            .normal(m0002030_create_ai::Migration)
            .normal(m0002040_create_crypto::Migration)
            .normal(m0002050_add_sbom_revision::Migration)
            .normal(m0002060_add_sbom_group_field::Migration)
            .normal(m0002070_alter_sbom_group_restrict_parent::Migration)
    }
}

impl<M: MigratorExt> MigratorWithData for M {
    fn data_migrations() -> Vec<Box<dyn MigrationTraitWithData>> {
        Self::build_migrations().only_data()
    }
}

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        Self::into_migrations()
    }
}

pub struct Now;

impl Iden for Now {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}

pub struct UuidV4;

impl Iden for UuidV4 {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "gen_random_uuid").unwrap()
    }
}
