DROP VIEW correlation_verdict_freshness;
DROP TRIGGER correlation_verdict_evidence_changed ON correlation_evidence;
DROP TRIGGER correlation_verdict_sbom_added ON sbom;
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['correlation_provider_alias', 'remediation', 'remediation_purl_status',
        'remediation_product_status', 'remediation_cpe_assertion', 'remediation_hash_assertion',
        'remediation_product_identifier_assertion', 'organization', 'assertion_context',
        'advisory', 'vulnerability', 'sbom', 'sbom_package', 'sbom_node'] LOOP
        EXECUTE format('DROP TRIGGER correlation_verdict_global_changed ON %I', t);
    END LOOP;
END $$;
DROP TRIGGER correlation_verdict_context_changed ON correlation_evidence_context;
DROP FUNCTION correlation_verdict_context_changed();
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['sbom_node_purl_ref', 'sbom_node_cpe_ref', 'sbom_node_product_identifier', 'package_relates_to_package'] LOOP
        EXECUTE format('DROP TRIGGER correlation_verdict_local_changed ON %I', t);
    END LOOP;
END $$;
DROP FUNCTION correlation_verdict_sbom_added();
DROP FUNCTION correlation_verdict_global_changed();
DROP FUNCTION correlation_verdict_evidence_changed();
DROP FUNCTION correlation_verdict_dirty(uuid);
DROP TABLE correlation_verdict;
DROP TYPE verdict_status;
DROP TABLE correlation_verdict_state;
DROP TABLE correlation_verdict_revision;
DROP TABLE correlation_verdict_publication;
