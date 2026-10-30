DROP VIEW correlation_verdict_freshness;
DO $$ DECLARE t text[]; op text; BEGIN
    FOREACH t SLICE 1 IN ARRAY ARRAY[
        ['correlation_evidence', 'correlation_verdict_evidence_changed'],
        ['correlation_evidence_context', 'correlation_verdict_context_changed'],
        ['sbom_node_purl_ref', 'correlation_verdict_local_changed'],
        ['sbom_node_cpe_ref', 'correlation_verdict_local_changed'],
        ['sbom_node_product_identifier', 'correlation_verdict_local_changed'],
        ['package_relates_to_package', 'correlation_verdict_local_changed']] LOOP
        FOREACH op IN ARRAY ARRAY['ins', 'upd', 'del'] LOOP
            EXECUTE format('DROP TRIGGER %I ON %I', t[2] || '_' || op, t[1]);
        END LOOP;
    END LOOP;
END $$;
DROP TRIGGER correlation_verdict_sbom_added ON sbom;
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['correlation_provider_alias', 'remediation', 'remediation_purl_status',
        'remediation_product_status', 'remediation_cpe_assertion', 'remediation_hash_assertion',
        'remediation_product_identifier_assertion', 'organization', 'assertion_context',
        'advisory', 'vulnerability', 'sbom', 'sbom_package', 'sbom_node'] LOOP
        EXECUTE format('DROP TRIGGER correlation_verdict_global_changed ON %I', t);
    END LOOP;
END $$;
DROP FUNCTION correlation_verdict_context_changed();
DROP FUNCTION correlation_verdict_sbom_added();
DROP FUNCTION correlation_verdict_global_changed();
DROP FUNCTION correlation_verdict_rows_changed();
DROP FUNCTION correlation_verdict_dirty(uuid[]);
DROP TABLE correlation_verdict;
DROP TYPE verdict_status;
DROP TABLE correlation_verdict_state;
DROP TABLE correlation_verdict_revision;
DROP TABLE correlation_verdict_publication;
