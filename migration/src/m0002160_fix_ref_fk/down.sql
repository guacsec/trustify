CREATE OR REPLACE FUNCTION public.qualified_package_transitive(sbom_id_param uuid, start_qualified_purl_id uuid, relationships_param integer[]) RETURNS TABLE(left_package_id uuid, right_package_id uuid)
    LANGUAGE plpgsql
    AS $$
begin

    return query
    select
        left_id.qualified_purl_id,
        right_id.qualified_purl_id
    from (
        select
            node_id
        from
            sbom_package_purl_ref AS source
        where
            source.qualified_purl_id = start_qualified_purl_id
            and
            source.sbom_id = sbom_id_param
    ) AS t

     cross join lateral package_transitive(sbom_id_param, t.node_id, relationships_param) as result
     join sbom_package_purl_ref as left_id
            on
                left_id.node_id = result.left_node_id
                and left_id.sbom_id = sbom_id_param
     join sbom_package_purl_ref as right_id
            on
                right_id.node_id = result.right_node_id
                and right_id.sbom_id = sbom_id_param
    ;

end
$$;
