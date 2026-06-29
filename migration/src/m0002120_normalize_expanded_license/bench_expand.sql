-- Benchmark: regexp_replace vs replace() for license expression expansion
-- Run with: psql -f bench_expand.sql <database>
--
-- Creates temporary functions and test data, runs both implementations,
-- verifies they produce identical results, and reports timings.

-- Ensure the license_mapping type exists
DO $$
BEGIN
    CREATE TYPE license_mapping AS (license_id TEXT, name TEXT);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

----------------------------------------------------------------------
-- 1. Define both function variants under benchmark-specific names
----------------------------------------------------------------------

-- Old version: regex-based (dynamically compiled pattern per mapping)
CREATE OR REPLACE FUNCTION bench_expand_regex(
    license_text TEXT,
    license_mappings license_mapping[]
) RETURNS TEXT AS $$
DECLARE
    result_text TEXT := license_text;
    mapping license_mapping;
BEGIN
    IF license_text IS NULL
       OR POSITION('LicenseRef-' IN license_text) = 0
       OR license_mappings IS NULL
       OR array_length(license_mappings, 1) IS NULL THEN
        RETURN license_text;
    END IF;

    FOREACH mapping IN ARRAY license_mappings
    LOOP
        IF POSITION('LicenseRef-' IN result_text) = 0 THEN
            EXIT;
        END IF;
        result_text := regexp_replace(
            result_text,
            '\m' || mapping.license_id || '(?![a-zA-Z0-9.\-])',
            mapping.name, 'g'
        );
    END LOOP;

    RETURN result_text;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;

-- New version: replace()-based (no regex, boundary-aware via SPDX delimiters)
CREATE OR REPLACE FUNCTION bench_expand_replace(
    license_text TEXT,
    license_mappings license_mapping[]
) RETURNS TEXT AS $$
DECLARE
    result_text TEXT;
    mapping license_mapping;
BEGIN
    IF license_text IS NULL
       OR POSITION('LicenseRef-' IN license_text) = 0
       OR license_mappings IS NULL
       OR array_length(license_mappings, 1) IS NULL THEN
        RETURN license_text;
    END IF;

    result_text := ' ' || license_text || ' ';

    FOREACH mapping IN ARRAY license_mappings
    LOOP
        IF POSITION('LicenseRef-' IN result_text) = 0 THEN
            EXIT;
        END IF;

        result_text := replace(result_text, ' ' || mapping.license_id || ' ',  ' ' || mapping.name || ' ');
        result_text := replace(result_text, ' ' || mapping.license_id || ')',  ' ' || mapping.name || ')');
        result_text := replace(result_text, ' ' || mapping.license_id || '+',  ' ' || mapping.name || '+');
        result_text := replace(result_text, '(' || mapping.license_id || ' ',  '(' || mapping.name || ' ');
        result_text := replace(result_text, '(' || mapping.license_id || ')',  '(' || mapping.name || ')');
        result_text := replace(result_text, '(' || mapping.license_id || '+',  '(' || mapping.name || '+');
    END LOOP;

    RETURN substring(result_text FROM 2 FOR length(result_text) - 2);
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;

----------------------------------------------------------------------
-- 2. Generate test data
----------------------------------------------------------------------

CREATE TEMPORARY TABLE bench_expressions (id SERIAL, expr TEXT);

INSERT INTO bench_expressions (expr) VALUES
    -- No LicenseRef (early-exit path)
    ('MIT'),
    ('Apache-2.0'),
    ('GPL-3.0-only'),
    ('BSD-2-Clause OR MIT'),
    -- Single LicenseRef
    ('LicenseRef-custom-1'),
    ('LicenseRef-scancode-unknown-license-reference'),
    -- Compound with LicenseRef
    ('LicenseRef-custom-1 AND MIT'),
    ('Apache-2.0 OR LicenseRef-custom-2'),
    ('LicenseRef-custom-1 AND LicenseRef-custom-2'),
    -- Parenthesized
    ('(LicenseRef-custom-1 OR LicenseRef-custom-2) AND MIT'),
    ('(LicenseRef-custom-1 AND Apache-2.0) OR (LicenseRef-custom-2 AND MIT)'),
    -- With + modifier
    ('LicenseRef-custom-1+'),
    ('LicenseRef-custom-1+ AND LicenseRef-custom-2'),
    -- Many refs
    ('LicenseRef-custom-1 AND LicenseRef-custom-2 AND LicenseRef-custom-3 AND LicenseRef-custom-4 AND LicenseRef-custom-5'),
    -- Complex nested
    ('(LicenseRef-custom-1 OR LicenseRef-custom-2) AND (LicenseRef-custom-3 OR LicenseRef-custom-4) AND (LicenseRef-custom-5 OR MIT) AND (Apache-2.0 OR LicenseRef-custom-6)'),
    -- Substring trap: LicenseRef-custom-1 must NOT match inside LicenseRef-custom-10
    ('LicenseRef-custom-1 AND LicenseRef-custom-10'),
    ('(LicenseRef-custom-10 OR LicenseRef-custom-1)');

-- Replicate each expression 1000x for measurable timing
CREATE TEMPORARY TABLE bench_data AS
SELECT e.id, e.expr
FROM bench_expressions e, generate_series(1, 1000);

-- Realistic mapping array (7 mappings, typical for an SBOM with custom licenses)
CREATE TEMPORARY TABLE bench_mappings AS
SELECT ARRAY[
    ROW('LicenseRef-custom-1',  'Custom License One')::license_mapping,
    ROW('LicenseRef-custom-2',  'Custom License Two')::license_mapping,
    ROW('LicenseRef-custom-3',  'Custom License Three')::license_mapping,
    ROW('LicenseRef-custom-4',  'Custom License Four')::license_mapping,
    ROW('LicenseRef-custom-5',  'Custom License Five')::license_mapping,
    ROW('LicenseRef-custom-6',  'Custom License Six')::license_mapping,
    ROW('LicenseRef-custom-10', 'Custom License Ten')::license_mapping,
    ROW('LicenseRef-scancode-unknown-license-reference', 'Unknown License Reference')::license_mapping
] AS mappings;

----------------------------------------------------------------------
-- 3. Correctness check (must pass before timing matters)
----------------------------------------------------------------------

DO $$
DECLARE
    mismatches BIGINT;
    sample_regex TEXT;
    sample_replace TEXT;
    sample_expr TEXT;
BEGIN
    SELECT count(*) INTO mismatches
    FROM bench_expressions e, bench_mappings m
    WHERE bench_expand_regex(e.expr, m.mappings)
          IS DISTINCT FROM
          bench_expand_replace(e.expr, m.mappings);

    IF mismatches > 0 THEN
        -- Show first mismatch for debugging
        SELECT e.expr,
               bench_expand_regex(e.expr, m.mappings),
               bench_expand_replace(e.expr, m.mappings)
        INTO sample_expr, sample_regex, sample_replace
        FROM bench_expressions e, bench_mappings m
        WHERE bench_expand_regex(e.expr, m.mappings)
              IS DISTINCT FROM
              bench_expand_replace(e.expr, m.mappings)
        LIMIT 1;

        RAISE EXCEPTION E'CORRECTNESS FAILURE: % mismatches\n  input:   %\n  regex:   %\n  replace: %',
            mismatches, sample_expr, sample_regex, sample_replace;
    END IF;

    RAISE NOTICE 'correctness: PASSED (all % expressions produce identical results)',
        (SELECT count(*) FROM bench_expressions);
END $$;

----------------------------------------------------------------------
-- 4. Warmup (populate caches, JIT compile if enabled)
----------------------------------------------------------------------

DO $$
DECLARE dummy BIGINT;
BEGIN
    SELECT count(bench_expand_regex(d.expr, m.mappings)) INTO dummy
    FROM bench_data d, bench_mappings m;
    SELECT count(bench_expand_replace(d.expr, m.mappings)) INTO dummy
    FROM bench_data d, bench_mappings m;
END $$;

----------------------------------------------------------------------
-- 5. Timed runs (3 iterations each, report min/avg)
----------------------------------------------------------------------

DO $$
DECLARE
    t_start  TIMESTAMPTZ;
    t_end    TIMESTAMPTZ;
    dummy    BIGINT;
    ms       NUMERIC;
    row_cnt  BIGINT;

    regex_times   NUMERIC[] := '{}';
    replace_times NUMERIC[] := '{}';
    i INT;
BEGIN
    SELECT count(*) INTO row_cnt FROM bench_data;

    FOR i IN 1..3 LOOP
        -- regex
        t_start := clock_timestamp();
        SELECT count(bench_expand_regex(d.expr, m.mappings)) INTO dummy
        FROM bench_data d, bench_mappings m;
        t_end := clock_timestamp();
        ms := EXTRACT(EPOCH FROM (t_end - t_start)) * 1000;
        regex_times := regex_times || ms;

        -- replace
        t_start := clock_timestamp();
        SELECT count(bench_expand_replace(d.expr, m.mappings)) INTO dummy
        FROM bench_data d, bench_mappings m;
        t_end := clock_timestamp();
        ms := EXTRACT(EPOCH FROM (t_end - t_start)) * 1000;
        replace_times := replace_times || ms;
    END LOOP;

    RAISE NOTICE '';
    RAISE NOTICE '=== Benchmark Results (% rows per run) ===', row_cnt;
    RAISE NOTICE '';
    RAISE NOTICE 'regex   : run1=% ms  run2=% ms  run3=% ms  avg=% ms',
        round(regex_times[1], 1),
        round(regex_times[2], 1),
        round(regex_times[3], 1),
        round((regex_times[1] + regex_times[2] + regex_times[3]) / 3, 1);
    RAISE NOTICE 'replace : run1=% ms  run2=% ms  run3=% ms  avg=% ms',
        round(replace_times[1], 1),
        round(replace_times[2], 1),
        round(replace_times[3], 1),
        round((replace_times[1] + replace_times[2] + replace_times[3]) / 3, 1);
    RAISE NOTICE '';
    RAISE NOTICE 'speedup : %x',
        round(
            ((regex_times[1] + regex_times[2] + regex_times[3])
            / NULLIF(replace_times[1] + replace_times[2] + replace_times[3], 0)),
            2
        );
END $$;

----------------------------------------------------------------------
-- 6. Cleanup
----------------------------------------------------------------------

DROP TABLE bench_data;
DROP TABLE bench_expressions;
DROP TABLE bench_mappings;
DROP FUNCTION bench_expand_regex;
DROP FUNCTION bench_expand_replace;
