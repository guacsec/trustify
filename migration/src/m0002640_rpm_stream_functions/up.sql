-- RPM release streams, mirroring `trustify_common::rpm` (`Evr::parse`, `Evr::stream`,
-- `stream_major`). Used to skip ranges of other streams before evaluating `version_matches()`;
-- the Rust implementation remains the authority on the result.

-- The release: the part after the last `-`, NULL without one. An epoch (`1:`) never contains a
-- `-`, so it needs no special handling.
CREATE OR REPLACE FUNCTION rpm_release(version_p text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$ SELECT CASE WHEN strpos(version_p, '-') > 0 THEN regexp_replace(version_p, '^.*-', '') END $$;

-- The stream of the release: its first `.` separated token starting with letters directly
-- followed by a digit (e.g. `el8_6` of `9.el8_6`), NULL without one.
CREATE OR REPLACE FUNCTION rpm_stream(version_p text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$ SELECT substring('.' || rpm_release(version_p) FROM '\.([A-Za-z]+[0-9][^.]*)') $$;

-- The major part of a stream: its leading letters and digits (e.g. `el8` of `el8_6`).
CREATE OR REPLACE FUNCTION rpm_stream_major(stream_p text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$ SELECT substring(stream_p FROM '^[A-Za-z]*[0-9]*') $$;
