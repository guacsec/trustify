-- The advisories being extracted right now. The extraction stays in the worker's transaction until
-- it commits, so workers publish this from separate, short transactions. A crashed worker's row
-- stays behind until the advisory is extracted again, so readers ignore old rows.
CREATE TABLE IF NOT EXISTS correlation_extraction_current (
    advisory_id uuid PRIMARY KEY REFERENCES advisory(id) ON DELETE CASCADE,
    started_at timestamptz NOT NULL
);
