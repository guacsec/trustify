-- The SBOMs whose verdicts are being computed right now, with the progress of the computation.
-- The verdicts stay in the worker's transaction until they commit, so workers publish this from
-- separate, short transactions. A crashed worker's row stays behind until the SBOM is computed
-- again, so readers ignore rows which haven't been updated for a while.
CREATE TABLE IF NOT EXISTS correlation_verdict_current (
    sbom_id uuid PRIMARY KEY REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    started_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- the (node, vulnerability) groups to resolve, and the ones resolved
    groups bigint NOT NULL,
    done bigint NOT NULL
);
