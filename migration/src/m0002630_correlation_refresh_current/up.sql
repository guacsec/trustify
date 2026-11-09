-- The document a refresh job is currently extracting. The job row stays locked until the
-- document commits, so workers publish this from a separate, short transaction.
-- At most one row per job; a crashed worker's row is overwritten when the job resumes.
CREATE TABLE IF NOT EXISTS correlation_refresh_current (
    job_id uuid PRIMARY KEY REFERENCES correlation_refresh_job(id) ON DELETE CASCADE,
    sbom_id uuid NOT NULL REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    started_at timestamptz NOT NULL,
    -- the chunks of the document extracted, and all of them; zero until known
    done bigint NOT NULL DEFAULT 0,
    total bigint NOT NULL DEFAULT 0
);
