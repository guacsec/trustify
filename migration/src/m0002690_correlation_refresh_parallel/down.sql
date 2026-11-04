-- keep the latest document of each job
DELETE FROM correlation_refresh_current c USING correlation_refresh_current l
WHERE c.job_id = l.job_id AND (c.started_at, c.sbom_id) < (l.started_at, l.sbom_id);
ALTER TABLE correlation_refresh_current DROP CONSTRAINT IF EXISTS correlation_refresh_current_pkey;
ALTER TABLE correlation_refresh_current ADD PRIMARY KEY (job_id);
