-- Workers extract documents of a refresh job in parallel, each publishing its own document.
ALTER TABLE correlation_refresh_current DROP CONSTRAINT IF EXISTS correlation_refresh_current_pkey;
ALTER TABLE correlation_refresh_current ADD PRIMARY KEY (job_id, sbom_id);
