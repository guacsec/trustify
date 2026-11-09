-- Invalidate snapshots and prevent old workers from publishing historical advisory evidence.
UPDATE correlation_verdict_revision
SET resolver_version = 2, revision = revision + 1, changed_at = clock_timestamp();
