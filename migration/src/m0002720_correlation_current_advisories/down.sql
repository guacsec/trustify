UPDATE correlation_verdict_revision
SET resolver_version = 1, revision = revision + 1, changed_at = clock_timestamp();
