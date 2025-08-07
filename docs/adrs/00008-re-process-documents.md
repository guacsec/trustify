# 00008. Re-process documents

Date: 2025-08-08

## Status

DRAFT

## Context

During the process of ingestion, we extract certain information of the uploaded documents and store that information
in the database. We also store the original source document "as-is".

When making changes to the database structure, we also have a migration process, which takes care of upgrading the
database structures during an upgrade.

However, in some cases, changing the database structure actually means extracting more information from documents than
is currently stored in the database. Or information is extracted in a different way. This requires a re-processing of
all documents affected by this change.

### Example

We do ignore all CVSS v2 scores at the moment. Adding new fields for storing v2 scores, we wouldn't have
any stored in the database without re-processing documents and extracting that information.

### Assumptions

This ADR makes the following assumptions:

* All documents are stored in the storage
* It is expected that an upgrade is actually required
* Running such migrations is expected to take a long time
* The management of infrastructure (PostgreSQL) is not in the scope of Trustify

Question? Do we want to support downgrades?

## Decision

During the migration of database structures (sea orm), we also re-process all documents (if required). This would
be running during the migration job of the Helm chart and would have an impact on updates as the rollout of newer
version pods would be delayed until the migration (of data) has been finished.

This would also require to prevent users from creating new documents during that time. Otherwise, we would need to
re-process documents ingested during the migration time. A way of doing this could be to leverage PostgreSQL's ability
to switch into read-only mode. Having mutable operations fail with a 503 (Service Unavailable) error. This would also
allow for easy A/B (green/blue) database setups. Switching the main one to read-only, having the other one run the
migration.

We could provide an endpoint to the UI, reporting the fact that the system is in read-only mode during a migration.

* 👍 Can fully migrate database (create mandatory field as optional -> re-process -> make mandatory)
* 👍 Might allow for an out-of-band migration of data, before running the upgrade (even on a staging env)
* 👍 Would allow to continue serving data while the process is running
* 👎 Might be tricky to create a combined re-processing of multiple ones
* 👎 Might block an upgrade if re-processing fails

We do want to support different approaches of this migration. Depending on the needs of the user, the size of the
data store and the infrastructure used.

### Approach 1

The "lazy" approach, where the user just runs the migration (or the new version of the application with migrations
enabled). The process will migrate schema and data. This might block the startup for a bit. But would be fast and
simple for small systems.

### Approach 2

The user uses a green/blue deployment. Switching the application to use green and run migrations against blue. Once
the migrations are complete, switching back to blue. Green will be read-only and mutable API calls will fail with a 503
error.

An alternative to this could also be to configure the system first to go into "read-only mode", by using a default
transaction mode of read-only.

## Open items

* [ ] How to handle unparsable or failing documents during migration?
* [ ] Add a version number to the document, tracking upgrades

## Alternative approaches

### Option 2

We create a similar module as for the importer. Running migrations after an upgrade. Accepting that in the meantime,
we might service inaccurate data.

* 👎 Might serve inaccurate data for a while for a longer time
* 👎 Can't fully migrate database (new mandatory field won't work)
* 👍 Upgrade process is faster and less complex
* 👎 Requires some coordination between instances (only one processor at a time, maybe one after the other)

### Option 3

We change ingestion in a way to it is possible to just re-ingest every document. Meaning, we re-ingest from the
original sources.

* 👎 Might serve inaccurate data for a while for a longer time
* 👎 Can't fully migrate database (new mandatory field won't work)
* 👍 Upgrade process is faster and less complex
* 👎 Original sources might no longer have the documents
* 👎 Won't work for manual (API) uploads
* 👎 Would require removing optimizations for existing documents


## Consequences

* The migration will block the upgrade process until it is finished
* Ansible and the operator will need to handle this as well
* The system will become read-only during a migration
* The UI needs to provide a page for monitoring the migration state. The backend needs to provide appropriate APIs.
