# 00008. Re-process documents

Date: 2025-08-08

## Status

DRAFT

## Context

During the process of ingestion, we extract certain information of the uploaded documents and store that information
in the database. We also store the original source document "as-is".

When making changes to the database structure, we also have a migration process, which takes care of upgrading the
database structures during an upgrade.

However, in some cases, changing the database structure actually means to extract more information from documents and is
currently stored in the database. Or information is extracted in a different way. This requires a re-processing of
all documents affected by this change.

### Example

We do ignore all CVSS v2 scores at the moment. Adding new fields for storing v2 scores, we wouldn't have
any stored in the database without re-processing documents and extracting that information.

### Assumptions

This ADR makes the following assumptions:

* All documents are stored in the storage
* It is expected that an upgrade is actually required
* Running such migrations is expected to take a long time

Question? Do we want to support downgrades?

## Decision

### Option 1

During the migration of database structures (sea orm), we also re-process all documents (when required).

In order to report progress, we could write that state into a table and expose that information to the user via the UI.

* 👎 Might serve inaccurate data for a while
* 👎 Might block an upgrade if re-processing fails
* 👍 Can fully migrate database (create mandatory field as optional -> re-process -> make mandatory)
* 👎 Might be tricky to create a combined re-processing of multiple ones

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

## Open items

…

## Alternative approaches

…

## Consequences

…
