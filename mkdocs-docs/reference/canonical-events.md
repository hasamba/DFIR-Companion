# Canonical Event Data

Every imported timeline event keeps the familiar timestamp, severity, description, host, source,
and indicator fields shown in the dashboard and reports. Behind those display fields, the Companion
now also stores a versioned canonical event envelope. This gives equivalent evidence from different
tools the same internal shape, so correlation does not depend on one importer's sentence wording.

## What is normalized

When the source record contains the information, the envelope represents:

- the actor, subject, object, and target of the activity;
- accounts, authentication results, logon types, and session identifiers;
- source and destination network endpoints;
- processes, parents, executable paths, command lines, and process identifiers;
- files and hashes, registry objects, services, and scheduled tasks;
- mailboxes, message identifiers, senders, and recipients;
- cloud principals, providers, regions, accounts, and resources; and
- the observed timestamp alongside its normalized UTC value, timezone, precision, and clock
  confidence.

Windows Event Log, Linux auditd, AWS CloudTrail, Suricata/Zeek, email, Volatility/Rekall, and ECAR
are the first representative mappings. Other importers can adopt the same envelope incrementally
without changing what analysts see.

## Traceability

Each envelope points back to its raw record by a stable locator and records the SHA-256 of the
source artifact when the importer has the original file. It also names the importer, parser,
mapping, and deterministic rule versions used.

Every normalized leaf field carries its own provenance:

- **raw** means the value came directly from named source fields;
- **derived** names the deterministic mapping or migration rule that produced it; and
- **confidence** is high, medium, or low for that individual mapping.

Importer conformance tests reject an envelope that contains an untraceable normalized field. This
provenance is internal evidence lineage; it does not replace the case's Chain of Custody record.

## Schema and migration policy

The first schema version is `1.0.0`.

- A **patch** version may clarify validation or a deterministic mapping without changing the
  meaning of existing fields.
- A **minor** version may add optional fields. Existing readers must continue to accept events that
  do not have them.
- A **major** version is required to remove a field or change its meaning. It must ship with an
  explicit, tested migration.
- An event with no envelope is a legacy event. It is upgraded on read using its existing structured
  fields; guarded description parsing is confined to this one-time legacy migration. The original
  event remains intact and the new envelope is persisted on the next normal case save.
- An unknown future schema version must be preserved, not silently rewritten or downgraded.

Migration is therefore incremental: opening an older case does not require a bulk rewrite or a
re-import, and no legacy field or report wording is removed.

## Graphs and display wording

The Login Graph and Evidence Chain now read account, authentication, process, file, and network
identity from the canonical envelope. Changing a displayed sentence cannot silently change a graph
edge or join.

Descriptions remain backward-compatible during migration. Existing report wording is unchanged;
new structured mappings can evolve without making prose the source of truth again.
