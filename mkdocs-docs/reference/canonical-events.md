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
It is also distinct from the `network.source.provenance` trust stamp, a developer-facing contract
between importers and host-attribution readers that is documented in the repository's
`ARCHITECTURE.md`.

## Schema and migration policy

The schema version is `1.0.0`, and it has not changed since the envelope was introduced. The version
is not a changelog stamp. Every reader matches it exactly: the envelope schema, the Login Graph and
Evidence Chain readers, and the re-import merge all treat an envelope with any other version as
opaque. They preserve it verbatim and read nothing from it.

- **Adding an optional field does not bump the version.** Every reader must fail closed when the
  field is absent, so an envelope written before the field existed is still read in full. Every
  optional block and field added since `1.0.0` landed this way, including the
  `network.source.provenance` stamp.
- **Changing how a persisted envelope is read bumps the version.** Removing a field, changing its
  meaning, or making a reader depend on a field that older envelopes lack all qualify.
- **A bump is only safe together with a registered migration**, and none exists today. The upgrade
  path knows one migration: an event with no envelope at all is a legacy event, upgraded on read
  from its existing structured fields, with guarded description parsing confined to that one-time
  step; the original event stays intact and the new envelope is persisted on the next normal case
  save. A bump without a migration for the previous version makes every stored envelope in every
  existing case invisible to the Login Graph, the Evidence Chain and the merge, and no test would
  catch it.
- An unknown future schema version is preserved, not silently rewritten or downgraded.

Migration is therefore incremental: opening an older case does not require a bulk rewrite or a
re-import, and no legacy field or report wording is removed.

## Graphs and display wording

The Login Graph and Evidence Chain now read account, authentication, process, file, and network
identity from the canonical envelope. Changing a displayed sentence cannot silently change a graph
edge or join.

Descriptions remain backward-compatible during migration. Existing report wording is unchanged;
new structured mappings can evolve without making prose the source of truth again.
