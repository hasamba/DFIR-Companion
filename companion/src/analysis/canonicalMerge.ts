import {
  CANONICAL_EVENT_SCHEMA_VERSION,
  LEGACY_UPGRADE_IMPORTER,
  type CanonicalEventEnvelope,
} from "./canonicalEvent.js";
import {
  compactFieldProvenance,
  expandFieldProvenance,
  migrateCanonicalEnvelope,
  type FieldProvenance,
} from "./canonicalProvenanceCompact.js";
import type { ForensicEvent } from "./stateTypes.js";

// Merging two canonical envelopes that describe one row (#965). Two paths bring a second envelope
// to a row: correlate.mergeGroup folds several tools' readings of one artifact into one row, and
// the state merge re-imports a row the case already holds. Before this module the first spread
// only the primary's fields — a Hayabusa Sigma hit at High over a Defender record became primary
// and the Windows importer's typed action/outcome/object vanished — and the second kept the first
// envelope's normalised fields whatever the re-import had learned.
//
// The rule is one function: a WINNER whose present values stand, and a FILLER whose values fill
// the winner's gaps, leaf by leaf. Evidence pointers are unioned and every field's provenance
// cites both records, so a filled field carries the filler's provenance and a conflicting one
// carries the winner's plus the loser's locator. Idempotent: filling from an envelope already
// folded in changes nothing.

type Plain = Record<string, unknown>;

function isPlain(v: unknown): v is Plain {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// An entity is atomic across kinds: an account must not inherit a network entity's address and
// port because both sat in the same slot. Same kind (or no kind on either) fills leaf by leaf.
function sameKind(a: Plain, b: Plain): boolean {
  return a.kind === undefined || b.kind === undefined || a.kind === b.kind;
}

// Leaf-wise fill: a key the winner lacks is taken from the filler; a nested object of the same
// kind recurses; a present scalar, array, or entity of another kind stays the winner's. Returns
// the winner itself when nothing was added.
function fillLeaves(winner: Plain, filler: Plain): Plain {
  let out: Plain | undefined;
  for (const [key, value] of Object.entries(filler)) {
    if (value === undefined) continue;
    const mine = winner[key];
    if (mine === undefined) (out ??= { ...winner })[key] = value;
    else if (isPlain(mine) && isPlain(value) && sameKind(mine, value)) {
      const nested = fillLeaves(mine, value);
      if (nested !== mine) (out ??= { ...winner })[key] = nested;
    }
  }
  return out ?? winner;
}

// Both sides EXPANDED (#1874): each may carry its own defaults block, so the union is taken over the
// complete records and the merged envelope is compacted afresh.
function unionProvenance(
  winner: Record<string, FieldProvenance>,
  filler: Record<string, FieldProvenance>,
): Record<string, FieldProvenance> {
  const out = { ...winner };
  for (const [path, provenance] of Object.entries(filler)) {
    const existing = out[path];
    if (!existing) {
      out[path] = provenance;
      continue;
    }
    const locators = [...new Set([...existing.recordLocators, ...provenance.recordLocators])];
    if (locators.length !== existing.recordLocators.length)
      out[path] = { ...existing, recordLocators: locators };
  }
  return out;
}

/**
 * The winner's envelope with the filler's values in its gaps, evidence and provenance unioned.
 * Both must be the current schema version; the caller gates that.
 */
export function fillCanonicalGaps(
  winner: CanonicalEventEnvelope,
  filler: CanonicalEventEnvelope,
): CanonicalEventEnvelope {
  const { schemaVersion, evidence, producer, fieldProvenance, fieldProvenanceDefaults, ...normalized } =
    winner;
  const {
    schemaVersion: _v,
    evidence: fillerEvidence,
    producer: _p,
    fieldProvenance: fillerProvenance,
    fieldProvenanceDefaults: fillerDefaults,
    ...fillerNormalized
  } = filler;
  // The same record cited by both sides is one pointer, and it keeps the durable record id
  // whichever side carried it — a partial re-import must not erase the id the stored row had.
  const pointers = [...evidence.rawRecords];
  for (const pointer of fillerEvidence.rawRecords) {
    const at = pointers.findIndex((p) => p.source === pointer.source && p.locator === pointer.locator);
    if (at === -1) pointers.push(pointer);
    else if (pointers[at].recordId === undefined && pointer.recordId !== undefined)
      pointers[at] = { ...pointers[at], recordId: pointer.recordId };
  }
  return compactFieldProvenance({
    schemaVersion,
    ...(fillLeaves(normalized, fillerNormalized) as typeof normalized),
    evidence: {
      rawRecords: pointers,
      ...((evidence.sourceArtifactHash ?? fillerEvidence.sourceArtifactHash)
        ? { sourceArtifactHash: evidence.sourceArtifactHash ?? fillerEvidence.sourceArtifactHash }
        : {}),
    },
    producer,
    fieldProvenance: unionProvenance(
      expandFieldProvenance({ fieldProvenance, fieldProvenanceDefaults }),
      expandFieldProvenance({ fieldProvenance: fillerProvenance, fieldProvenanceDefaults: fillerDefaults }),
    ),
  });
}

function isCurrent(envelope: CanonicalEventEnvelope | undefined): envelope is CanonicalEventEnvelope {
  return (
    (envelope as { schemaVersion?: string } | undefined)?.schemaVersion === CANONICAL_EVENT_SCHEMA_VERSION
  );
}

/**
 * The state merge of a re-imported row: the INCOMING envelope wins per field and the stored one
 * fills its gaps — the same trust the flat fields on that row already give a re-import (its
 * description, severity and path overwrite). The one producer that never overwrites is the
 * legacy upgrade: an envelope derived from flat fields at the read boundary and echoed back by a
 * client would otherwise replace the typed one an importer wrote. A future schema version is kept
 * verbatim, whichever side carries it.
 */
export function mergeCanonicalEvents(
  first: CanonicalEventEnvelope | undefined,
  incoming: CanonicalEventEnvelope | undefined,
): CanonicalEventEnvelope | undefined {
  if (!first) return incoming;
  if (!incoming) return first;
  // A stored 1.0.0 envelope is current once relabelled (#1874) — never kept opaque for that alone.
  const stored = migrateCanonicalEnvelope(first);
  const next = migrateCanonicalEnvelope(incoming);
  if (!isCurrent(stored)) return stored;
  if (!isCurrent(next)) return next;
  return next.producer.importer === LEGACY_UPGRADE_IMPORTER
    ? fillCanonicalGaps(stored, next)
    : fillCanonicalGaps(next, stored);
}

/**
 * The envelope of a correlate.mergeGroup row: the PRIMARY's envelope, with every other member's
 * current-version envelope filling its gaps in input order. A primary without an envelope takes
 * the first member's. A primary carrying a future schema version is kept verbatim.
 */
export function mergeGroupCanonical(
  primary: ForensicEvent,
  members: readonly ForensicEvent[],
): CanonicalEventEnvelope | undefined {
  const primaryCanonical = migrateCanonicalEnvelope(primary.canonical);
  if (primaryCanonical && !isCurrent(primaryCanonical)) return primaryCanonical;
  let out = primaryCanonical;
  for (const member of members) {
    const canonical = migrateCanonicalEnvelope(member.canonical);
    if (member === primary || !isCurrent(canonical)) continue;
    out = out ? fillCanonicalGaps(out, canonical) : canonical;
  }
  return out;
}
