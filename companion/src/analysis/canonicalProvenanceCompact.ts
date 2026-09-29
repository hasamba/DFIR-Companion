import { z } from "zod";

// The stored form of canonical.fieldProvenance (#1874). Every normalized leaf of an envelope carries
// its own provenance entry, and in a typical import nearly all of them repeat the same origin,
// confidence, record locators and default derivation text — about 2.3 KB of a 3.8 KB event. The
// compact form writes each repeated value ONCE, in `fieldProvenanceDefaults`, and leaves it out of
// every entry that equals it. Nothing is dropped: `expandFieldProvenance` rebuilds the exact
// per-field record, and it is the ONE way any reader gets at provenance.
//
// THE RULE, per entry, when the envelope has a defaults block:
//   origin / confidence / recordLocators — an absent value is the default.
//   derivation — an absent value is the default ONLY when the entry's (expanded) origin is
//     "derived". A raw entry never inherits a derivation.
// An envelope WITHOUT a defaults block is the verbose form every envelope had before 1.1.0, and is
// read exactly as written.
//
// WHY IT IS LOSSLESS. `compactFieldProvenance` only ever removes a value that EQUALS the default
// that replaces it, and it only sets a default for a field when every entry the default would apply
// to already carries that field. So "absent" never has to mean both "the default" and "genuinely
// missing". Contract for writers: an entry written straight into a COMPACT envelope's map (as
// siemDnsConnJoin.ts and awsReplicas.ts do) must be complete — a derived entry written without a
// derivation would inherit the default rather than be reported as rule-less.

/** The schema version whose envelopes may carry a defaults block. */
export const COMPACT_PROVENANCE_SCHEMA_VERSION = "1.1.0" as const;
/** Every envelope written before #1874: always verbose; migrated by relabelling (see below). */
export const VERBOSE_PROVENANCE_SCHEMA_VERSION = "1.0.0" as const;

const originSchema = z.enum(["raw", "derived"]);
const confidenceSchema = z.enum(["high", "medium", "low"]);

/** One stored entry. Origin, confidence and locators may be left to the defaults block. */
export const storedFieldProvenanceSchema = z.object({
  origin: originSchema.optional(),
  confidence: confidenceSchema.optional(),
  rawFields: z.array(z.string()).optional(),
  derivation: z.string().optional(),
  recordLocators: z.array(z.string().min(1)).min(1).optional(),
});

export const fieldProvenanceDefaultsSchema = z.object({
  origin: originSchema.optional(),
  confidence: confidenceSchema.optional(),
  derivation: z.string().optional(),
  recordLocators: z.array(z.string().min(1)).min(1).optional(),
});

export type StoredFieldProvenance = z.infer<typeof storedFieldProvenanceSchema>;
export type FieldProvenanceDefaults = z.infer<typeof fieldProvenanceDefaultsSchema>;

/** One field's provenance as every reader sees it — the complete, verbose record. */
export interface FieldProvenance {
  origin: z.infer<typeof originSchema>;
  confidence: z.infer<typeof confidenceSchema>;
  rawFields?: string[];
  derivation?: string;
  recordLocators: string[];
}

/** Anything that carries a provenance map: a full envelope, or a partial view of one. */
export interface ProvenanceCarrier {
  fieldProvenance?: Record<string, StoredFieldProvenance>;
  fieldProvenanceDefaults?: FieldProvenanceDefaults;
}

type Defaultable = "origin" | "confidence" | "derivation" | "recordLocators";
const REQUIRED: readonly Defaultable[] = ["origin", "confidence", "recordLocators"];

function sameLocators(a: readonly string[] | undefined, b: readonly string[] | undefined): boolean {
  return !!a && !!b && a.length === b.length && a.every((v, i) => v === b[i]);
}

function inherits(entry: StoredFieldProvenance, d: FieldProvenanceDefaults, field: Defaultable): boolean {
  if (entry[field] !== undefined || d[field] === undefined) return false;
  return field !== "derivation" || (entry.origin ?? d.origin) === "derived";
}

function expandEntry(entry: StoredFieldProvenance, d: FieldProvenanceDefaults): StoredFieldProvenance {
  if (!(["origin", "confidence", "derivation", "recordLocators"] as const).some((f) => inherits(entry, d, f)))
    return entry;
  const { origin, confidence, rawFields, derivation, recordLocators, ...rest } = entry;
  const o = origin ?? d.origin;
  const c = confidence ?? d.confidence;
  const dv = derivation ?? (o === "derived" ? d.derivation : undefined);
  const rl = recordLocators ?? (d.recordLocators ? [...d.recordLocators] : undefined);
  // The key order createCanonicalEvent writes, so an expanded export is byte-identical to the
  // verbose one it replaces.
  return {
    ...(o !== undefined ? { origin: o } : {}),
    ...(c !== undefined ? { confidence: c } : {}),
    ...(rawFields !== undefined ? { rawFields } : {}),
    ...(dv !== undefined ? { derivation: dv } : {}),
    ...(rl !== undefined ? { recordLocators: rl } : {}),
    ...rest,
  };
}

/**
 * Every field's provenance, complete. THE reader helper: validation, merge, diagnostics and
 * exports all read provenance through this, never through `fieldProvenance` directly. A verbose
 * envelope's map is returned as it is (same object).
 */
export function expandFieldProvenance(
  envelope: ProvenanceCarrier | null | undefined,
): Record<string, FieldProvenance> {
  const map = envelope?.fieldProvenance ?? {};
  const d = envelope?.fieldProvenanceDefaults;
  if (!d) return map as Record<string, FieldProvenance>;
  const out: Record<string, StoredFieldProvenance> = {};
  for (const [path, entry] of Object.entries(map)) out[path] = expandEntry(entry, d);
  return out as Record<string, FieldProvenance>;
}

/** One field's complete provenance, or undefined when the envelope has none for that path. */
export function fieldProvenanceAt(
  envelope: ProvenanceCarrier | null | undefined,
  path: string,
): FieldProvenance | undefined {
  const entry = envelope?.fieldProvenance?.[path];
  if (!entry) return undefined;
  const d = envelope?.fieldProvenanceDefaults;
  return (d ? expandEntry(entry, d) : entry) as FieldProvenance;
}

/** Entries still missing a required value after expansion — the schema reports these. */
export function incompleteFieldProvenance(envelope: ProvenanceCarrier): { path: string; field: string }[] {
  const out: { path: string; field: string }[] = [];
  for (const [path, entry] of Object.entries(expandFieldProvenance(envelope))) {
    for (const field of REQUIRED) if (entry[field] === undefined) out.push({ path, field });
  }
  return out;
}

/**
 * The envelope schema as the boundary uses it: a 1.0.0 envelope is accepted by migrating it, and
 * every provenance entry must be complete once expanded — the same "Required" issue at the same
 * path a verbose entry missing that value always produced.
 */
export function acceptingStoredProvenance<Out extends ProvenanceCarrier, In>(
  schema: z.ZodType<Out, z.ZodTypeDef, In>,
): z.ZodType<Out, z.ZodTypeDef, unknown> {
  return z.preprocess(
    migrateCanonicalEnvelope,
    schema.superRefine((envelope, ctx) => {
      for (const { path, field } of incompleteFieldProvenance(envelope))
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["fieldProvenance", path, field],
          message: "Required",
        });
    }),
  );
}

// The most frequent value among `values` (ties: first seen), or undefined when none repeats — a
// default used by one entry saves nothing.
function mostFrequent<T>(values: readonly T[], key: (v: T) => string): T | undefined {
  const counts = new Map<string, { value: T; n: number }>();
  for (const v of values) {
    const k = key(v);
    const hit = counts.get(k);
    if (hit) hit.n++;
    else counts.set(k, { value: v, n: 1 });
  }
  let best: { value: T; n: number } | undefined;
  for (const c of counts.values()) if (!best || c.n > best.n) best = c;
  return best && best.n >= 2 ? best.value : undefined;
}

// A default is chosen for a field only when EVERY entry it would apply to carries that field.
function chooseDefaults(entries: readonly StoredFieldProvenance[]): FieldProvenanceDefaults {
  const all = <K extends Defaultable>(field: K, of = entries) =>
    of.every((e) => e[field] !== undefined)
      ? of.map((e) => e[field] as NonNullable<StoredFieldProvenance[K]>)
      : [];
  const origin = mostFrequent(all("origin"), String);
  const confidence = mostFrequent(all("confidence"), String);
  const locators = mostFrequent(all("recordLocators"), (v) => JSON.stringify(v));
  const derived = entries.filter((e) => e.origin === "derived");
  const derivation = mostFrequent(all("derivation", derived), String);
  return {
    ...(origin !== undefined ? { origin } : {}),
    ...(confidence !== undefined ? { confidence } : {}),
    ...(derivation !== undefined ? { derivation } : {}),
    ...(locators !== undefined ? { recordLocators: [...locators] } : {}),
  };
}

function stripEntry(entry: StoredFieldProvenance, d: FieldProvenanceDefaults): StoredFieldProvenance {
  const expandedOrigin = entry.origin ?? d.origin;
  const drop = {
    origin: d.origin !== undefined && entry.origin === d.origin,
    confidence: d.confidence !== undefined && entry.confidence === d.confidence,
    derivation:
      expandedOrigin === "derived" && d.derivation !== undefined && entry.derivation === d.derivation,
    recordLocators: sameLocators(entry.recordLocators, d.recordLocators),
  };
  if (!drop.origin && !drop.confidence && !drop.derivation && !drop.recordLocators) return entry;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(entry)) if (!drop[k as Defaultable]) out[k] = v;
  return out;
}

/**
 * The compact form of an envelope's provenance. Pure; returns the same object when nothing can be
 * written more compactly. An envelope that already has a defaults block keeps it and only loses
 * values that repeat it. Invariant: expandFieldProvenance(result) deep-equals
 * expandFieldProvenance(envelope).
 */
export function compactFieldProvenance<T extends ProvenanceCarrier>(envelope: T): T {
  const map = envelope.fieldProvenance;
  if (!map) return envelope;
  const entries = Object.entries(map);
  const existing = envelope.fieldProvenanceDefaults;
  const defaults = existing ?? chooseDefaults(entries.map(([, e]) => e));
  if (!existing && !Object.keys(defaults).length) return envelope;
  let changed = !existing;
  const out: Record<string, StoredFieldProvenance> = {};
  for (const [path, entry] of entries) {
    const stripped = stripEntry(entry, defaults);
    if (stripped !== entry) changed = true;
    out[path] = stripped;
  }
  if (!changed) return envelope;
  return { ...envelope, fieldProvenance: out, fieldProvenanceDefaults: defaults };
}

/** The envelope with its provenance written out in full and no defaults block — for exports. */
export function withExpandedFieldProvenance<T extends ProvenanceCarrier>(envelope: T): T {
  if (!envelope.fieldProvenanceDefaults) return envelope;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(envelope)) {
    if (k === "fieldProvenanceDefaults") continue;
    out[k] = k === "fieldProvenance" ? expandFieldProvenance(envelope) : v;
  }
  return out as T;
}

/**
 * 1.0.0 → 1.1.0: a 1.0.0 envelope is always verbose, and a verbose envelope is a valid 1.1.0 one,
 * so the migration is the relabel alone. 1.0.0 had no defaults block, so a stray one is dropped
 * rather than given a meaning it never had. Any other version is returned untouched.
 */
export function migrateCanonicalEnvelope<T>(envelope: T): T {
  const version = (envelope as { schemaVersion?: unknown } | null | undefined)?.schemaVersion;
  if (version !== VERBOSE_PROVENANCE_SCHEMA_VERSION) return envelope;
  const { fieldProvenanceDefaults: _stray, ...rest } = envelope as T & ProvenanceCarrier;
  return { ...rest, schemaVersion: COMPACT_PROVENANCE_SCHEMA_VERSION } as T;
}

/**
 * An event whose CURRENT-version envelope is still verbose (a 1.0.0 envelope, relabelled on read),
 * with its provenance compacted — the save boundary's step, so an old case shrinks on its next save.
 * Already-compact and unknown-version envelopes are returned untouched, cheaply.
 */
export function compactEventProvenance<E extends { canonical?: unknown }>(event: E): E {
  const canonical = event.canonical as (ProvenanceCarrier & { schemaVersion?: unknown }) | undefined;
  if (!canonical || canonical.fieldProvenanceDefaults) return event;
  if (canonical.schemaVersion !== COMPACT_PROVENANCE_SCHEMA_VERSION) return event;
  const compact = compactFieldProvenance(canonical);
  return compact === canonical ? event : { ...event, canonical: compact };
}

/** A state whose forensic events carry their provenance written out in full — for exports. */
export function withExpandedEventProvenance<S extends { forensicTimeline?: { canonical?: unknown }[] }>(
  state: S,
): S {
  const events = state.forensicTimeline;
  if (!events?.some((e) => (e.canonical as ProvenanceCarrier | undefined)?.fieldProvenanceDefaults))
    return state;
  return {
    ...state,
    forensicTimeline: events.map((e) => {
      const canonical = e.canonical as ProvenanceCarrier | undefined;
      return canonical?.fieldProvenanceDefaults
        ? { ...e, canonical: withExpandedFieldProvenance(canonical) }
        : e;
    }),
  };
}
