// The observed-state model for configuration snapshots (#2305): a Microsoft-Extractor-Suite export
// of inbox rules, transport rules, OAuth grants or MFA methods says what the tenant held WHEN IT WAS
// COLLECTED. It says nothing about when that state began or who set it, so a snapshot never becomes
// an action ("New-InboxRule"); it becomes an observation stamped with the collection time.
//
// Two keys per object, kept apart on purpose:
//   identity — provider + tenant + object (mailbox + rule id, app + scope + principal, user). Stable
//              across snapshots: it is what "the same rule" means.
//   state    — the object's mutable columns, minus the ones that are pure timestamps (WhenChanged,
//              CreationTimestamp, ...), hashed. Same identity + same state → nothing new.
// Comparison is by OBSERVATION time, never import order: importing an older snapshot after a newer
// one never announces a change.

import { createHash } from "node:crypto";

export type SnapshotState = Readonly<Record<string, string>>;

/** One stored observation of one object (persisted per case by cloudStateStore.ts). */
export interface StoredSnapshotObservation {
  /** sha256 of the identity key — the store's entity id. Never the raw key. */
  id: string;
  /** When the state was observed (the collection time). Not named `timestamp`: see the store. */
  observedAt: string;
  stateHash: string;
  state: SnapshotState;
}

/** What one parsed row says about its object at the collection time. */
export interface SnapshotObservation {
  identityKey: string;
  state: SnapshotState;
}

export type SnapshotDecision =
  | { kind: "new" }
  | { kind: "changed"; previous: StoredSnapshotObservation; diff: string[] }
  | { kind: "unchanged" }
  | { kind: "duplicate" }
  | { kind: "older" };

const ID_HEX = 24;
const DIFF_SHOWN = 4;
const DIFF_VALUE_MAX = 60;

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

/** provider|tenant|objectType|object, lowercased. Tenant is "" when the export does not name one. */
export function identityKey(provider: string, tenant: string, objectType: string, object: string): string {
  return [provider, tenant, objectType, object].map((p) => p.trim().toLowerCase()).join("|");
}

export const identityId = (key: string): string => sha(`snapshot-identity\u0000${key}`).slice(0, ID_HEX);

/** Order-independent hash of the state record. */
export function stateHash(state: SnapshotState): string {
  const keys = Object.keys(state).sort();
  return sha(keys.map((k) => `${k}=${state[k]}`).join("\u0000")).slice(0, ID_HEX);
}

const show = (v: string | undefined): string => {
  if (v === undefined || v === "") return "(empty)";
  const flat = v.replace(/[\u0000-\u001f\u007f]+/g, " ");
  return `"${flat.slice(0, DIFF_VALUE_MAX)}${flat.length > DIFF_VALUE_MAX ? "…" : ""}"`;
};

/**
 * The columns whose value differs, compared on the columns BOTH records hold — a column one MES
 * version writes and another does not is not a change of state. Bounded for display.
 */
export function stateDiff(before: SnapshotState, after: SnapshotState): string[] {
  const keys = Object.keys(after)
    .filter((k) => k in before && before[k] !== after[k])
    .sort();
  const shown = keys.slice(0, DIFF_SHOWN).map((k) => `${k} ${show(before[k])} → ${show(after[k])}`);
  return keys.length > DIFF_SHOWN ? [...shown, `+${keys.length - DIFF_SHOWN} more`] : shown;
}

const at = (o: { observedAt: string }): number => Date.parse(o.observedAt);

function latest(list: readonly StoredSnapshotObservation[]): StoredSnapshotObservation | undefined {
  return list.reduce<StoredSnapshotObservation | undefined>(
    (m, o) => (!m || at(o) >= at(m) ? o : m),
    undefined,
  );
}

/**
 * What a new observation adds, given every stored observation of the same identity:
 *   new        — the object was never observed before;
 *   duplicate  — this exact observation (same time, same state) is stored: a re-import;
 *   older      — the object was already observed at a LATER time: no change is announced;
 *   unchanged  — the latest earlier observation holds the same state;
 *   changed    — it holds a different state: one change observation with a short diff.
 */
export function decide(
  history: readonly StoredSnapshotObservation[],
  observedAt: string,
  state: SnapshotState,
): SnapshotDecision {
  if (!history.length) return { kind: "new" };
  const hash = stateHash(state);
  const t = Date.parse(observedAt);
  if (history.some((o) => at(o) === t && o.stateHash === hash)) return { kind: "duplicate" };
  if (history.some((o) => at(o) > t)) return { kind: "older" };
  const previous = latest(history.filter((o) => at(o) <= t));
  if (!previous || previous.stateHash === hash) return { kind: "unchanged" };
  const diff = stateDiff(previous.state, state);
  return diff.length ? { kind: "changed", previous, diff } : { kind: "unchanged" };
}

// ───────────────────────────── collection time ─────────────────────────────

export interface CollectionTime {
  observedAt: string;
  /** Plain-language basis, shown in every event's detail. */
  basis: string;
  fromFileName: boolean;
}

// MES names every output `yyyyMMdd-HHmmss-<Postfix>.csv` from [datetime]::Now (Init-OutputDir). The
// stored evidence name adds a `NNNN_` sequence prefix in front of it.
const MES_NAME_TIME = /(?:^|[_/\\])(\d{4})(\d{2})(\d{2})-?(\d{2})(\d{2})(\d{2})-[A-Za-z][^/\\]*$/;

function fileNameTime(label: string): string | null {
  const m = MES_NAME_TIME.exec(label);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}Z`;
  const ms = Date.parse(iso);
  // Reject a rolled-over date (2026-02-31 parses as March 3 in some engines).
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) === iso.slice(0, 19) ? iso : null;
}

/**
 * The collection time of a snapshot file. None of the four MES snapshots carries a collection-time
 * column (WhenChanged / CreationTimestamp / StartTime are object history, kept as detail only), so:
 * the MES file-name time when the name carries one, else the import time — and the event says which.
 */
export function collectionTime(label: string, importedAt: string): CollectionTime {
  const named = fileNameTime(label);
  if (named)
    return {
      observedAt: named,
      fromFileName: true,
      basis:
        "collection time from the MES file name (the collecting machine's local clock; the zone is not recorded, read as UTC)",
    };
  return {
    observedAt: importedAt,
    fromFileName: false,
    basis:
      "import time — the file name carries no MES collection time and the export has no collection-time column, so the true collection time is earlier and unknown",
  };
}

// ───────────────────────────── row helpers (shared by the shape mappers) ─────────────────────────────

/** One CSV row, keys lowercased and trimmed. */
export type SnapRow = Readonly<Record<string, string>>;

/** The first non-empty value among the given (lowercased) column names. */
export function col(row: SnapRow, ...names: string[]): string {
  for (const n of names) {
    const v = row[n];
    if (v !== undefined && v.trim() !== "") return v.trim();
  }
  return "";
}

// Columns that are timestamps of the object's own history: kept as detail, never part of the
// state hash — a WhenChanged touched by Exchange housekeeping is not a change of what the rule does.
const HISTORY_COLUMNS = new Set([
  "whenchanged",
  "whencreated",
  "creationtimestamp",
  "createddatetime",
  "starttime",
  "expirytime",
  "lastmodifiedtime",
]);

/** The row's mutable state: every column except the identity columns and the history timestamps. */
export function stateOf(row: SnapRow, identityColumns: readonly string[]): SnapshotState {
  const skip = new Set(identityColumns);
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(row)) {
    if (!skip.has(k) && !HISTORY_COLUMNS.has(k)) out[k] = v.trim();
  }
  return out;
}

/** History timestamps present on the row, for the event detail ("WhenChanged 11/1/2026 ..."). */
export function historyDetail(row: SnapRow): string[] {
  return Object.entries(row)
    .filter(([k, v]) => HISTORY_COLUMNS.has(k) && v.trim())
    .map(([k, v]) => `${k} ${clean(v, 40)} (object history, not the observation time)`);
}

/** Adversary-controlled text for a description: control characters flattened, length capped. */
export function clean(s: string, max: number): string {
  const flat = s.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

export const quoted = (s: string, max: number): string => `"${clean(s, max)}"`;

// An SMTP address wherever it sits: `a@b`, `"a@b" [SMTP:a@b]`, `Name <a@b>`, `smtp:a@b`.
const EMAIL = /[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

/** The distinct SMTP addresses in a cell, lowercased. */
export function emailsIn(v: string): string[] {
  return [...new Set((v.match(EMAIL) ?? []).map((a) => a.toLowerCase()))];
}

export const domainOfEmail = (a: string): string => a.slice(a.lastIndexOf("@") + 1).toLowerCase();

/** What a shape mapper makes of one row. `summary` and `subject` are already cleaned for display. */
export interface MappedSnapshot extends SnapshotObservation {
  /** "inbox rule on user1@example.com" — what was observed. */
  subject: string;
  /** What the state says, actions first: "forwards to x@example.net (outside …), …". */
  summary: string;
  /** Detail-only facts (object history, the rule's own description), never hashed. */
  details: string[];
  severity: "Info" | "Low" | "Medium" | "High";
  mitre: string[];
}
