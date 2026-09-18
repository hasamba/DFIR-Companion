// #1152 + #1290 Part A — bounded "latest per rowId" derivation and the analyst-configured
// high-value label match, both computed from data sqliteRowStateImport.ts's own mapRow() already
// validated (never a second independent parse). Kept in its own file so sqliteRowStateImport.ts
// stays within its size bound (mirrors canonicalOlevbaFinding.ts's own sibling-file pattern).

import {
  MAX_FIELD_LEN,
  MAX_HIGH_VALUE_LABELS,
  type SqliteRowStateOperation,
} from "./canonicalSqliteRowState.js";

function clip(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max);
}

/** DFIR_SQLITE_HIGH_VALUE_LABELS: comma-separated substrings (analyst-configured, never inferred).
 * An empty/absent var, or a var containing only empty items (e.g. a trailing comma), means no
 * labels — never one empty-string label that would match every table (the #1069 falsy-string
 * lesson applied at item granularity). Bounded to MAX_HIGH_VALUE_LABELS entries, each clipped to
 * MAX_FIELD_LEN, lowercased once (a plain, ICU-stable `.toLowerCase()` — no RegExp is ever built
 * from this input, so there is no ReDoS surface). */
export function parseHighValueLabels(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0)
    .slice(0, MAX_HIGH_VALUE_LABELS)
    .map((s) => clip(s, MAX_FIELD_LEN));
}

/** Case-insensitive SUBSTRING match only against the filename-derived table name. Returns the
 * FIRST configured label (in configured order) that matches, brackets stripped (same forgery
 * guard as `tableLabel` in sqliteRowStateImport.ts — a crafted upload filename must never be able
 * to inject a `[noteName: ...]`-shaped string into a description via this path either). Never
 * matches when the table name itself is unavailable — nothing to compare against. */
export function matchHighValueLabel(
  tableName: string,
  tableNameSource: "filename" | "unavailable",
  labels: readonly string[],
): string | undefined {
  if (tableNameSource !== "filename" || !tableName) return undefined;
  const haystack = tableName.toLowerCase();
  for (const label of labels) {
    if (!haystack.includes(label)) continue;
    const stripped = label.replace(/[[\]]/g, "");
    // A label made ENTIRELY of brackets (e.g. "[") strips to "" — returning it would violate this
    // function's own "absent when none matched" contract for every downstream caller, which only
    // ever falsy-checks the result (code review finding).
    if (stripped) return stripped;
  }
  return undefined;
}

export function highValueClause(label: string | undefined): string {
  if (!label) return "";
  return (
    `; table name matches an analyst-configured high-value label ("${label}") — a ` +
    `filename-derived match only, not independent verification of the table's real schema/content`
  );
}

/** One row's own facts needed for the deferred "latest per rowId" pass — the SAME validated
 * values mapRow() already produced, never a second independent parse (mirrors CarvedDeletedTally's
 * own established discipline in this module). */
export interface LatestRowFacts {
  rowId?: string;
  versionNumber: number;
  columnsDigest: string;
  operation: SqliteRowStateOperation;
}

export interface LatestRowResult {
  index: number;
  ambiguous: boolean;
  multiMember: boolean;
  // A Carved row shares this rowId with a version >= the winner's/tied rows' own version — Carved
  // rows never win (their rowId is a carving-signature reconstruction, not a live index read), but
  // a consumer disclosing "the highest recorded version" must say so, or the prose overclaims in
  // exactly the case this exclusion exists for (code review finding).
  carvedAtOrAboveWinningVersion: boolean;
}

/** Computes, for every rowId group within ONE report, which single row (if any) is "the latest" —
 * see canonicalSqliteRowState.ts's own SQLITE_ROW_STATE_BASIS_V2 for the exact, bounded claim this
 * makes. Returns only the rows that need a flag; every other row is left untouched by the caller.
 * Carved rows never win (their rowId is a carving-signature reconstruction, not a live index read)
 * but still count toward `multiMember`, since the analyst value here is "more than one recorded
 * state exists for this identity," regardless of one member's own provenance. A content-identical
 * tie (same `columnsDigest`) collapses to one winner, arbitrarily but harmlessly, since they are
 * "the same observation" per this module's own dedup philosophy; a content-DIFFERENT tie is
 * reported as ambiguous instead of guessed at. Caller MUST skip this entirely when the report was
 * truncated — a partial scan cannot honestly claim "the highest recorded version." */
export function computeLatestForRowId(rows: readonly LatestRowFacts[]): LatestRowResult[] {
  const groups = new Map<string, number[]>();
  rows.forEach((row, index) => {
    if (!row.rowId) return;
    const arr = groups.get(row.rowId) ?? [];
    arr.push(index);
    groups.set(row.rowId, arr);
  });

  const results: LatestRowResult[] = [];
  for (const indices of groups.values()) {
    const multiMember = indices.length > 1;
    const candidates = indices.filter((i) => rows[i].operation !== "Carved");
    if (candidates.length === 0) continue; // an all-Carved group never gets a winner
    const maxVersion = Math.max(...candidates.map((i) => rows[i].versionNumber));
    const winners = candidates.filter((i) => rows[i].versionNumber === maxVersion);
    const carvedAtOrAboveWinningVersion = indices.some(
      (i) => rows[i].operation === "Carved" && rows[i].versionNumber >= maxVersion,
    );
    if (winners.length === 1) {
      results.push({ index: winners[0], ambiguous: false, multiMember, carvedAtOrAboveWinningVersion });
      continue;
    }
    const digests = new Set(winners.map((i) => rows[i].columnsDigest));
    if (digests.size === 1) {
      results.push({ index: winners[0], ambiguous: false, multiMember, carvedAtOrAboveWinningVersion });
    } else {
      for (const i of winners) {
        results.push({ index: i, ambiguous: true, multiMember, carvedAtOrAboveWinningVersion });
      }
    }
  }
  return results;
}

/** The description clause for one flagged row. Empty for a singleton group's own winner (finding:
 * appending this to every one-row "history" would be near-universal noise, diluting the feature —
 * the canonical `latestForRowId: true` flag is still set for a singleton, just without prose).
 * `carvedAtOrAboveWinningVersion` MUST be disclosed whenever true — without it, "the highest
 * recorded version" is a false claim in the exact case Carved-exclusion exists for (code review
 * finding: a Carved row can carry a higher/equal version than the non-Carved winner). */
export function latestClause(
  rowId: string,
  operation: SqliteRowStateOperation,
  ambiguous: boolean,
  multiMember: boolean,
  carvedAtOrAboveWinningVersion: boolean,
): string {
  const carvedCaveat = carvedAtOrAboveWinningVersion
    ? "; a Carved row for this same rowid, at or above this version, is excluded from this " +
      "comparison — its own identity is a carving-signature reconstruction, not a live index read"
    : "";
  if (ambiguous) {
    return (
      `; more than one row recorded the same (highest) version for row ${rowId} in this report ` +
      `with different content — which reflects the true latest state cannot be determined from ` +
      `this report alone${carvedCaveat}`
    );
  }
  if (!multiMember) return "";
  return operation === "Deleted"
    ? `; the last recorded event for row ${rowId} in this report was its own deletion${carvedCaveat}`
    : `; the highest recorded version for row ${rowId} in this report — not proof this reflects ` +
        `any write after this capture, and a reused rowid may combine two unrelated records' own ` +
        `history${carvedCaveat}`;
}
