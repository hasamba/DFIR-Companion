import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { LateralPath } from "./evidenceGraph.js";

// Analyst dismissal of a reconstructed lateral-movement chain (#92 follow-up).
//
// WHY THIS IS NOT A FALSE-POSITIVE MARKER: a false positive says "this EVIDENCE is wrong" and
// removes the underlying events from the whole case — the timeline, the report, every other graph.
// A lateral path is an INFERENCE drawn from evidence that is usually perfectly real: the logons
// happened, the binary really is on both hosts, but "therefore the attacker pivoted A → B → C" is
// the wrong conclusion. Forcing an analyst to discard real evidence to silence a bad conclusion
// would hide facts they never disputed, so dismissal is its own, narrower decision.
//
// WHAT IT KEYS ON: lateral paths are derived on every read and never stored, so there is no
// durable id to hang a dismissal on — `LateralPath.id` is positional (lateral-path:0, :1) and
// shifts as soon as the data changes. The ordered HOST SEQUENCE is used instead, because that is
// precisely the claim being rejected, and it survives the same route being rebuilt from different
// underlying evidence after a re-import.
export interface LateralPathDismissal {
  id: string;
  key: string;          // ordered host sequence — the durable anchor (see lateralPathKey)
  hostIds: string[];    // the route as dismissed, kept readable for the review/undo list
  note: string;         // why the analyst rejected it (free text, may be empty)
  dismissedAt: string;  // ISO timestamp
}

// A path annotated with its dismissal state, for the "show dismissed" review view.
export type AnnotatedLateralPath = LateralPath & { dismissed: boolean; dismissalNote?: string };

// The claim's identity: the ordered hosts, normalized so trivial formatting differences between a
// stored dismissal and a freshly derived path cannot cause a silent miss.
export function lateralPathKey(hostIds: readonly string[]): string {
  return hostIds.map((h) => h.trim().toLowerCase()).join(">");
}

function dismissedKeys(dismissals: readonly LateralPathDismissal[]): Map<string, LateralPathDismissal> {
  const byKey = new Map<string, LateralPathDismissal>();
  // Re-derive the key from hostIds rather than trusting the stored `key`, so a hand-edited or
  // older file can't hold a stale/mis-normalized anchor that silently matches nothing.
  for (const d of dismissals) byKey.set(d.hostIds?.length ? lateralPathKey(d.hostIds) : d.key, d);
  return byKey;
}

// Drop dismissed routes. EXACT sequence match only: A→B→C→D is a different claim than A→B→C (the
// attacker reached one more host), so dismissing the shorter chain must never hide the longer one.
export function filterDismissedPaths<T extends LateralPath>(
  paths: readonly T[],
  dismissals: readonly LateralPathDismissal[],
): T[] {
  if (dismissals.length === 0) return [...paths];
  const byKey = dismissedKeys(dismissals);
  return paths.filter((p) => !byKey.has(lateralPathKey(p.hostIds)));
}

// Keep every path but flag the dismissed ones — powers the review/undo view, where the analyst
// needs to SEE what they dismissed in order to restore it.
export function annotateDismissedPaths(
  paths: readonly LateralPath[],
  dismissals: readonly LateralPathDismissal[],
): AnnotatedLateralPath[] {
  const byKey = dismissedKeys(dismissals);
  return paths.map((p) => {
    const hit = byKey.get(lateralPathKey(p.hostIds));
    return { ...p, dismissed: !!hit, ...(hit?.note ? { dismissalNote: hit.note } : {}) };
  });
}

// Build a dismissal record for a route. Returns null when the route is not a chain (a path needs
// at least two hosts), so a malformed request can't persist an anchor that matches nothing.
export function buildDismissal(hostIds: readonly string[], note: string, now = new Date()): LateralPathDismissal | null {
  const hosts = hostIds.map((h) => h.trim()).filter((h) => h.length > 0);
  if (hosts.length < 2) return null;
  return {
    id: randomUUID(),
    key: lateralPathKey(hosts),
    hostIds: hosts,
    note: note.trim(),
    dismissedAt: now.toISOString(),
  };
}

// Per-case persistence, mirroring FalsePositiveStore: one JSON file in the case's state dir.
export class LateralPathDismissStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "lateral-path-dismissals.json");
  }

  async load(caseId: string): Promise<LateralPathDismissal[]> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
      if (!Array.isArray(raw)) return [];
      return raw.filter((d): d is LateralPathDismissal => {
        const o = d as Partial<LateralPathDismissal>;
        return typeof o?.id === "string" && Array.isArray(o.hostIds) && o.hostIds.length >= 2;
      });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async save(caseId: string, dismissals: LateralPathDismissal[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(dismissals, null, 2));
  }

  // Add a dismissal, replacing any existing one for the same route so re-dismissing updates the
  // note instead of accumulating duplicates. Returns the stored record, or null if invalid.
  async add(caseId: string, hostIds: readonly string[], note: string): Promise<LateralPathDismissal | null> {
    const record = buildDismissal(hostIds, note);
    if (!record) return null;
    const existing = await this.load(caseId);
    await this.save(caseId, [...existing.filter((d) => lateralPathKey(d.hostIds) !== record.key), record]);
    return record;
  }

  // Restore a route by its key. Returns true when something was actually removed.
  async remove(caseId: string, key: string): Promise<boolean> {
    const existing = await this.load(caseId);
    const remaining = existing.filter((d) => lateralPathKey(d.hostIds) !== key.trim().toLowerCase());
    if (remaining.length === existing.length) return false;
    await this.save(caseId, remaining);
    return true;
  }
}
