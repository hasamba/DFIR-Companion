/**
 * The per-case sweeps every import path runs after it lands evidence, plus the undo checkpoint that
 * makes an import reversible. Lifted out of createApp by #416.
 *
 * These four belong together because they are all READ-MODIFY-WRITE passes over one case's already-
 * persisted state, all of them idempotent, and all of them called from the same three seams
 * (/import, ingestStreamed, the Velociraptor collect). Grouping them is what lets those seams take
 * ONE dependency instead of four.
 *
 * WHY WHITELIST AND NSRL WRITE FALSE-POSITIVE MARKERS rather than deleting anything: a known-good
 * hash is still evidence. Marking reuses the existing false-positive machinery, so the decision is
 * reversible, visible in the "False Positives" panel, and attributed — which "the importer dropped
 * it" never would be. Both are opt-in: an empty whitelist / absent NSRL set makes them no-ops.
 */
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import { FalsePositiveStore, markerId, type FalsePositiveMarker } from "../analysis/falsePositive.js";
import { whitelistMatches } from "../analysis/iocWhitelist.js";
import { nsrlMatchIocs, nsrlMatchEvents } from "../analysis/nsrl.js";
import type { NsrlDb } from "../analysis/nsrlDb.js";
import { applyDeobfuscation } from "../analysis/applyDeobfuscation.js";
import { pushCheckpoint } from "../analysis/importUndo.js";
import { DEFAULT_PLAYBOOK_CONTROL, type PlaybookControl } from "../analysis/playbookControl.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import type { InvestigationState } from "../analysis/stateTypes.js";

export interface CaseAppliersDeps {
  store: CaseStore;
  options: AppOptions;
  /** Serializes a case's load->save critical section (see createApp's runStateExclusive). */
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  /**
   * The LIVE NSRL SQLite handle. A function, not a value: Settings -> NSRL connect/disconnect swaps
   * it at runtime, and a captured value would keep answering from a closed database.
   */
  nsrlDb: () => NsrlDb | undefined;
}

export interface CaseAppliers {
  /** The shared FalsePositiveStore the whitelist/NSRL sweeps write through. */
  readonly falsePositives: FalsePositiveStore;
  pushImportCheckpoint(caseId: string, beforeState: InvestigationState, label: string): Promise<void>;
  applyWhitelistToCase(caseId: string): Promise<{ matched: number; added: number }>;
  applyDeobfuscationToCase(caseId: string): Promise<{ deobfuscated: number; newIocs: number }>;
  applyNsrlToCase(caseId: string): Promise<{ matchedIocs: number; matchedEvents: number; added: number }>;
  loadPlaybookControl(caseId: string): Promise<PlaybookControl>;
  syncPlaybook(caseId: string): Promise<PlaybookTask[]>;
}

export function createCaseAppliers({
  store,
  options,
  runStateExclusive,
  nsrlDb,
}: CaseAppliersDeps): CaseAppliers {
  // Client-confirmed false-positive findings/IOCs. Marking one re-runs synthesis so the AI
  // re-derives its conclusions without it.
  const falsePositives = new FalsePositiveStore(store);

  // #76: snapshot the PRE-import investigation state (findings + IOCs + timeline + MITRE + attacker
  // path — everything the import and its synthesis change) onto the per-case undo stack so the whole
  // import can be rolled back. Best-effort — undo is a convenience and must NEVER break the import.
  // Callers gate on whether the import actually changed anything (no checkpoint for a no-op re-import).
  async function pushImportCheckpoint(
    caseId: string,
    beforeState: InvestigationState,
    label: string,
  ): Promise<void> {
    const undoStore = options.importUndoStore;
    if (!undoStore) return;
    try {
      // Atomic load->push->save under the store's per-case lock: overlapping imports (e.g. bulk
      // import firing requests seconds apart while the previous one's async work is still in
      // flight) must not race on the same undo-stack file (lost checkpoints, duplicate huge
      // simultaneous tmp writes).
      await undoStore.mutate(caseId, (stack) => ({
        stack: pushCheckpoint(
          stack,
          { label, at: new Date().toISOString(), state: beforeState },
          undoStore.depth(),
          undoStore.byteBudget(),
        ),
        result: undefined,
      }));
      options.onImportUndo?.(caseId);
    } catch {
      /* non-fatal */
    }
  }

  // ── IOC whitelist (Phase 2 of #35) ─────────────────────────────────────────────────────────
  // A GLOBAL, environment-level set of "known-good" patterns the analyst maintains (internal IP
  // ranges as CIDR, known-good hashes, regexes for internal domains). An IOC matching a rule is
  // auto-marked a FALSE POSITIVE — reusing the false-positive machinery, so it's reversible and
  // shows in the "False Positives" panel. Auto-applied on import; also on demand per case.
  //
  // Pure read-modify-write on false-positive.json (no re-synthesis here — the caller decides).
  // Returns how many IOCs matched and how many NEW markers were added.
  async function applyWhitelistToCase(caseId: string): Promise<{ matched: number; added: number }> {
    if (!options.iocWhitelistStore || !options.stateStore) return { matched: 0, added: 0 };
    const rules = await options.iocWhitelistStore.load();
    if (rules.length === 0) return { matched: 0, added: 0 };
    const state = await options.stateStore.load(caseId);
    const matches = whitelistMatches(state.iocs, rules);
    if (matches.length === 0) return { matched: 0, added: 0 };
    const markers = await falsePositives.load(caseId);
    const byId = new Map<string, FalsePositiveMarker>(markers.map((m) => [m.id, m]));
    let added = 0;
    for (const { ioc, rule } of matches) {
      const id = markerId("ioc", ioc.value);
      if (byId.has(id)) continue;
      byId.set(id, {
        id,
        kind: "ioc",
        ref: ioc.value,
        reason: "known-good-tool",
        note: `auto-whitelist: ${rule.match} ${rule.pattern}${rule.note ? ` — ${rule.note}` : ""}`,
        markedAt: new Date().toISOString(),
        markedBy: "anonymous",
        label: ioc.value,
      });
      added++;
    }
    if (added > 0) await falsePositives.save(caseId, [...byId.values()]);
    return { matched: matches.length, added };
  }

  // Apply the deobfuscation pass to a case: scan the forensic timeline for obfuscated command
  // lines (PowerShell -enc, base64 blobs), decode them, extract hidden IOCs, and persist.
  // Pure read-modify-write on state.json (no re-synthesis here — the caller decides).
  // Returns how many events were decoded and how many new IOCs were extracted.
  async function applyDeobfuscationToCase(
    caseId: string,
  ): Promise<{ deobfuscated: number; newIocs: number }> {
    if (!options.stateStore) return { deobfuscated: 0, newIocs: 0 };
    return runStateExclusive(caseId, async () => {
      const state = await options.stateStore!.load(caseId);
      const result = applyDeobfuscation(state);
      if (result.deobfuscated === 0 && result.newIocs === 0) return { deobfuscated: 0, newIocs: 0 };
      await options.stateStore!.save(result.state);
      options.onState?.(result.state);
      return { deobfuscated: result.deobfuscated, newIocs: result.newIocs };
    });
  }

  // ── NSRL known-good hashes (#63) ───────────────────────────────────────────────────────────────
  // A GLOBAL set of known-software file hashes (NIST NSRL / RDS). A forensic event whose file hash —
  // or an IOC whose value — is in the set is a known-good file, auto-marked a FALSE POSITIVE to
  // reduce noise. Reuses the false-positive machinery (reversible, shown in "False Positives").
  // Auto-applied on import; also on demand per case. Opt-in (the set starts empty).
  //
  // Marks an ioc BY VALUE and an event BY ID, so the raw evidence is preserved and un-marking
  // restores it. Returns how many IOCs/events matched and how many NEW markers were added.
  async function applyNsrlToCase(
    caseId: string,
  ): Promise<{ matchedIocs: number; matchedEvents: number; added: number }> {
    if (!options.stateStore) return { matchedIocs: 0, matchedEvents: 0, added: 0 };
    // A hash is known-good if EITHER backend has it: the flat in-memory set (small custom lists) or
    // the on-demand SQLite RDS (the full ~160 GB set).
    const flat = options.nsrlStore ? await options.nsrlStore.load() : undefined;
    const haveFlat = Boolean(flat && flat.size > 0);
    const db = nsrlDb();
    if (!haveFlat && !db) return { matchedIocs: 0, matchedEvents: 0, added: 0 };
    const lookup = (h: string): boolean => (flat?.has(h) ?? false) || (db?.has(h) ?? false);
    const state = await options.stateStore.load(caseId);
    const iocMatches = nsrlMatchIocs(state.iocs, lookup);
    const eventMatches = nsrlMatchEvents(state.forensicTimeline, lookup);
    if (iocMatches.length === 0 && eventMatches.length === 0)
      return { matchedIocs: 0, matchedEvents: 0, added: 0 };
    const markers = await falsePositives.load(caseId);
    const byId = new Map<string, FalsePositiveMarker>(markers.map((m) => [m.id, m]));
    const now = new Date().toISOString();
    let added = 0;
    for (const { ioc, hash } of iocMatches) {
      const id = markerId("ioc", ioc.value);
      if (byId.has(id)) continue;
      byId.set(id, {
        id,
        kind: "ioc",
        ref: ioc.value,
        reason: "known-good-tool",
        note: `NSRL known-good hash (${hash})`,
        markedAt: now,
        markedBy: "anonymous",
        label: ioc.value,
      });
      added++;
    }
    for (const { event, hash } of eventMatches) {
      const id = markerId("event", event.id);
      if (byId.has(id)) continue;
      byId.set(id, {
        id,
        kind: "event",
        ref: event.id,
        reason: "known-good-tool",
        note: `NSRL known-good file (${hash})`,
        markedAt: now,
        markedBy: "anonymous",
        label: event.description,
      });
      added++;
    }
    if (added > 0) await falsePositives.save(caseId, [...byId.values()]);
    return { matchedIocs: iocMatches.length, matchedEvents: eventMatches.length, added };
  }

  // Per-case playbook derivation (issue #36). The playbook + hunt-suggestion/outcome ROUTES live in
  // routes/playbookHunts.ts; these two helpers are shared with the POST /cases/:id/push/iris route,
  // which is why they are here rather than inside that route module.
  async function loadPlaybookControl(caseId: string): Promise<PlaybookControl> {
    return options.playbookControlStore
      ? options.playbookControlStore.load(caseId)
      : { ...DEFAULT_PLAYBOOK_CONTROL };
  }

  // Re-derive against current state honoring the case's template setting (no-op-safe write).
  async function syncPlaybook(caseId: string): Promise<PlaybookTask[]> {
    if (!options.playbookStore || !options.stateStore)
      return options.playbookStore ? options.playbookStore.load(caseId) : [];
    const state = await options.stateStore.load(caseId);
    const { useTemplates } = await loadPlaybookControl(caseId);
    return options.playbookStore.sync(caseId, state, { useTemplates });
  }

  return {
    falsePositives,
    pushImportCheckpoint,
    applyWhitelistToCase,
    applyDeobfuscationToCase,
    applyNsrlToCase,
    loadPlaybookControl,
    syncPlaybook,
  };
}
