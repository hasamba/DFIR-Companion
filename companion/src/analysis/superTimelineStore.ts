import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { ForensicEvent } from "./stateTypes.js";
import { dedupeAppend, capEvents, querySuper, type SuperLabelMap, type SuperQuery, type SuperQueryResult } from "./superTimeline.js";

// Per-case super-timeline: the complete record of every imported event (a copy of the forensic
// timeline + raw host-triage artifacts routed here exclusively). A CAPPED JSON array written via
// atomicWrite (the codebase's "never a bare writeFile" invariant; the cap bounds file size). Labels
// live in a sidecar map so (un)labelling never rewrites the events file. NOT in InvestigationState
// (synthesis never touches it) and deliberately NOT in SNAPSHOT_STATE_FILES (large/raw).

export const DEFAULT_SUPER_MAX = 100_000;

export class SuperTimelineStore {
  constructor(private readonly cases: CaseStore, private readonly max: number = DEFAULT_SUPER_MAX) {}

  private eventsPath(caseId: string): string { return join(this.cases.stateDir(caseId), "super-timeline.json"); }
  private labelsPath(caseId: string): string { return join(this.cases.stateDir(caseId), "super-timeline-labels.json"); }

  private async loadEvents(caseId: string): Promise<ForensicEvent[]> {
    try {
      const parsed = JSON.parse(await readFile(this.eventsPath(caseId), "utf8"));
      return Array.isArray(parsed) ? (parsed as ForensicEvent[]) : [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      return [];   // malformed file: degrade to empty rather than break the case
    }
  }

  private async loadLabels(caseId: string): Promise<SuperLabelMap> {
    try {
      const parsed = JSON.parse(await readFile(this.labelsPath(caseId), "utf8"));
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as SuperLabelMap) : {};
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      return {};
    }
  }

  // Returns how many of `events` were NEW to the store (not already present by id) — so callers can
  // report an accurate "+N events" (a re-import of the same rows dedups to +0).
  async append(caseId: string, events: ForensicEvent[]): Promise<number> {
    if (!events.length) return 0;
    const existing = await this.loadEvents(caseId);
    const existingIds = new Set(existing.map((e) => e.id));
    const addedCount = events.filter((e) => !existingIds.has(e.id)).length;
    const merged = capEvents(dedupeAppend(existing, events), this.max);
    await atomicWrite(this.eventsPath(caseId), JSON.stringify(merged, null, 2));
    // Prune label entries for events the cap evicted — otherwise the sidecar map leaks keys forever
    // (labels are keyed by event id and nothing else garbage-collects them). Only rewrite when something
    // was actually pruned, so the common append-under-cap path stays a single write.
    const labels = await this.loadLabels(caseId);
    const retained = new Set(merged.map((e) => e.id));
    const pruned = Object.keys(labels).filter((id) => !retained.has(id));
    if (pruned.length) {
      const next: SuperLabelMap = {};
      for (const [id, val] of Object.entries(labels)) if (retained.has(id)) next[id] = val;
      await atomicWrite(this.labelsPath(caseId), JSON.stringify(next, null, 2));
    }
    return addedCount;
  }

  // `labelMap` overrides the built-in per-event label sidecar — the route passes the case's analyst
  // TAGS here so `labels=`/`labelsAvailable` filter by tags (unifying the two labelling systems). When
  // omitted, falls back to the legacy sidecar map.
  async query(caseId: string, q: SuperQuery, labelMap?: SuperLabelMap): Promise<SuperQueryResult> {
    return querySuper(await this.loadEvents(caseId), labelMap ?? (await this.loadLabels(caseId)), q);
  }

  async get(caseId: string, id: string): Promise<ForensicEvent | null> {
    return (await this.loadEvents(caseId)).find((e) => e.id === id) ?? null;
  }

  // Every stored event (unpaginated) — for the manual "Run tagger" pass over the whole raw timeline.
  async all(caseId: string): Promise<ForensicEvent[]> {
    return this.loadEvents(caseId);
  }

  async setLabels(caseId: string, eventId: string, labels: string[]): Promise<void> {
    const map = await this.loadLabels(caseId);
    const clean = [...new Set(labels.map((l) => String(l).trim()).filter(Boolean))];
    if (clean.length) map[eventId] = clean; else delete map[eventId];
    await atomicWrite(this.labelsPath(caseId), JSON.stringify(map, null, 2));
  }
}
