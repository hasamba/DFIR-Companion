import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Analyst-pinned findings (#220). The analyst pins the most important findings so they stay
// visible in a dedicated strip while scrolling the timeline or graph. Kept as an ORDERED list
// in a per-case side file (`state/pinned-findings.json`) — NOT in InvestigationState, so
// synthesis never wipes an analyst's pins. Each pin references a finding by id; the dashboard
// resolves it against the live findings (a pin whose finding no longer exists is simply not
// rendered) and offers a one-click jump. Capped to a small number to avoid clutter — the whole
// point is a curated shortlist, not a second copy of the findings list.

// Default cap on how many findings can be pinned at once (issue asks for ~5). Overridable via
// DFIR_MAX_PINNED_FINDINGS for analysts who want a longer shortlist.
export const DEFAULT_MAX_PINNED_FINDINGS = 5;

export const pinnedFindingSchema = z.object({
  findingId: z.string(),
  pinnedBy: z.string(),
  pinnedAt: z.string(),
});

export type PinnedFinding = z.infer<typeof pinnedFindingSchema>;
const pinnedFindingsSchema = z.array(pinnedFindingSchema).catch([]);

export interface NewPin {
  findingId: string;
  pinnedBy?: string;
}

// Raised by pin() when the cap is already reached, so the route can map it to a 409 (as opposed
// to a generic 500) and the dashboard can tell the analyst to unpin something first.
export class PinLimitError extends Error {
  constructor(public readonly max: number) {
    super(`pin limit reached (max ${max})`);
    this.name = "PinLimitError";
  }
}

export class PinnedFindingsStore {
  private readonly max: number;

  constructor(private readonly cases: CaseStore, max?: number) {
    this.max = max && max > 0 ? Math.floor(max) : DEFAULT_MAX_PINNED_FINDINGS;
  }

  // The active cap — surfaced to the dashboard so it can hint "N of MAX pinned".
  get limit(): number {
    return this.max;
  }

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "pinned-findings.json");
  }

  async load(caseId: string): Promise<PinnedFinding[]> {
    try {
      return pinnedFindingsSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(caseId: string, pins: PinnedFinding[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(pins, null, 2));
  }

  // Pin a finding (append to the end, preserving analyst-chosen order). Idempotent: re-pinning an
  // already-pinned finding returns the current list unchanged. Author falls back to "anonymous".
  // Throws PinLimitError when the cap is reached, or a plain Error on a blank findingId.
  async pin(caseId: string, input: NewPin): Promise<PinnedFinding[]> {
    const findingId = String(input.findingId ?? "").trim();
    if (!findingId) throw new Error("findingId is required");
    const pins = await this.load(caseId);
    if (pins.some((p) => p.findingId === findingId)) return pins; // already pinned — no duplicate
    if (pins.length >= this.max) throw new PinLimitError(this.max);
    const pin: PinnedFinding = {
      findingId,
      pinnedBy: (input.pinnedBy || "").trim() || "anonymous",
      pinnedAt: new Date().toISOString(),
    };
    const next = [...pins, pin];
    await this.save(caseId, next);
    return next;
  }

  // Unpin a finding by id. Returns the resulting list; a no-op (returns the list unchanged, no
  // write) when the finding was not pinned.
  async unpin(caseId: string, findingId: string): Promise<PinnedFinding[]> {
    const id = String(findingId ?? "").trim();
    const pins = await this.load(caseId);
    const next = pins.filter((p) => p.findingId !== id);
    if (next.length === pins.length) return pins;
    await this.save(caseId, next);
    return next;
  }

  // Reorder the pins to match the given findingId order (drag-to-reorder). Ids not currently
  // pinned are ignored; any pinned finding missing from `orderedIds` is appended in its existing
  // relative order so nothing is silently lost. Immutable + idempotent.
  async reorder(caseId: string, orderedIds: string[]): Promise<PinnedFinding[]> {
    const pins = await this.load(caseId);
    const byId = new Map(pins.map((p) => [p.findingId, p]));
    const seen = new Set<string>();
    const next: PinnedFinding[] = [];
    for (const raw of orderedIds || []) {
      const id = String(raw ?? "").trim();
      const p = byId.get(id);
      if (p && !seen.has(id)) {
        next.push(p);
        seen.add(id);
      }
    }
    for (const p of pins) if (!seen.has(p.findingId)) next.push(p);
    await this.save(caseId, next);
    return next;
  }
}
