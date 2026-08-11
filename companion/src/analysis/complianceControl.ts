import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case compliance-view settings (#336). Two analyst inputs the compliance mapping cannot
// derive on its own; mirrors ConfidenceControlStore's shape. state/compliance-control.json.
//
//   discoveredAt — the date the notification clocks run from. It CANNOT be derived from case data:
//     every clock in the dataset starts on a legal determination (awareness of a personal-data
//     breach, discovery of a breach of unsecured PHI, a materiality determination), which counsel
//     makes. The earliest forensic event is not that date, and defaulting to it would manufacture
//     a deadline. Absent = no countdowns are computed at all.
//
//   frameworks — which frameworks to show. Absent (not empty) = show everything; an explicit empty
//     array is a deliberate "show none". Lets a healthcare org drop PCI noise.
export interface ComplianceControl {
  discoveredAt?: string;
  frameworks?: string[];
}

const schema = z
  .object({
    discoveredAt: z.string().optional().catch(undefined),
    frameworks: z.array(z.string()).optional().catch(undefined),
  })
  .catch({});

// A parseable instant, or undefined. Guards the countdown against a junk date turning into
// `Invalid Date` and rendering "NaN days remaining".
export function normalizeDiscoveredAt(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
}

export class ComplianceControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "compliance-control.json");
  }

  async load(caseId: string): Promise<ComplianceControl> {
    try {
      const parsed = schema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
      return {
        ...parsed,
        ...(parsed.discoveredAt ? { discoveredAt: normalizeDiscoveredAt(parsed.discoveredAt) } : {}),
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  async set(caseId: string, patch: ComplianceControl): Promise<ComplianceControl> {
    const current = await this.load(caseId);
    const next: ComplianceControl = {
      ...current,
      // `in` rather than a truthiness test: passing an explicit undefined/empty is how the analyst
      // CLEARS the date or narrows to no frameworks, and that must not read as "leave unchanged".
      ...("discoveredAt" in patch ? { discoveredAt: normalizeDiscoveredAt(patch.discoveredAt) } : {}),
      ...("frameworks" in patch
        ? { frameworks: Array.isArray(patch.frameworks) ? patch.frameworks : undefined }
        : {}),
    };
    if (next.discoveredAt === undefined) delete next.discoveredAt;
    if (next.frameworks === undefined) delete next.frameworks;
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
