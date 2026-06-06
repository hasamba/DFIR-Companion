import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { FindingsDiff } from "./findingsDiff.js";

// Lightweight per-case record of the LAST synthesis run: when it actually ran (the AI call, not a
// skipped no-op) and what changed in the findings. Kept in a side file (`state/synth-meta.json`)
// so the dashboard can show "last synthesized 3 min ago" and a what-changed diff. NOT part of
// InvestigationState (which synthesis rewrites); written by pipeline.synthesize only on a real run.

const severityChangeSchema = z.object({
  title: z.string(),
  from: z.string(),
  to: z.string(),
});

export const synthMetaSchema = z.object({
  lastSynthesizedAt: z.string().catch(""),
  lastDiff: z.object({
    added: z.array(z.string()).catch([]),
    removed: z.array(z.string()).catch([]),
    severityChanged: z.array(severityChangeSchema).catch([]),
  }).nullable().catch(null),
});

export type SynthMeta = z.infer<typeof synthMetaSchema>;

const EMPTY: SynthMeta = { lastSynthesizedAt: "", lastDiff: null };

export class SynthMetaStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "synth-meta.json");
  }

  async load(caseId: string): Promise<SynthMeta> {
    try {
      return synthMetaSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  // Record a completed synthesis run: stamp the time and store the findings diff.
  async record(caseId: string, diff: FindingsDiff, at: string = new Date().toISOString()): Promise<SynthMeta> {
    const meta: SynthMeta = { lastSynthesizedAt: at, lastDiff: diff };
    await atomicWrite(this.path(caseId), JSON.stringify(meta, null, 2));
    return meta;
  }
}
