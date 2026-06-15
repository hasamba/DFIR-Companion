import { readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { SecondOpinion } from "./secondOpinion.js";

// Per-case persistence for the Second LLM Opinion (issue #116). Holds the last second-opinion run:
// the two model labels, the reconcile summary, and every disagreement delta with its analyst status
// (pending | accepted | rejected). Side file `state/second-opinion.json`, written atomically (the
// cases/ dir may live in a synced folder). NOT part of InvestigationState — and DELIBERATELY excluded
// from SNAPSHOT_STATE_FILES: it's transient QA scratch, and accepted findings already live in the
// snapshotted case state. Enums use .catch(...) so a hand-edited/older file still loads.

const severity = z.enum(["Critical", "High", "Medium", "Low", "Info"]);

const findingSchema = z.object({
  id: z.string(),
  severity: severity.catch("Medium"),
  confidence: z.number().optional(),
  title: z.string(),
  description: z.string().catch(""),
  relatedIocs: z.array(z.string()).catch([]),
  sourceScreenshots: z.array(z.string()).catch([]),
  mitreTechniques: z.array(z.string()).catch([]),
  firstSeen: z.string().catch(""),
  lastUpdated: z.string().catch(""),
  status: z.enum(["open", "confirmed", "dismissed"]).catch("open"),
});

const deltaSchema = z.object({
  id: z.string(),
  kind: z.enum(["b_only", "a_only", "severity", "mitre_added", "mitre_removed"]),
  title: z.string(),
  aSeverity: severity.optional(),
  bSeverity: severity.optional(),
  finding: findingSchema.optional(),
  techniqueName: z.string().optional(),
  rationale: z.string().catch(""),
  recommendation: z.enum(["accept_b", "keep_a", "review"]).catch("review"),
  status: z.enum(["pending", "accepted", "rejected"]).catch("pending"),
});

export const secondOpinionSchema = z.object({
  generatedAt: z.string().catch(""),
  modelA: z.string().catch(""),
  modelB: z.string().catch(""),
  summary: z.string().catch(""),
  agreementCount: z.number().catch(0),
  deltas: z.array(deltaSchema).catch([]),
});

export class SecondOpinionStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "second-opinion.json");
  }

  async load(caseId: string): Promise<SecondOpinion | null> {
    try {
      return secondOpinionSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8"))) as SecondOpinion;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async save(caseId: string, so: SecondOpinion): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(so, null, 2));
  }

  async clear(caseId: string): Promise<void> {
    try {
      await unlink(this.path(caseId));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
  }
}
