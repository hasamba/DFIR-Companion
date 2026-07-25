import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import {
  DEFAULT_VERDICT_EVOLUTION_CONFIG,
  type IocVerdictHistory,
  type VerdictEvolutionConfig,
  type VerdictSample,
} from "./verdictEvolution.js";

// Per-case verdict-evolution store (#232), in state/verdict-evolution.json. A stateless wrapper
// over CaseStore (mirrors SourceTrustStore / ClockSkewStore). Persists:
//   - the per-case config (enabled, interval, severity filter, score-delta threshold, last/next run)
//   - the per-IOC verdict HISTORY (timestamped samples) built by computeVerdictHistories
//
// Returns sensible defaults when absent / unreadable. Validates on read so a hand-edited file
// can't inject a malformed config or history into the change-detection path.

const severitySchema = z.enum(["Critical", "High", "Medium", "Low", "Info"]);
const verdictSchema = z.enum(["malicious", "suspicious", "harmless", "unknown"]);

const sampleSchema = z.object({
  ts: z.string(),
  provider: z.string(),
  verdict: verdictSchema,
  score: z.string().optional(),
  detections: z.number().optional(),
  total: z.number().optional(),
});

const historySchema = z.object({
  iocId: z.string(),
  value: z.string(),
  type: z.enum(["ip", "domain", "hash", "file", "process", "url", "sid", "other"]),
  samples: z.array(sampleSchema).catch([]),
});

const configSchema = z.object({
  enabled: z.boolean().catch(false),
  intervalDays: z.number().catch(7),
  maliciousIntervalDays: z.number().catch(30),
  minSeverity: severitySchema.catch("Low"),
  scoreDeltaThreshold: z.number().catch(5),
  lastRunAt: z.string().catch(""),
  nextRunAt: z.string().catch(""),
});

const recordSchema = z.object({
  config: configSchema.catch(DEFAULT_VERDICT_EVOLUTION_CONFIG),
  histories: z.array(historySchema).catch([]),
});

export interface VerdictEvolutionRecord {
  config: VerdictEvolutionConfig;
  histories: IocVerdictHistory[];
}

export class VerdictEvolutionStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "verdict-evolution.json");
  }

  async load(caseId: string): Promise<VerdictEvolutionRecord> {
    try {
      const parsed = recordSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
      return {
        config: { ...DEFAULT_VERDICT_EVOLUTION_CONFIG, ...parsed.config },
        histories: parsed.histories as IocVerdictHistory[],
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return { config: { ...DEFAULT_VERDICT_EVOLUTION_CONFIG }, histories: [] };
      }
      throw err;
    }
  }

  async saveConfig(caseId: string, config: VerdictEvolutionConfig): Promise<VerdictEvolutionConfig> {
    const current = await this.load(caseId);
    const clean: VerdictEvolutionConfig = { ...DEFAULT_VERDICT_EVOLUTION_CONFIG, ...config };
    await atomicWrite(this.path(caseId), JSON.stringify({ config: clean, histories: current.histories }, null, 2));
    return clean;
  }

  async saveHistories(caseId: string, histories: IocVerdictHistory[]): Promise<void> {
    const current = await this.load(caseId);
    await atomicWrite(this.path(caseId), JSON.stringify({ config: current.config, histories }, null, 2));
  }

  async markRun(caseId: string, lastRunAt: string, nextRunAt: string): Promise<VerdictEvolutionConfig> {
    const current = await this.load(caseId);
    return this.saveConfig(caseId, { ...current.config, lastRunAt, nextRunAt });
  }
}