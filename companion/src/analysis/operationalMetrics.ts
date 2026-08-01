import { mkdir, readFile, stat } from "node:fs/promises";
import { dirname } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";

export const OPERATIONAL_DEFAULT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_SAMPLES = 5_000;
const MAX_METRICS_FILE_BYTES = 16 * 1024 * 1024;
const FLUSH_DELAY_MS = 10_000;

export const IMPORTER_LABELS = [
  "thor",
  "siem",
  "evtxxml",
  "chainsaw",
  "hayabusa",
  "velociraptor",
  "securityonion",
  "socrates",
  "network",
  "kape",
  "cybertriage",
  "m365",
  "aws",
  "cloud",
  "k8s",
  "osquery",
  "plaso",
  "sandbox",
  "memory",
  "email",
  "thehive",
  "auditd",
  "journald",
  "sysdig",
  "wazuh",
  "bashhistory",
  "ecar",
  "snort",
  "yara",
  "combinedlog",
  "asa",
  "syslog",
  "csv",
  "log",
  "custom",
] as const;
export type ImporterLabel = (typeof IMPORTER_LABELS)[number];

export const QUERY_OPERATIONS = [
  "forensic_timeline",
  "super_timeline",
  "state_load",
  "state_save",
  "event_append",
] as const;
export type QueryOperation = (typeof QUERY_OPERATIONS)[number];

export const QUERY_INDEXES = [
  "ordinal",
  "timestamp",
  "host",
  "source",
  "severity",
  "ioc",
  "technique",
  "entity",
  "none",
] as const;
export type QueryIndex = (typeof QUERY_INDEXES)[number];

export const AI_PHASES = ["vision", "synthesis", "import", "analysis", "report", "other"] as const;
export type AiPhase = (typeof AI_PHASES)[number];
export const AI_ERROR_KINDS = [
  "none",
  "auth",
  "billing",
  "rate_limit",
  "timeout",
  "transport",
  "context",
  "parse",
  "other",
] as const;
export type AiErrorKind = (typeof AI_ERROR_KINDS)[number];
export const EXPORT_FORMATS = [
  "markdown",
  "html",
  "docx",
  "csv",
  "json",
  "jsonl",
  "stix",
  "attack",
  "archive",
  "other",
] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];
export const WEBSOCKET_EVENTS = ["connect", "reconnect", "disconnect", "reject", "error", "reap"] as const;
export type WebSocketEvent = (typeof WEBSOCKET_EVENTS)[number];
export const IMPORT_REJECTION_REASONS = [
  "none",
  "filtered",
  "invalid",
  "severity_floor",
  "capped",
  "error",
] as const;
export type ImportRejectionReason = (typeof IMPORT_REJECTION_REASONS)[number];

const at = z.string().datetime();
const count = z.number().int().nonnegative();
const duration = z.number().finite().nonnegative();
const importMetricSchema = z
  .object({
    type: z.literal("import"),
    at,
    importer: z.enum(IMPORTER_LABELS),
    durationMs: duration,
    rowsRead: count,
    accepted: count,
    rejected: count,
    promoted: count,
    rejectionReason: z.enum(IMPORT_REJECTION_REASONS),
  })
  .strict();
const promotionMetricSchema = z
  .object({
    type: z.literal("import_promotion"),
    at,
    promoted: count,
  })
  .strict();
const queryMetricSchema = z
  .object({
    type: z.literal("query"),
    at,
    operation: z.enum(QUERY_OPERATIONS),
    index: z.enum(QUERY_INDEXES),
    durationMs: duration,
    rows: count,
  })
  .strict();
const capacityMetricSchema = z
  .object({
    type: z.literal("capacity"),
    at,
    databaseBytes: count,
    diskFreeBytes: count,
    diskTotalBytes: count,
    rssBytes: count,
    heapUsedBytes: count,
  })
  .strict();
const aiMetricSchema = z
  .object({
    type: z.literal("ai"),
    at,
    phase: z.enum(AI_PHASES),
    durationMs: duration,
    success: z.boolean(),
    inputTokens: count,
    outputTokens: count,
    costUsd: z.number().finite().nonnegative(),
    errorKind: z.enum(AI_ERROR_KINDS),
  })
  .strict();
const retryMetricSchema = z
  .object({
    type: z.literal("ai_retry"),
    at,
    phase: z.enum(AI_PHASES),
    errorKind: z.enum(AI_ERROR_KINDS),
  })
  .strict();
const exportMetricSchema = z
  .object({
    type: z.literal("export"),
    at,
    format: z.enum(EXPORT_FORMATS),
    durationMs: duration,
    outputBytes: count,
    success: z.boolean(),
  })
  .strict();
const websocketMetricSchema = z
  .object({
    type: z.literal("websocket"),
    at,
    event: z.enum(WEBSOCKET_EVENTS),
    durationMs: duration,
  })
  .strict();

const operationalMetricSchema = z.discriminatedUnion("type", [
  importMetricSchema,
  promotionMetricSchema,
  queryMetricSchema,
  capacityMetricSchema,
  aiMetricSchema,
  retryMetricSchema,
  exportMetricSchema,
  websocketMetricSchema,
]);
export type OperationalMetric = z.infer<typeof operationalMetricSchema>;
export type ImportMetric = z.infer<typeof importMetricSchema>;
export type QueryMetric = z.infer<typeof queryMetricSchema>;
export type CapacityMetric = z.infer<typeof capacityMetricSchema>;
export type AiMetric = z.infer<typeof aiMetricSchema>;
export type ExportMetric = z.infer<typeof exportMetricSchema>;
export type WebSocketMetric = z.infer<typeof websocketMetricSchema>;

export type OperationalMetricInput =
  | Omit<ImportMetric, "at">
  | Omit<z.infer<typeof promotionMetricSchema>, "at">
  | Omit<QueryMetric, "at">
  | Omit<CapacityMetric, "at">
  | Omit<AiMetric, "at">
  | Omit<z.infer<typeof retryMetricSchema>, "at">
  | Omit<ExportMetric, "at">
  | Omit<WebSocketMetric, "at">;

const documentSchema = z
  .object({
    version: z.literal(1),
    samples: z.array(operationalMetricSchema),
  })
  .strict();
type MetricDocument = z.infer<typeof documentSchema>;

export function parseOperationalMetric(input: unknown) {
  return operationalMetricSchema.safeParse(input);
}

const importerSet = new Set<string>(IMPORTER_LABELS);
export function safeImporterLabel(kind: string): ImporterLabel {
  return importerSet.has(kind) ? (kind as ImporterLabel) : "custom";
}

export function safeAiPhase(label: string): AiPhase {
  if (label === "extract") return "vision";
  if (label === "synthesis" || label === "second-opinion-reconcile") return "synthesis";
  if (label === "csv" || label === "log") return "import";
  if (/report|narrative|exec-summary/.test(label)) return "report";
  if (/ask|explain|deep|hypoth|playbook/.test(label)) return "analysis";
  return "other";
}

export function safeAiErrorKind(kind: string | undefined): AiErrorKind {
  return AI_ERROR_KINDS.includes(kind as AiErrorKind) ? (kind as AiErrorKind) : "other";
}

export interface OperationalMetricsStoreOptions {
  enabled?: boolean;
  retentionMs?: number;
  maxSamples?: number;
  now?: () => number;
  onError?: (error: Error) => void;
}

export class OperationalMetricsStore {
  readonly enabled: boolean;
  readonly retentionMs: number;
  readonly maxSamples: number;
  private readonly now: () => number;
  private readonly onError?: (error: Error) => void;
  private cache: MetricDocument | null = null;
  private writes: Promise<void> = Promise.resolve();
  private pending: OperationalMetric[] = [];
  private flushTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly path: string,
    options: OperationalMetricsStoreOptions = {},
  ) {
    this.enabled = options.enabled ?? true;
    this.retentionMs = Math.max(1, Math.floor(options.retentionMs ?? OPERATIONAL_DEFAULT_RETENTION_MS));
    this.maxSamples = Math.max(1, Math.floor(options.maxSamples ?? DEFAULT_MAX_SAMPLES));
    this.now = options.now ?? Date.now;
    this.onError = options.onError;
  }

  async record(input: OperationalMetricInput): Promise<void> {
    if (!this.enabled) return;
    const parsed = operationalMetricSchema.safeParse({
      ...input,
      at: new Date(this.now()).toISOString(),
    });
    if (!parsed.success) {
      this.report(new Error("invalid operational metric sample was discarded"));
      return;
    }
    const sample = parsed.data;
    this.pending = [...this.pending, sample].slice(-this.maxSamples);
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => void this.flush(), FLUSH_DELAY_MS);
      this.flushTimer.unref();
    }
  }

  async flush(): Promise<void> {
    if (!this.enabled) return;
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.flushTimer = null;
    const pending = this.pending;
    this.pending = [];
    if (!pending.length) {
      await this.writes;
      return;
    }
    const write = this.writes.then(async () => {
      const current = await this.load();
      const next = { version: 1 as const, samples: this.prune([...current.samples, ...pending]) };
      await mkdir(dirname(this.path), { recursive: true });
      await atomicWrite(this.path, JSON.stringify(next));
      this.cache = next;
    });
    this.writes = write.catch((error: unknown) => this.report(error));
    await this.writes;
  }

  async snapshot(): Promise<OperationalMetric[]> {
    if (!this.enabled) return [];
    await this.flush();
    return this.prune((await this.load()).samples).map((sample) => ({ ...sample }));
  }

  private prune(samples: readonly OperationalMetric[]): OperationalMetric[] {
    const cutoff = this.now() - this.retentionMs;
    return samples.filter((sample) => Date.parse(sample.at) >= cutoff).slice(-this.maxSamples);
  }

  private async load(): Promise<MetricDocument> {
    if (this.cache) return this.cache;
    try {
      const info = await stat(this.path);
      if (info.size > MAX_METRICS_FILE_BYTES)
        throw new Error("operational metrics file exceeded its size bound");
      const parsed = documentSchema.safeParse(JSON.parse(await readFile(this.path, "utf8")));
      if (!parsed.success) throw new Error("invalid operational metrics document was discarded");
      this.cache = { version: 1, samples: this.prune(parsed.data.samples) };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") this.report(error);
      this.cache = { version: 1, samples: [] };
    }
    return this.cache;
  }

  private report(error: unknown): void {
    try {
      this.onError?.(error instanceof Error ? error : new Error(String(error)));
    } catch {
      // Metrics are a side channel; even their error reporter cannot affect core behavior.
    }
  }
}
