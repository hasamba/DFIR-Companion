import { z } from "zod";

export const ANALYSIS_RUN_SCHEMA_VERSION = 1;

export const ANALYSIS_RUN_KINDS = [
  "import",
  "deterministic",
  "enrichment",
  "synthesis",
  "deep-pass",
  "report",
] as const;

export type AnalysisRunKind = (typeof ANALYSIS_RUN_KINDS)[number];
export type AnalysisRunStatus = "completed" | "failed";
export type ManifestValue =
  null | boolean | number | string | ManifestValue[] | { [key: string]: ManifestValue };

export interface AnalysisRunArtifact {
  /** Case-relative path. Absolute workstation paths are never persisted in a manifest. */
  path: string;
  sha256: string;
}

export interface AnalysisRunHash {
  id: string;
  sha256: string;
}

export interface AnalysisRunClaim {
  id: string;
  hash: string;
  evidenceEventIds: string[];
}

export interface AnalysisRunVersions {
  application: string;
  schema?: string;
  importer?: string;
  rules?: string;
  data?: string;
}

export interface AnalysisRunInput {
  artifacts: AnalysisRunArtifact[];
  eventIds: string[];
  entityIds: string[];
  selectionHash?: string;
}

export interface AnalysisRunConfiguration {
  promptHash?: string;
  templateHash?: string;
  provider?: string;
  model?: string;
  parameters?: Record<string, ManifestValue>;
  anonymizationPolicy?: Record<string, ManifestValue>;
  filteringPolicy?: Record<string, ManifestValue>;
}

export interface AnalysisRunExecution {
  retries: number;
  warnings: string[];
  costUsd?: number;
  inputTokens?: number;
  outputTokens?: number;
}

export interface AnalysisRunOutput {
  entityIds: string[];
  hashes: AnalysisRunHash[];
  claims: AnalysisRunClaim[];
}

export interface AnalysisRunManifest {
  id: string;
  caseId: string;
  schemaVersion: typeof ANALYSIS_RUN_SCHEMA_VERSION;
  /** Append order in this case's ledger; independent of when a long-running operation started. */
  sequence: number;
  kind: AnalysisRunKind;
  status: AnalysisRunStatus;
  parentRunId: string | null;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  versions: AnalysisRunVersions;
  input: AnalysisRunInput;
  configuration?: AnalysisRunConfiguration;
  execution: AnalysisRunExecution;
  output: AnalysisRunOutput;
  error?: string;
  previousManifestHash: string | null;
  manifestHash: string;
}

export const manifestValueSchema: z.ZodType<ManifestValue> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number(),
    z.string(),
    z.array(manifestValueSchema),
    z.record(z.string(), manifestValueSchema),
  ]),
);
const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/i);

/** Strict disk/API boundary for immutable manifests; a damaged file never masquerades as a run. */
export const analysisRunManifestSchema: z.ZodType<AnalysisRunManifest> = z.object({
  id: z.string().min(1),
  caseId: z.string().min(1),
  schemaVersion: z.literal(ANALYSIS_RUN_SCHEMA_VERSION),
  sequence: z.number().int().positive(),
  kind: z.enum(ANALYSIS_RUN_KINDS),
  status: z.enum(["completed", "failed"]),
  parentRunId: z.string().nullable(),
  startedAt: z.string().datetime(),
  finishedAt: z.string().datetime(),
  durationMs: z.number().nonnegative(),
  versions: z.object({
    application: z.string(),
    schema: z.string().optional(),
    importer: z.string().optional(),
    rules: z.string().optional(),
    data: z.string().optional(),
  }),
  input: z.object({
    artifacts: z.array(z.object({ path: z.string(), sha256: sha256Schema })),
    eventIds: z.array(z.string()),
    entityIds: z.array(z.string()),
    selectionHash: sha256Schema.optional(),
  }),
  configuration: z
    .object({
      promptHash: sha256Schema.optional(),
      templateHash: sha256Schema.optional(),
      provider: z.string().optional(),
      model: z.string().optional(),
      parameters: z.record(z.string(), manifestValueSchema).optional(),
      anonymizationPolicy: z.record(z.string(), manifestValueSchema).optional(),
      filteringPolicy: z.record(z.string(), manifestValueSchema).optional(),
    })
    .optional(),
  execution: z.object({
    retries: z.number().int().nonnegative(),
    warnings: z.array(z.string()),
    costUsd: z.number().optional(),
    inputTokens: z.number().int().nonnegative().optional(),
    outputTokens: z.number().int().nonnegative().optional(),
  }),
  output: z.object({
    entityIds: z.array(z.string()),
    hashes: z.array(z.object({ id: z.string(), sha256: sha256Schema })),
    claims: z.array(
      z.object({
        id: z.string(),
        hash: z.string(),
        evidenceEventIds: z.array(z.string()),
      }),
    ),
  }),
  error: z.string().optional(),
  previousManifestHash: sha256Schema.nullable(),
  manifestHash: sha256Schema,
});

export interface AnalysisRunHead {
  schemaVersion: typeof ANALYSIS_RUN_SCHEMA_VERSION;
  sequence: number;
  manifestHash: string;
}

export const analysisRunHeadSchema: z.ZodType<AnalysisRunHead> = z.object({
  schemaVersion: z.literal(ANALYSIS_RUN_SCHEMA_VERSION),
  sequence: z.number().int().positive(),
  manifestHash: sha256Schema,
});

export interface AnalysisRunRecordInput {
  id?: string;
  kind: AnalysisRunKind;
  status?: AnalysisRunStatus;
  parentRunId?: string | null;
  startedAt: string;
  finishedAt: string;
  versions: Omit<AnalysisRunVersions, "application"> & { application?: string };
  input: AnalysisRunInput;
  configuration?: AnalysisRunConfiguration;
  execution?: Partial<AnalysisRunExecution>;
  output: AnalysisRunOutput;
  error?: string;
}

export interface AnalysisRunIntegrity {
  ok: boolean;
  manifests: number;
  problems: string[];
}
