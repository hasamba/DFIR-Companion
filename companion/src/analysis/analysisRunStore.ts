import { mkdir, open, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { hashManifestValue, sanitizeManifestValue } from "./analysisRunHash.js";
import {
  ANALYSIS_RUN_SCHEMA_VERSION,
  analysisRunHeadSchema,
  analysisRunManifestSchema,
  type AnalysisRunHead,
  type AnalysisRunIntegrity,
  type AnalysisRunManifest,
  type AnalysisRunRecordInput,
  type ManifestValue,
} from "./analysisRunTypes.js";

const VALID_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,119}$/;

export interface AnalysisRunStoreOptions {
  appVersion: string;
}

type UnhashedManifest = Omit<AnalysisRunManifest, "manifestHash">;

function manifestHash(manifest: UnhashedManifest): string {
  return hashManifestValue(manifest);
}

function parseManifest(raw: string): AnalysisRunManifest {
  return analysisRunManifestSchema.parse(JSON.parse(raw) as unknown);
}

function safeConfiguration(
  configuration: AnalysisRunRecordInput["configuration"],
): AnalysisRunRecordInput["configuration"] {
  if (!configuration) return undefined;
  return sanitizeManifestValue(configuration as unknown as ManifestValue) as typeof configuration;
}

function buildManifest(
  caseId: string,
  input: AnalysisRunRecordInput,
  appVersion: string,
  sequence: number,
  previousManifestHash: string | null,
): AnalysisRunManifest {
  const id = input.id ?? `${input.startedAt.replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
  if (!VALID_RUN_ID.test(id)) throw new Error(`invalid analysis run id: ${id}`);
  const started = Date.parse(input.startedAt);
  const finished = Date.parse(input.finishedAt);
  if (!Number.isFinite(started) || !Number.isFinite(finished) || finished < started) {
    throw new Error("analysis run timestamps are invalid");
  }
  const base: UnhashedManifest = {
    id,
    caseId,
    schemaVersion: ANALYSIS_RUN_SCHEMA_VERSION,
    sequence,
    kind: input.kind,
    status: input.status ?? "completed",
    parentRunId: input.parentRunId ?? null,
    startedAt: input.startedAt,
    finishedAt: input.finishedAt,
    durationMs: finished - started,
    versions: { ...input.versions, application: input.versions.application ?? appVersion },
    input: {
      ...input.input,
      artifacts: input.input.artifacts.map((artifact) => ({
        path: artifact.path.replace(/\\/g, "/").replace(/^\/+/, ""),
        sha256: artifact.sha256,
      })),
    },
    ...(input.configuration ? { configuration: safeConfiguration(input.configuration) } : {}),
    execution: {
      retries: input.execution?.retries ?? 0,
      warnings: input.execution?.warnings ?? [],
      ...(input.execution?.costUsd !== undefined ? { costUsd: input.execution.costUsd } : {}),
      ...(input.execution?.inputTokens !== undefined ? { inputTokens: input.execution.inputTokens } : {}),
      ...(input.execution?.outputTokens !== undefined ? { outputTokens: input.execution.outputTokens } : {}),
    },
    output: input.output,
    ...(input.error ? { error: sanitizeManifestValue(input.error) as string } : {}),
    previousManifestHash,
  };
  return { ...base, manifestHash: manifestHash(base) };
}

export class AnalysisRunStore {
  private readonly lock = new StateLock();

  constructor(
    private readonly cases: CaseStore,
    private readonly options: AnalysisRunStoreOptions,
  ) {}

  private dir(caseId: string): string {
    return join(this.cases.stateDir(caseId), "analysis-runs");
  }

  private path(caseId: string, id: string): string {
    if (!VALID_RUN_ID.test(id)) throw new Error(`invalid analysis run id: ${id}`);
    return join(this.dir(caseId), `${id}.json`);
  }

  private headPath(caseId: string): string {
    return join(this.dir(caseId), "head.json");
  }

  private async readHead(caseId: string): Promise<AnalysisRunHead | null> {
    try {
      return analysisRunHeadSchema.parse(
        JSON.parse(await readFile(this.headPath(caseId), "utf8")) as unknown,
      );
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  private async readAll(caseId: string): Promise<AnalysisRunManifest[]> {
    let names: string[];
    try {
      names = (await readdir(this.dir(caseId))).filter(
        (name) => name.endsWith(".json") && name !== "head.json",
      );
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    return Promise.all(
      names.map(async (name) => parseManifest(await readFile(join(this.dir(caseId), name), "utf8"))),
    );
  }

  async list(caseId: string): Promise<AnalysisRunManifest[]> {
    const runs = await this.readAll(caseId);
    return runs.sort((a, b) => b.startedAt.localeCompare(a.startedAt) || b.id.localeCompare(a.id));
  }

  async get(caseId: string, id: string): Promise<AnalysisRunManifest | null> {
    if (!VALID_RUN_ID.test(id)) return null;
    try {
      return parseManifest(await readFile(this.path(caseId, id), "utf8"));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async record(caseId: string, input: AnalysisRunRecordInput): Promise<AnalysisRunManifest> {
    return this.lock.runExclusive(caseId, async () => {
      const existing = await this.readAll(caseId);
      const latest = existing.reduce<AnalysisRunManifest | undefined>(
        (current, run) => (!current || run.sequence > current.sequence ? run : current),
        undefined,
      );
      const sequence = (latest?.sequence ?? 0) + 1;
      const manifest = buildManifest(
        caseId,
        input,
        this.options.appVersion,
        sequence,
        latest?.manifestHash ?? null,
      );
      await mkdir(this.dir(caseId), { recursive: true });
      let handle;
      try {
        handle = await open(this.path(caseId, manifest.id), "wx");
        await handle.writeFile(JSON.stringify(manifest, null, 2), "utf8");
        await handle.sync();
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") {
          throw new Error(`analysis run ${manifest.id} already exists`);
        }
        throw err;
      } finally {
        await handle?.close();
      }
      await atomicWrite(
        this.headPath(caseId),
        JSON.stringify({
          schemaVersion: ANALYSIS_RUN_SCHEMA_VERSION,
          sequence: manifest.sequence,
          manifestHash: manifest.manifestHash,
        } satisfies AnalysisRunHead),
      );
      return manifest;
    });
  }

  async verify(caseId: string): Promise<AnalysisRunIntegrity> {
    let runs: AnalysisRunManifest[];
    try {
      runs = [...(await this.readAll(caseId))].sort((a, b) => a.sequence - b.sequence);
    } catch (err) {
      return { ok: false, manifests: 0, problems: [`ledger unreadable: ${(err as Error).message}`] };
    }
    const problems: string[] = [];
    let head: AnalysisRunHead | null;
    try {
      head = await this.readHead(caseId);
    } catch (err) {
      return {
        ok: false,
        manifests: runs.length,
        problems: [`ledger head unreadable: ${(err as Error).message}`],
      };
    }
    let previous: string | null = null;
    for (const [index, run] of runs.entries()) {
      if (run.sequence !== index + 1) problems.push(`${run.id}: ledger sequence mismatch`);
      const { manifestHash: storedHash, ...unhashed } = run;
      if (manifestHash(unhashed) !== storedHash) problems.push(`${run.id}: manifest hash mismatch`);
      if (run.previousManifestHash !== previous) problems.push(`${run.id}: previous manifest hash mismatch`);
      previous = storedHash;
    }
    const latest = runs.at(-1);
    if (latest && !head) problems.push("ledger head missing");
    if (!latest && head) problems.push("ledger head exists without manifests");
    if (latest && head && (head.sequence !== latest.sequence || head.manifestHash !== latest.manifestHash)) {
      problems.push("ledger head mismatch");
    }
    return { ok: problems.length === 0, manifests: runs.length, problems };
  }
}
