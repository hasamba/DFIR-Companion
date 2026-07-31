import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  assessNoRegressionGate,
  evaluationSourceHash,
  noRegressionAttestationSchema,
  type NoRegressionAttestation,
} from "./changeGate.js";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const ATTESTATION_PATH = fileURLToPath(new URL("./reports/no-regression.json", import.meta.url));

function git(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("git", args, { cwd: REPOSITORY_ROOT }, (error, stdout) => {
      if (error) reject(new Error(`git ${args[0] ?? "command"} failed: ${error.message}`, { cause: error }));
      else resolve(stdout.trim());
    });
  });
}

async function baseRevision(): Promise<string> {
  const githubBase = process.env.GITHUB_BASE_REF?.trim();
  if (githubBase) return git(["merge-base", "HEAD", `origin/${githubBase}`]);
  return git(["merge-base", "HEAD", "master"]);
}

async function baseFile(revision: string, path: string): Promise<string> {
  return git(["show", `${revision}:${path}`]);
}

async function currentSourceHash(): Promise<string> {
  const [pipeline, envExample] = await Promise.all([
    readFile(`${REPOSITORY_ROOT}/companion/src/analysis/pipeline.ts`, "utf8"),
    readFile(`${REPOSITORY_ROOT}/companion/.env.example`, "utf8"),
  ]);
  return evaluationSourceHash(pipeline, envExample);
}

async function baseSourceHash(revision: string): Promise<string> {
  const [pipeline, envExample] = await Promise.all([
    baseFile(revision, "companion/src/analysis/pipeline.ts"),
    baseFile(revision, "companion/.env.example"),
  ]);
  return evaluationSourceHash(pipeline, envExample);
}

async function readAttestation(): Promise<NoRegressionAttestation | undefined> {
  try {
    const raw = await readFile(ATTESTATION_PATH, "utf8");
    const attestation = noRegressionAttestationSchema.parse(JSON.parse(raw) as unknown);
    await verifyAttestedReport(attestation);
    return attestation;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

const attestedReportSchema = z.object({
  schemaVersion: z.literal(1),
  outcome: z.literal("passed"),
  identity: z.object({ sourceHash: z.string().regex(/^[a-f0-9]{64}$/) }),
  baselineComparison: z.object({
    status: z.literal("passed"),
    baselineKey: z.string().min(1),
  }),
  privacy: z.object({
    containsEvidence: z.literal(false),
    containsModelOutput: z.literal(false),
    containsCredentials: z.literal(false),
  }),
});

async function verifyAttestedReport(attestation: NoRegressionAttestation): Promise<void> {
  if (attestation.reportPath !== basename(attestation.reportPath)) {
    throw new Error("no-regression reportPath must name a file beside the attestation");
  }
  const path = join(dirname(ATTESTATION_PATH), attestation.reportPath);
  const raw = await readFile(path, "utf8");
  const hash = createHash("sha256").update(raw).digest("hex");
  if (hash !== attestation.reportSha256) throw new Error("no-regression report hash mismatch");
  const report = attestedReportSchema.parse(JSON.parse(raw) as unknown);
  if (report.identity.sourceHash !== attestation.sourceHash) {
    throw new Error("no-regression report source hash does not match its attestation");
  }
  if (report.baselineComparison.baselineKey !== attestation.baselineKey) {
    throw new Error("no-regression report baseline does not match its attestation");
  }
}

async function main(): Promise<void> {
  const revision = await baseRevision();
  const [baseHash, currentHash, attestation] = await Promise.all([
    baseSourceHash(revision),
    currentSourceHash(),
    readAttestation(),
  ]);
  const assessment = assessNoRegressionGate(baseHash, currentHash, attestation);
  console.log(`AI evaluation change gate: ${assessment.status} — ${assessment.message}`);
  if (!["not-required", "passed"].includes(assessment.status)) process.exitCode = 1;
}

void main().catch((error: unknown) => {
  console.error(`AI evaluation change gate errored: ${(error as Error).message}`);
  process.exitCode = 2;
});
