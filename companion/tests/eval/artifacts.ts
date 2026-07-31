import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { basename, dirname } from "node:path";
import type { NoRegressionAttestation } from "./changeGate.js";
import type { EvaluationReport } from "./report.js";

async function writeJson(path: string, value: unknown): Promise<string> {
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, serialized, "utf8");
  return createHash("sha256").update(serialized).digest("hex");
}

export async function writeEvaluationReport(path: string, report: EvaluationReport): Promise<string> {
  return writeJson(path, report);
}

export async function writeNoRegressionAttestation(
  path: string,
  reportPath: string,
  reportSha256: string,
  report: EvaluationReport,
): Promise<void> {
  const comparison = report.baselineComparison;
  if (!comparison) throw new Error("a baseline comparison is required to write an attestation");
  const attestation: NoRegressionAttestation = {
    schemaVersion: 1,
    sourceHash: report.identity.sourceHash,
    status: report.outcome === "passed" && comparison.status === "passed" ? "passed" : "failed",
    reportPath: basename(reportPath),
    reportSha256,
    baselineKey: comparison.baselineKey,
    evaluatedAt: report.createdAt,
  };
  await writeJson(path, attestation);
}
