import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import {
  EvidenceIntegrityMonitor,
  resolveIntegrityConfig,
  type IntegritySweep,
} from "../../src/analysis/custodyIntegrity.js";

let cases: CaseStore;
let custody: CustodyStore;
let monitor: EvidenceIntegrityMonitor;
let alerts: IntegritySweep[];

const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

async function collect(caseId: string, name: string, text: string): Promise<string> {
  const path = join(cases.importsDir(caseId), name);
  await writeFile(path, text, "utf8");
  await custody.record(caseId, {
    artifactPath: path, sha256: sha(text), collectedBy: "alice",
    collectedAt: "2026-07-28T10:00:00.000Z", source: "host-a", trigger: "import", caseId,
  });
  return path;
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-integrity-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
  custody = new CustodyStore(cases);
  alerts = [];
  monitor = new EvidenceIntegrityMonitor(cases, custody, { intervalMs: 86_400_000, onOpenThrottleMs: 0 }, (sweep) => { alerts.push(sweep); });
});

// The all-cases sweep interval. Its DEFAULT (off) and the on-open trigger are covered in
// custodyIntegrityScope.test.ts, which owns the trigger model.
describe("resolveIntegrityConfig", () => {
  it("takes the operator's interval", () => {
    expect(resolveIntegrityConfig({ DFIR_CUSTODY_VERIFY_INTERVAL_MS: "60000" }).intervalMs).toBe(60_000);
  });

  it("treats 0 as disabled rather than as 'run constantly'", () => {
    expect(resolveIntegrityConfig({ DFIR_CUSTODY_VERIFY_INTERVAL_MS: "0" }).intervalMs).toBe(0);
  });

  it("falls back to off on a non-numeric value", () => {
    expect(resolveIntegrityConfig({ DFIR_CUSTODY_VERIFY_INTERVAL_MS: "soon" }).intervalMs).toBe(0);
  });
});

describe("EvidenceIntegrityMonitor.runSweep", () => {
  it("reports every artifact as verified when nothing has changed", async () => {
    await collect("c1", "a.csv", "one\n");
    await collect("c2", "b.csv", "two\n");

    const sweep = await monitor.runSweep();

    expect(sweep).toMatchObject({ casesChecked: 2, artifacts: 2, failedArtifacts: 0, chainBreaks: 0 });
    expect(sweep.problemCases).toEqual([]);
  });

  it("counts an artifact whose bytes changed on disk", async () => {
    const path = await collect("c1", "a.csv", "one\n");
    await collect("c2", "b.csv", "two\n");
    await writeFile(path, "tampered\n", "utf8");

    const sweep = await monitor.runSweep();

    expect(sweep).toMatchObject({ artifacts: 2, failedArtifacts: 1 });
    expect(sweep.problemCases.map((c) => c.caseId)).toEqual(["c1"]);
    expect(sweep.problemCases[0].mismatches[0]).toMatchObject({ artifactPath: path, reason: "hash-mismatch" });
  });

  it("counts a deleted artifact as failed", async () => {
    const path = await collect("c1", "a.csv", "one\n");
    await rm(path);

    expect((await monitor.runSweep()).failedArtifacts).toBe(1);
  });

  it("counts a break in the custody log itself", async () => {
    await collect("c1", "a.csv", "one\n");
    await collect("c1", "b.csv", "two\n");
    const [first, second] = (await readFile(cases.custodyLogPath("c1"), "utf8")).split("\n").filter((l) => l.trim());
    const edited = { ...(JSON.parse(first) as Record<string, unknown>), collectedBy: "mallory" };
    await writeFile(cases.custodyLogPath("c1"), JSON.stringify(edited) + "\n" + second + "\n", "utf8");

    const sweep = await monitor.runSweep();

    // The files themselves are untouched — only the record of them.
    expect(sweep.failedArtifacts).toBe(0);
    expect(sweep.chainBreaks).toBe(1);
    expect(sweep.problemCases.map((c) => c.caseId)).toEqual(["c1"]);
  });

  it("counts cases with no custody log as checked but empty", async () => {
    const sweep = await monitor.runSweep();

    expect(sweep).toMatchObject({ casesChecked: 2, artifacts: 0, failedArtifacts: 0 });
  });

  it("verifies archived cases too, since archived evidence is still evidence", async () => {
    const path = await collect("c1", "a.csv", "one\n");
    await cases.archiveCaseFolder("c1");
    await writeFile(path.replace(join(cases.casesRoot, "c1"), join(cases.casesRoot, "_archived", "c1")), "tampered\n", "utf8");

    const sweep = await monitor.runSweep();

    expect(sweep.failedArtifacts).toBe(1);
  });
});

describe("EvidenceIntegrityMonitor alerting", () => {
  it("alerts when a sweep finds a problem", async () => {
    const path = await collect("c1", "a.csv", "one\n");
    await writeFile(path, "tampered\n", "utf8");

    await monitor.runSweep();

    expect(alerts).toHaveLength(1);
    expect(alerts[0].failedArtifacts).toBe(1);
  });

  it("stays quiet when everything verifies", async () => {
    await collect("c1", "a.csv", "one\n");

    await monitor.runSweep();

    expect(alerts).toEqual([]);
  });
});

describe("EvidenceIntegrityMonitor.status", () => {
  it("reports never-run before the first sweep", () => {
    expect(monitor.status()).toMatchObject({ enabled: true, lastRunAt: null, artifacts: 0, failedArtifacts: 0 });
  });

  it("reports the last sweep once one has run", async () => {
    await collect("c1", "a.csv", "one\n");

    await monitor.runSweep();

    const status = monitor.status();
    expect(status.lastRunAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(status).toMatchObject({ artifacts: 1, failedArtifacts: 0, chainBreaks: 0, problemCaseIds: [] });
  });

  it("names the cases that failed, so the operator knows where to look", async () => {
    const path = await collect("c1", "a.csv", "one\n");
    await writeFile(path, "tampered\n", "utf8");

    await monitor.runSweep();

    expect(monitor.status().problemCaseIds).toEqual(["c1"]);
  });

  it("reports itself disabled when the interval is 0", () => {
    const off = new EvidenceIntegrityMonitor(cases, custody, { intervalMs: 0, onOpenThrottleMs: 0 });
    expect(off.status().enabled).toBe(false);
  });
});

describe("evidence integrity in GET /diagnostics", () => {
  it("reports the monitor's last sweep, and defaults to disabled when none is wired", async () => {
    const { createApp } = await import("../../src/server.js");
    const app = createApp(cases, { custodyStore: custody, integrityMonitor: monitor });

    await collect("c1", "a.csv", "one\n");
    await monitor.runSweep();

    const { default: request } = await import("supertest");
    const res = await request(app).get("/diagnostics");
    expect(res.status).toBe(200);
    expect(res.body.report.evidenceIntegrity).toMatchObject({ enabled: true, artifacts: 1, failedArtifacts: 0 });
    expect(res.body.text).toContain("-- Evidence integrity --");

    const bare = await request(createApp(cases, {})).get("/diagnostics");
    expect(bare.body.report.evidenceIntegrity).toMatchObject({ enabled: false, lastRunAt: null });
  });
});
