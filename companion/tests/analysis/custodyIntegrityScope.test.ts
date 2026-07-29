import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import {
  EvidenceIntegrityMonitor,
  resolveIntegrityConfig,
  DEFAULT_ON_OPEN_THROTTLE_MS,
  type IntegritySweep,
} from "../../src/analysis/custodyIntegrity.js";

let cases: CaseStore;
let custody: CustodyStore;
let monitor: EvidenceIntegrityMonitor;
let alerts: IntegritySweep[];

const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const config = { intervalMs: 0, onOpenThrottleMs: DEFAULT_ON_OPEN_THROTTLE_MS };

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
  const root = await mkdtemp(join(tmpdir(), "dfir-integrityscope-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
  custody = new CustodyStore(cases);
  alerts = [];
  monitor = new EvidenceIntegrityMonitor(cases, custody, config, (s) => { alerts.push(s); });
});

describe("integrity config defaults", () => {
  it("leaves the all-cases sweep OFF by default, so an idle install does no background hashing", () => {
    expect(resolveIntegrityConfig({}).intervalMs).toBe(0);
  });

  it("still runs the all-cases sweep when the operator opts in", () => {
    expect(resolveIntegrityConfig({ DFIR_CUSTODY_VERIFY_INTERVAL_MS: "3600000" }).intervalMs).toBe(3_600_000);
  });

  it("verifies a case when it is opened, throttled to four hours by default", () => {
    expect(resolveIntegrityConfig({}).onOpenThrottleMs).toBe(DEFAULT_ON_OPEN_THROTTLE_MS);
  });

  it("takes the operator's on-open throttle, and treats 0 as off", () => {
    expect(resolveIntegrityConfig({ DFIR_CUSTODY_VERIFY_ON_OPEN_MS: "60000" }).onOpenThrottleMs).toBe(60_000);
    expect(resolveIntegrityConfig({ DFIR_CUSTODY_VERIFY_ON_OPEN_MS: "0" }).onOpenThrottleMs).toBe(0);
  });
});

describe("EvidenceIntegrityMonitor.verifyCase", () => {
  it("verifies only the case it was given", async () => {
    await collect("c1", "a.csv", "one\n");
    const other = await collect("c2", "b.csv", "two\n");
    await writeFile(other, "tampered\n", "utf8");

    const result = await monitor.verifyCase("c1");

    expect(result).toMatchObject({ caseId: "c1", artifacts: 1 });
    expect(result.mismatches).toEqual([]);
    // c2 is broken, but nothing looked at it — so nothing reports it.
    expect(monitor.status().problemCaseIds).toEqual([]);
  });

  it("alerts when the opened case is the broken one", async () => {
    const path = await collect("c1", "a.csv", "one\n");
    await writeFile(path, "tampered\n", "utf8");

    await monitor.verifyCase("c1");

    expect(alerts).toHaveLength(1);
    expect(alerts[0].problemCases.map((c) => c.caseId)).toEqual(["c1"]);
  });
});

describe("EvidenceIntegrityMonitor.verifyCaseIfStale", () => {
  it("verifies a case that has never been checked", async () => {
    await collect("c1", "a.csv", "one\n");

    expect(await monitor.verifyCaseIfStale("c1")).not.toBeNull();
  });

  it("skips a re-check while the throttle window is still open", async () => {
    await collect("c1", "a.csv", "one\n");
    const openedAt = Date.now();
    await monitor.verifyCaseIfStale("c1");

    // Re-opening the case a minute later must not re-hash gigabytes of evidence.
    expect(await monitor.verifyCaseIfStale("c1", openedAt + 60_000)).toBeNull();
  });

  it("verifies again once the throttle window has passed", async () => {
    await collect("c1", "a.csv", "one\n");
    const openedAt = Date.now();
    await monitor.verifyCaseIfStale("c1");

    expect(await monitor.verifyCaseIfStale("c1", openedAt + DEFAULT_ON_OPEN_THROTTLE_MS + 1_000)).not.toBeNull();
  });

  it("does nothing when on-open verification is switched off", async () => {
    const off = new EvidenceIntegrityMonitor(cases, custody, { intervalMs: 0, onOpenThrottleMs: 0 });
    await collect("c1", "a.csv", "one\n");

    expect(await off.verifyCaseIfStale("c1")).toBeNull();
  });
});

describe("EvidenceIntegrityMonitor.status with per-case verification", () => {
  it("aggregates what is known across the cases actually verified", async () => {
    await collect("c1", "a.csv", "one\n");
    await collect("c2", "b.csv", "two\n");

    await monitor.verifyCase("c1");
    await monitor.verifyCase("c2");

    expect(monitor.status()).toMatchObject({ casesVerified: 2, artifacts: 2, failedArtifacts: 0 });
  });

  it("reports a case as clean again once it has been re-verified", async () => {
    const path = await collect("c1", "a.csv", "one\n");
    await writeFile(path, "tampered\n", "utf8");
    await monitor.verifyCase("c1");
    expect(monitor.status().failedArtifacts).toBe(1);

    // The analyst restores the file from backup and re-opens the case.
    await writeFile(path, "one\n", "utf8");
    await monitor.verifyCase("c1");

    expect(monitor.status()).toMatchObject({ failedArtifacts: 0, problemCaseIds: [] });
  });

  it("says whether each trigger is on", () => {
    expect(monitor.status()).toMatchObject({ enabled: false, verifyOnOpen: true });
  });
});

describe("POST /cases/:id/custody/verify", () => {
  it("kicks off verification for the opened case and returns immediately", async () => {
    const { createApp } = await import("../../src/server.js");
    const { default: request } = await import("supertest");
    const app = createApp(cases, { custodyStore: custody, integrityMonitor: monitor });
    await collect("c1", "a.csv", "one\n");

    const res = await request(app).post("/cases/c1/custody/verify").send({});

    expect(res.status).toBe(202);
    // The check runs in the background; the status reflects it once it lands.
    await new Promise((r) => setTimeout(r, 50));
    expect(monitor.status().casesVerified).toBe(1);
  });

  it("404s for a case that does not exist", async () => {
    const { createApp } = await import("../../src/server.js");
    const { default: request } = await import("supertest");
    const app = createApp(cases, { custodyStore: custody, integrityMonitor: monitor });

    expect((await request(app).post("/cases/nope/custody/verify").send({})).status).toBe(404);
  });

  it("501s when no monitor is wired", async () => {
    const { createApp } = await import("../../src/server.js");
    const { default: request } = await import("supertest");

    expect((await request(createApp(cases, {})).post("/cases/c1/custody/verify").send({})).status).toBe(501);
  });
});
