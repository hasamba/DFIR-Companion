import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { RELOADABLE_ENV_PREFIXES } from "../../src/settings/envManager.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader, type SigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import {
  bundledSigmaGrader,
  sigmaInventorySummary,
  sigmaRulesEnabled,
} from "../../src/composition/sigmaRules.js";

// The import-time Sigma grader reaches the CloudTrail importer through the pipeline (#2202), and
// the server's DFIR_SIGMA_RULES switch is read at import time. Synthetic values only.

const RECORD = {
  eventVersion: "1.08",
  eventTime: "2026-03-01T10:00:00Z",
  eventSource: "securityhub.amazonaws.com",
  eventName: "BatchUpdateFindings",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2",
  userIdentity: { type: "IAMUser", userName: "alice", accountId: "111111111111" },
  recipientAccountId: "111111111111",
  readOnly: false,
  eventID: "evt-1",
};

async function pipeline(sigmaGrader?: SigmaImportGrader): Promise<AnalysisPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-sigma-wiring-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  return new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore: new StateStore(caseStore),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    ...(sigmaGrader ? { sigmaGrader } : {}),
  });
}

const run = async (p: AnalysisPipeline) => {
  const state = await p.importAws("c1", JSON.stringify({ Records: [RECORD] }), {
    label: "trail.json",
    idPrefix: "a1",
    importedAt: "2026-03-02T00:00:00Z",
  });
  return state.forensicTimeline.find((e) => /BatchUpdateFindings/.test(e.description));
};

describe("Sigma grader wiring", () => {
  it("grades through the pipeline when a grader is configured", async () => {
    const ev = await run(await pipeline(createSigmaImportGrader(loadBundledSigmaRuleSet().set)));
    expect(ev?.severity).toBe("High");
    expect(ev?.description).toMatch(/^Sigma: AWS SecurityHub Findings Evasion/);
  });

  it("grades exactly as before without one", async () => {
    const ev = await run(await pipeline());
    expect(ev?.description).not.toMatch(/Sigma/);
  });
});

describe("server Sigma settings", () => {
  it("is on unless DFIR_SIGMA_RULES says off", () => {
    expect(sigmaRulesEnabled({})).toBe(true);
    expect(sigmaRulesEnabled({ DFIR_SIGMA_RULES: "on" })).toBe(true);
    for (const v of ["off", "OFF", "0", "false", "no"])
      expect(sigmaRulesEnabled({ DFIR_SIGMA_RULES: v })).toBe(false);
  });

  it("loads the bundled grader once and reads the switch at import time", () => {
    const g = bundledSigmaGrader();
    expect(bundledSigmaGrader()).toBe(g);
    expect(g.set.release).toBe("r2026-07-01");
    const before = process.env.DFIR_SIGMA_RULES;
    try {
      process.env.DFIR_SIGMA_RULES = "off";
      expect(g.enabled()).toBe(false);
      process.env.DFIR_SIGMA_RULES = "on";
      expect(g.enabled()).toBe(true);
    } finally {
      if (before === undefined) delete process.env.DFIR_SIGMA_RULES;
      else process.env.DFIR_SIGMA_RULES = before;
    }
  });

  it("summarises the inventory per log source", () => {
    expect(sigmaInventorySummary(bundledSigmaGrader().set)).toMatch(
      /^Sigma rules r2026-07-01 — aws-cloudtrail: .*28 loaded/,
    );
  });

  it("reloads DFIR_SIGMA_ on save, in the server and the browser lists (Codex review)", async () => {
    expect(RELOADABLE_ENV_PREFIXES.has("DFIR_SIGMA_")).toBe(true);
    const js = await readFile(
      new URL("../../../public/js/dashboard-env-settings.js", import.meta.url),
      "utf8",
    );
    const block = /const RELOADABLE_ENV_PREFIXES = \[([\s\S]*?)\];/.exec(js)?.[1] ?? "";
    expect(block).toMatch(/^\s*"DFIR_SIGMA_",?\s*$/m);
  });
});
