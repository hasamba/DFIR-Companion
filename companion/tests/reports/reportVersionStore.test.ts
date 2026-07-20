import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ReportVersionStore } from "../../src/reports/reportVersionStore.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";

let caseStore: CaseStore;
let versions: ReportVersionStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-report-versions-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  versions = new ReportVersionStore(caseStore);
});

const emptyDiffState = () => ({ findings: [], iocs: [], forensicTimeline: [] });

describe("ReportVersionStore", () => {
  it("returns [] when no versions exist yet", async () => {
    expect(await versions.list("c1")).toEqual([]);
  });

  it("snapshots a version and lists it newest first", async () => {
    const first = await versions.snapshot("c1", { markdown: "# report v1", meta: emptyReportMeta(), state: emptyDiffState() });
    expect(first.version).toBe("v1");

    const second = await versions.snapshot("c1", { markdown: "# report v2", meta: emptyReportMeta(), state: emptyDiffState() });
    expect(second.version).toBe("v2");

    const list = await versions.list("c1");
    expect(list.map((v) => v.id)).toEqual([second.id, first.id]);
  });

  it("skips writing a new version when the markdown is unchanged", async () => {
    const first = await versions.snapshot("c1", { markdown: "# same", meta: emptyReportMeta(), state: emptyDiffState() });
    const again = await versions.snapshot("c1", { markdown: "# same", meta: emptyReportMeta(), state: emptyDiffState() });
    expect(again.id).toBe(first.id);
    expect(await versions.list("c1")).toHaveLength(1);
  });

  it("retrieves a full record by id, including markdown/meta/state", async () => {
    const meta = { ...emptyReportMeta(), organization: "ExampleCorp" };
    const state = { findings: [{ id: "f1", severity: "Critical" as const, title: "Ransomware deployed", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "t0", lastUpdated: "t1", status: "open" as const }], iocs: [], forensicTimeline: [] };
    const summary = await versions.snapshot("c1", { markdown: "# report", meta, state });

    const record = await versions.get("c1", summary.id);
    expect(record?.markdown).toBe("# report");
    expect(record?.meta.organization).toBe("ExampleCorp");
    expect(record?.state.findings).toHaveLength(1);
    expect(record?.findingsCount).toBe(1);
  });

  it("returns null for a missing version id", async () => {
    expect(await versions.get("c1", "ghost")).toBeNull();
  });

  it("refuses a path-traversal id even when it would resolve to a real sibling file", async () => {
    // Plant a JSON file one level above the report-versions dir. Without id validation,
    // get("c1", "../secret") would resolve to <report-versions>/../secret.json and read it.
    const stateDir = caseStore.stateDir("c1");
    await writeFile(join(stateDir, "secret.json"), JSON.stringify({ markdown: "TOP SECRET" }), "utf8");

    expect(await versions.get("c1", "../secret")).toBeNull();
    expect(await versions.get("c1", "..%2Fsecret")).toBeNull();
    expect(await versions.get("c1", "/etc/hostname")).toBeNull();
  });

  it("prunes the oldest versions beyond DFIR_REPORT_VERSION_MAX", async () => {
    const prev = process.env.DFIR_REPORT_VERSION_MAX;
    process.env.DFIR_REPORT_VERSION_MAX = "2";
    try {
      const v1 = await versions.snapshot("c1", { markdown: "# 1", meta: emptyReportMeta(), state: emptyDiffState() });
      await versions.snapshot("c1", { markdown: "# 2", meta: emptyReportMeta(), state: emptyDiffState() });
      const v3 = await versions.snapshot("c1", { markdown: "# 3", meta: emptyReportMeta(), state: emptyDiffState() });

      const list = await versions.list("c1");
      expect(list).toHaveLength(2);
      expect(list.map((v) => v.id)).toEqual([v3.id, expect.any(String)]);
      expect(await versions.get("c1", v1.id)).toBeNull(); // pruned
    } finally {
      if (prev === undefined) delete process.env.DFIR_REPORT_VERSION_MAX;
      else process.env.DFIR_REPORT_VERSION_MAX = prev;
    }
  });

  it("keeps auto-numbered labels unique after pruning at the retention cap", async () => {
    const prev = process.env.DFIR_REPORT_VERSION_MAX;
    process.env.DFIR_REPORT_VERSION_MAX = "2";
    try {
      for (let i = 1; i <= 4; i++) {
        await versions.snapshot("c1", { markdown: `# ${i}`, meta: emptyReportMeta(), state: emptyDiffState() });
      }
      // Once the cap is reached the list stops growing, so a length-derived label would repeat "v3"
      // for every later version. Labels must keep counting up from the newest retained one.
      expect((await versions.list("c1")).map((v) => v.version)).toEqual(["v4", "v3"]);
    } finally {
      if (prev === undefined) delete process.env.DFIR_REPORT_VERSION_MAX;
      else process.env.DFIR_REPORT_VERSION_MAX = prev;
    }
  });

  it("carries the manual revision label from report-meta when present", async () => {
    const meta = { ...emptyReportMeta(), revisions: [{ version: "1.0", date: "2026-01-01", author: "a", comments: "initial" }] };
    const summary = await versions.snapshot("c1", { markdown: "# report", meta, state: emptyDiffState() });
    expect(summary.manualVersion).toBe("1.0");
  });
});
