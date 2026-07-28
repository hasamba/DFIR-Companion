import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";

let cases: CaseStore;
let custody: CustodyStore;
let writer: ReportWriter;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-custodyreport-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  custody = new CustodyStore(cases);
  const state = new StateStore(cases);
  writer = new ReportWriter(cases, state, { custodyStore: custody });

  const artifactPath = join(cases.importsDir("c1"), "0001_evidence.csv");
  await writeFile(artifactPath, "ts,message\n", "utf8");
  await custody.record("c1", {
    artifactPath, sha256: "a".repeat(64), collectedBy: "alice",
    collectedAt: "2026-07-28T10:00:00.000Z", source: "WORKSTATION-7", trigger: "import", caseId: "c1",
  });
});

describe("chain of custody in the generated report", () => {
  it("appears in the written Markdown report", async () => {
    await writer.writeAll("c1");

    const md = await readFile(join(cases.reportsDir("c1"), "report.md"), "utf8");
    expect(md).toContain("Chain of Custody");
    expect(md).toContain("0001_evidence.csv");
    expect(md).toContain("WORKSTATION-7");
  });

  it("appears in the HTML report too, since it renders from the same Markdown", async () => {
    await writer.writeAll("c1");

    const html = await readFile(join(cases.reportsDir("c1"), "report.html"), "utf8");
    expect(html).toContain("Chain of Custody");
    expect(html).toContain("0001_evidence.csv");
  });
});

describe("chain of custody in the REDACTED export", () => {
  // Custody records live in custody.jsonl, not in investigation.json — so they do NOT pass through
  // applyAnonDeep(state) like everything else the redacted report renders. Without explicit
  // redaction the appendix would ship the victim's hostnames and real filesystem paths to an
  // external party, which is the exact leak the redacted export exists to prevent.
  it("tokenizes the hostnames and paths in the custody appendix", async () => {
    const redact = (s: string) =>
      s.replace(/WORKSTATION-7/g, "ANON_HOST_1").replace(/0001_evidence\.csv/g, "ANON_PATH_1");

    const { markdown } = await writer.redactedReportContents("c1", redact);

    expect(markdown).toContain("Chain of Custody");
    expect(markdown).toContain("ANON_HOST_1");
    expect(markdown).not.toContain("WORKSTATION-7");
    expect(markdown).not.toContain("0001_evidence.csv");
  });
});
