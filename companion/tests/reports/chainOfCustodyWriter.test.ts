import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { redactCustodyRecords } from "../../src/analysis/redactedExport.js";
import { verifyCustodyManifest } from "../../src/analysis/custodyManifest.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";

let cases: CaseStore;
let custody: CustodyStore;
let writer: ReportWriter;

const SECRET = Buffer.from("a".repeat(64), "hex");

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-custodyreport-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  custody = new CustodyStore(cases);
  const state = new StateStore(cases);
  writer = new ReportWriter(cases, state, { custodyStore: custody, instanceSecret: SECRET });

  const artifactPath = join(cases.importsDir("c1"), "0001_evidence.csv");
  await writeFile(artifactPath, "ts,message\n", "utf8");
  await custody.record("c1", {
    artifactPath,
    sha256: "a".repeat(64),
    collectedBy: "alice",
    collectedAt: "2026-07-28T10:00:00.000Z",
    source: "WORKSTATION-7",
    trigger: "import",
    caseId: "c1",
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

describe("what survives redaction in the custody appendix (#362)", () => {
  const SHA = "a".repeat(64);

  // A hash is not PII: a SHA-256 reveals nothing about the file's contents, its name, or the host
  // it came from. Tokenizing it leaves the recipient a chain they cannot check against the evidence
  // they hold, which is most of the appendix's value to an external party.
  it("keeps the artifact hash intact", async () => {
    const redact = (s: string) =>
      s.replace(/WORKSTATION-7/g, "ANON_HOST_1").replace(/[0-9a-f]{64}/g, "ANON_HASH");

    const { markdown } = await writer.redactedReportContents("c1", redact);

    expect(markdown).toContain(SHA);
    expect(markdown).not.toContain("ANON_HASH");
  });

  it("keeps prevHash intact, without which the chain cannot be walked at all", async () => {
    const second = join(cases.importsDir("c1"), "0002_more.csv");
    await writeFile(second, "more\n", "utf8");
    await custody.record("c1", {
      artifactPath: second,
      sha256: "b".repeat(64),
      collectedBy: "alice",
      collectedAt: "2026-07-28T11:00:00.000Z",
      source: "WORKSTATION-7",
      trigger: "import",
      caseId: "c1",
    });
    const before = (await custody.load("c1"))[1].prevHash;
    expect(before).toMatch(/^[0-9a-f]{64}$/);

    const redactAll = (s: string) => `ANON(${s})`;
    const records = redactCustodyRecords(await custody.load("c1"), redactAll);

    expect(records[1].prevHash).toBe(before);
  });

  it("still redacts the path, the source host and the collector", async () => {
    const redactAll = (s: string) => `ANON(${s})`;

    const [record] = redactCustodyRecords(await custody.load("c1"), redactAll);

    expect(record.artifactPath).toContain("ANON(");
    expect(record.source).toBe("ANON(WORKSTATION-7)");
    expect(record.collectedBy).toBe("ANON(alice)");
    expect(record.trigger).toContain("ANON(");
  });

  it("keeps the ordinal and the event name, which carry no case data", async () => {
    const redactAll = (s: string) => `ANON(${s})`;

    const [record] = redactCustodyRecords(await custody.load("c1"), redactAll);

    expect(record.seq).toBe(1);
    expect(record.event).toBe("collected");
  });

  it("redacts a field it has never heard of, rather than letting it through", async () => {
    // A field added to CustodyRecord later must be redacted by DEFAULT — leaking by default is the
    // failure mode worth engineering against here.
    const withExtra = {
      ...(await custody.load("c1"))[0],
      custodianNotes: "handed over by Bob at ACME-DC01",
    } as Record<string, unknown>;
    const redactAll = (s: string) => `ANON(${s})`;

    const [record] = redactCustodyRecords([withExtra as never], redactAll) as unknown as Record<
      string,
      unknown
    >[];

    expect(record.custodianNotes).toBe("ANON(handed over by Bob at ACME-DC01)");
  });
});

describe("the signed manifest that travels with a redacted package", () => {
  it("is built over the REDACTED records, never the real ones", async () => {
    const redact = (s: string) =>
      s.replace(/WORKSTATION-7/g, "ANON_HOST_1").replace(/evidence\.csv/g, "ANON_FILE");

    const { custodyManifest } = await writer.redactedReportContents("c1", redact);

    expect(custodyManifest).toBeDefined();
    const blob = JSON.stringify(custodyManifest);
    expect(blob).not.toContain("WORKSTATION-7");
    expect(blob).not.toContain("evidence.csv");
    expect(blob).toContain("ANON_HOST_1");
  });

  it("keeps the artifact hashes, so the chain still describes real evidence", async () => {
    const redact = (s: string) => `ANON(${s})`;

    const { custodyManifest } = await writer.redactedReportContents("c1", redact);

    expect(custodyManifest!.artifacts[0].sha256).toBe("a".repeat(64));
  });

  it("is signed, so the issuing installation can later prove what it sent", async () => {
    const { custodyManifest } = await writer.redactedReportContents("c1", (s) => s);

    expect(verifyCustodyManifest(custodyManifest!, SECRET)).toBe(true);
    expect(verifyCustodyManifest(custodyManifest!, Buffer.from("b".repeat(64), "hex"))).toBe(false);
  });

  it("is absent when the writer has no signing secret", async () => {
    const unsigned = new ReportWriter(cases, new StateStore(cases), { custodyStore: custody });

    const { custodyManifest } = await unsigned.redactedReportContents("c1", (s) => s);

    expect(custodyManifest).toBeUndefined();
  });
});
