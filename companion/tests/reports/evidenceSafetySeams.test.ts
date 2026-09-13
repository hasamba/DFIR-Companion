import { describe, it, expect, vi, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { renderDocxReportChecked } from "../../src/reports/docx.js";
import { renderStandalonePresentationChecked } from "../../src/reports/presentationExport.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import * as evidenceSafety from "../../src/reports/evidenceSafety.js";

// #1006 — the check is wired at the door of every human-readable export. Every exporter defangs
// and escapes correctly today, so the real renderers produce no finding (the first block pins
// that); the wiring itself is proven by making the check report, and reading where the warning
// lands: in the document, on the activity log, and in the generate-report response.

vi.mock("../../src/reports/evidenceSafety.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/reports/evidenceSafety.js")>();
  return { ...actual, checkEvidenceSafety: vi.fn(actual.checkEvidenceSafety) };
});

const check = vi.mocked(evidenceSafety.checkEvidenceSafety);
const LIVE = "https://evil.example/drop.ps1";
const PLANTED: evidenceSafety.EvidenceSafetyFinding[] = [{ kind: "live-indicator", value: LIVE }];

function hostileState(): InvestigationState {
  const state = emptyState("c1");
  state.lastSummary = `Beacon to ${LIVE} then 203.0.113.9.`;
  state.iocs.push(
    { id: "i1", type: "url", value: LIVE, firstSeen: "2026-05-01T00:00:00Z" },
    { id: "i2", type: "ip", value: "203.0.113.9", firstSeen: "2026-05-01T00:00:00Z" },
    { id: "i3", type: "domain", value: "evil.example", firstSeen: "2026-05-01T00:00:00Z" },
  );
  state.forensicTimeline.push({
    id: "e1",
    timestamp: "2026-05-01T00:00:00Z",
    description: `download ${LIVE} <script>alert(1)</script> <img src=x onerror="alert(2)">`,
    severity: "High",
    asset: "WIN-01",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  state.findings.push({
    id: "f1",
    title: "C2 at evil.example",
    description: `the host reached ${LIVE} <a href="javascript:alert(3)">x</a>`,
    severity: "High",
    mitreTechniques: [],
    relatedEventIds: ["e1"],
    relatedIocs: ["i1"],
    sourceScreenshots: [],
    firstSeen: "2026-05-01T00:00:00Z",
    lastUpdated: "2026-05-01T00:00:00Z",
    status: "open",
  });
  return state;
}

let cases: CaseStore;
let stateStore: StateStore;
let activityLogStore: ActivityLogStore;
let writer: ReportWriter;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  check.mockClear();
  const root = await mkdtemp(join(tmpdir(), "dfir-evidence-safety-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "Case", investigator: "Alice", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save(hostileState());
  activityLogStore = new ActivityLogStore(cases);
  writer = new ReportWriter(cases, stateStore);
  app = createApp(cases, { stateStore, reportWriter: writer, activityLogStore });
});

describe("today's exporters pass the check", () => {
  it("Markdown + HTML: no finding, no banner, an empty warning list", async () => {
    const paths = await writer.writeAll("c1");
    expect(paths.evidenceSafety).toEqual([]);
    expect(await readFile(paths.html, "utf8")).not.toContain('class="evidence-safety"');
    expect(await readFile(paths.markdown, "utf8")).not.toContain("Evidence-safety warning");
  });

  it("DOCX, interactive HTML and the deck: no finding", async () => {
    const { evidenceSafety: docx } = await renderDocxReportChecked(hostileState());
    expect(docx).toEqual([]);
    const interactive = await request(app).get("/cases/c1/report/interactive");
    expect(interactive.status).toBe(200);
    expect(interactive.text).not.toContain('class="evidence-safety"');
    const deck = await request(app).get("/cases/c1/present/export");
    expect(deck.status).toBe(200);
    expect(deck.text).not.toContain('class="evidence-safety"');
    await settled();
    expect(await activityLogStore.load("c1")).toEqual([]);
  });
});

describe("when the check reports", () => {
  it("the HTML and Markdown report carry the banner, the response carries the lines, the activity log has one entry", async () => {
    check.mockReturnValue(PLANTED);
    const res = await request(app).post("/cases/c1/report");
    expect(res.status).toBe(200);
    expect(res.body.evidenceSafety).toEqual([
      "1 live indicator(s) not defanged: hxxps://evil[.]example/drop.ps1",
    ]);
    const html = await readFile(res.body.html, "utf8");
    expect(html).toContain('class="evidence-safety"');
    expect(html.indexOf('class="evidence-safety"')).toBeLessThan(html.indexOf('<main class="report">'));
    const md = await readFile(res.body.markdown, "utf8");
    expect(md.startsWith("> **")).toBe(true);
    expect(md).toContain("Evidence-safety warning");
    const entries = await warnings();
    expect(entries).toHaveLength(1);
    expect(entries[0].detail).toMatch(/^html export produced with a warning — 1 live indicator/);
  });

  it("the DOCX carries the banner as its first paragraphs", async () => {
    check.mockReturnValue(PLANTED);
    const { default: JSZip } = await import("jszip");
    const res = await request(app).get("/cases/c1/report.docx").buffer(true).parse(binaryParser);
    expect(res.status).toBe(200);
    const zip = await JSZip.loadAsync(res.body as Buffer);
    const xml = await zip.file("word/document.xml")!.async("text");
    expect(xml.indexOf("Evidence-safety warning")).toBeGreaterThan(-1);
    expect(xml.indexOf("Evidence-safety warning")).toBeLessThan(xml.indexOf("Incident"));
    expect(xml).toContain("hxxps://evil[.]example/drop.ps1");
    const entries = await warnings();
    expect(entries.map((e) => e.detail)).toEqual([expect.stringMatching(/^docx export/)]);
  });

  it("the interactive report carries the banner and logs", async () => {
    check.mockReturnValue(PLANTED);
    const res = await request(app).get("/cases/c1/report/interactive");
    expect(res.status).toBe(200);
    expect(res.text.indexOf('class="evidence-safety"')).toBeLessThan(
      res.text.indexOf('<main class="report">'),
    );
    const nonce = /'nonce-([^']+)'/.exec(res.headers["content-security-policy"] ?? "")?.[1];
    expect(res.text).toContain(`<style nonce="${nonce}">.evidence-safety`);
    const entries = await warnings();
    expect(entries.map((e) => e.detail)).toEqual([expect.stringMatching(/^interactive-html export/)]);
  });

  it("the deck carries the banner and logs", async () => {
    check.mockReturnValue(PLANTED);
    const res = await request(app).get("/cases/c1/present/export");
    expect(res.status).toBe(200);
    expect(res.text).toContain('class="evidence-safety"');
    expect(res.text).not.toContain("CSP_NONCE_PLACEHOLDER");
    const entries = await warnings();
    expect(entries.map((e) => e.detail)).toEqual([expect.stringMatching(/^presentation export/)]);
  });
});

describe("the deck check reads the finished file", () => {
  it("flags a live case indicator the deck still carries, and passes once nothing does", async () => {
    check.mockImplementation(
      (await vi.importActual<typeof evidenceSafety>("../../src/reports/evidenceSafety.js"))
        .checkEvidenceSafety,
    );
    const state = hostileState();
    const deck = await writer.presentation("c1");
    // caseName is case metadata defangDeck leaves alone by design (#901/#906) — so a URL IOC in it
    // is exactly the leak this check exists for.
    const live = await renderStandalonePresentationChecked(
      state,
      { ...deck, caseName: `Case ${LIVE}` },
      "n1",
    );
    expect(live.evidenceSafety.map((f) => f.value)).toContain(LIVE);
    expect(live.html).toContain('class="evidence-safety"');
    expect(live.html).toContain('<style nonce="n1">.evidence-safety');
    // The real deck passes — including the bare `evil.example` in a finding title, which the
    // deck's own IOC pool never vouched for and the case's domain list now does (#1006).
    const clean = await renderStandalonePresentationChecked(state, deck, "n1");
    expect(clean.evidenceSafety).toEqual([]);
    expect(clean.html).not.toContain('class="evidence-safety"');
    expect(clean.html).toContain("C2 at evil[.]example");
  });
});

// The activity append is fire-and-forget at the route; give it a turn before reading the log.
async function settled(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 20));
}

async function warnings() {
  await settled();
  return (await activityLogStore.load("c1")).filter((e) => e.action === "evidence-safety-warning");
}

function binaryParser(res: NodeJS.ReadableStream, cb: (err: Error | null, body: Buffer) => void): void {
  const chunks: Buffer[] = [];
  res.on("data", (c: Buffer) => chunks.push(c));
  res.on("end", () => cb(null, Buffer.concat(chunks)));
}
