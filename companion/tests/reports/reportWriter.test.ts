import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { LegitimateStore, markerId } from "../../src/analysis/legitimate.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-report-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  const state = emptyState("c1");
  state.lastSummary = "summary text";
  await stateStore.save(state);
});

describe("ReportWriter", () => {
  it("writes all report files and returns their paths", async () => {
    const writer = new ReportWriter(caseStore, stateStore);
    const paths = await writer.writeAll("c1");

    expect(paths.markdown).toMatch(/report\.md$/);
    const md = await readFile(paths.markdown, "utf8");
    expect(md).toContain("summary text");

    expect(paths.html).toMatch(/report\.html$/);
    const html = await readFile(paths.html, "utf8");
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("summary text");

    const findings = await readFile(paths.findingsCsv, "utf8");
    expect(findings).toContain("id,severity,confidence,title");

    const exported = JSON.parse(await readFile(paths.stateJson, "utf8"));
    expect(exported.caseId).toBe("c1");
  });

  it("excludes client-confirmed legitimate forensic events from the report", async () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "attacker beacon callout", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00Z", description: "client admin maintenance window", severity: "Low",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(state);

    const legitimate = new LegitimateStore(caseStore);
    await legitimate.save("c1", [
      { id: markerId("event", "e2"), kind: "event", ref: "e2", note: "client's maintenance", markedAt: "2026-05-28T10:00:00Z", label: "client admin maintenance window" },
    ]);

    const writer = new ReportWriter(caseStore, stateStore, undefined, legitimate);
    const paths = await writer.writeAll("c1");

    const forensic = await readFile(paths.forensicTimelineCsv, "utf8");
    expect(forensic).toContain("attacker beacon callout");          // kept
    expect(forensic).not.toContain("client admin maintenance window"); // legit event excluded

    const md = await readFile(paths.markdown, "utf8");
    expect(md).not.toContain("client admin maintenance window");
  });

  it("exports the incident timeline as CSV, excluding legitimate events", async () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "attacker beacon callout", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00Z", description: "client admin maintenance window", severity: "Low",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(state);

    const legitimate = new LegitimateStore(caseStore);
    await legitimate.save("c1", [
      { id: markerId("event", "e2"), kind: "event", ref: "e2", note: "client's maintenance", markedAt: "2026-05-28T10:00:00Z", label: "client admin maintenance window" },
    ]);

    const writer = new ReportWriter(caseStore, stateStore, undefined, legitimate);
    const csv = await writer.incidentTimelineCsv("c1");

    expect(csv).toContain("timestamp,endTimestamp,count,severity,description");
    expect(csv).toContain("attacker beacon callout");
    expect(csv).not.toContain("client admin maintenance window"); // legit event excluded
  });

  it("exports the report as a .docx Buffer, applying scope/legitimate filtering", async () => {
    const { default: JSZip } = await import("jszip");

    const state = emptyState("c1");
    state.lastSummary = "real summary text";
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "attacker beacon callout", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00Z", description: "client admin maintenance window", severity: "Low",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(state);

    const legitimate = new LegitimateStore(caseStore);
    await legitimate.save("c1", [
      { id: markerId("event", "e2"), kind: "event", ref: "e2", note: "client's maintenance",
        markedAt: "2026-05-28T10:00:00Z", label: "client admin maintenance window" },
    ]);

    const writer = new ReportWriter(caseStore, stateStore, undefined, legitimate);
    const buf = await writer.docx("c1");

    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBeGreaterThan(1024);

    const zip = await JSZip.loadAsync(buf);
    const xml = await zip.file("word/document.xml")!.async("text");
    expect(xml).toContain("real summary text");                        // canonical report content present
    expect(xml).toContain("attacker beacon callout");                  // kept
    expect(xml).not.toContain("client admin maintenance window");      // legit event excluded
  }, 30_000);   // docx generation is CPU-heavy; give it headroom under full-suite parallel load

  it("builds a mobile summary with the case name and scope/legitimate filtering applied", async () => {
    const state = emptyState("c1");
    state.lastSummary = "mobile recap";
    state.findings.push({ id: "f1", severity: "Critical", title: "Ransomware deployed", description: "d",
      relatedIocs: [], sourceScreenshots: [], mitreTechniques: ["T1486"], firstSeen: "t0", lastUpdated: "t1", status: "open" });
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "attacker beacon callout", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00Z", description: "client admin maintenance window", severity: "Low",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(state);

    const legitimate = new LegitimateStore(caseStore);
    await legitimate.save("c1", [
      { id: markerId("event", "e2"), kind: "event", ref: "e2", note: "client's maintenance",
        markedAt: "2026-05-28T10:00:00Z", label: "client admin maintenance window" },
    ]);

    const writer = new ReportWriter(caseStore, stateStore, undefined, legitimate);
    const s = await writer.mobileSummary("c1");

    expect(s.caseId).toBe("c1");
    expect(s.caseName).toBe("n");               // pulled from case.json (createCase name "n")
    expect(s.summary).toBe("mobile recap");
    expect(s.severityCounts.Critical).toBe(1);
    expect(s.counts.events).toBe(1);            // legit event e2 filtered out
    expect(s.events.items.map((e) => e.id)).toEqual(["e1"]);
    expect(s.events.items.map((e) => e.description)).not.toContain("client admin maintenance window");
  });

  it("builds an ATT&CK Navigator layer, excluding techniques only from legitimate events", async () => {
    const state = emptyState("c1");
    state.findings.push({ id: "f1", severity: "Critical", title: "Ransomware deployed", description: "d",
      relatedIocs: [], sourceScreenshots: [], mitreTechniques: ["T1486"],
      firstSeen: "t0", lastUpdated: "t1", status: "open" });
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "attacker beacon callout", severity: "High",
        mitreTechniques: ["T1071"], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00Z", description: "client admin maintenance window", severity: "Low",
        mitreTechniques: ["T1018"], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(state);

    const legitimate = new LegitimateStore(caseStore);
    await legitimate.save("c1", [
      { id: markerId("event", "e2"), kind: "event", ref: "e2", note: "client's maintenance",
        markedAt: "2026-05-28T10:00:00Z", label: "client admin maintenance window" },
    ]);

    const writer = new ReportWriter(caseStore, stateStore, undefined, legitimate);
    const layer = await writer.attackLayer("c1");

    const ids = layer.techniques.map((t) => t.techniqueID);
    expect(ids).toContain("T1486"); // finding technique
    expect(ids).toContain("T1071"); // attacker-event technique kept
    expect(ids).not.toContain("T1018"); // legit-event-only technique excluded
    expect(layer.domain).toBe("enterprise-attack");
  });
});
