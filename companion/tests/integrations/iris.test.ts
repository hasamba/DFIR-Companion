import { describe, it, expect } from "vitest";
import {
  irisEventDate, mapIoc, mapAsset, mapEvent, mapNextStepTask, buildNotes, executiveSummaryMarkdown,
} from "../../src/integrations/iris/irisMap.js";
import { tacticForTechniques } from "../../src/integrations/iris/mitreTactics.js";
import { pushCaseToIris, type IrisClientLike } from "../../src/integrations/iris/irisPush.js";
import { emptyState, type InvestigationState, type IOC, type ForensicEvent, type NextStep } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import type { GraphAsset } from "../../src/analysis/assetGraph.js";
import type {
  IrisCaseCreate, IrisCaseRef, IrisAssetRef, IrisIocRef, IrisEventRef, IrisDirRef, IrisTaskRef,
  IrisAssetBody, IrisIocBody, IrisEventBody, IrisTaskBody,
} from "../../src/integrations/iris/irisClient.js";

const IOC_TYPES = new Map<string, number>([["ip-dst", 5], ["domain", 9], ["md5", 20], ["sha256", 22], ["url", 30], ["filename", 40]]);
const ASSET_TYPES = new Map<string, number>([["windows - computer", 9], ["account", 1]]);
// IRIS event categories (MITRE tactics) name→id, and task statuses, as a stock install seeds them.
const CATEGORY_MAP = new Map<string, number>([
  ["unspecified", 1], ["execution", 5], ["persistence", 6], ["privilege escalation", 7],
  ["credential access", 9], ["lateral movement", 11], ["impact", 15],
]);
const STATUS_MAP = new Map<string, number>([["to do", 1], ["in progress", 2], ["done", 4]]);

function ioc(over: Partial<IOC> & { value: string; type: IOC["type"] }): IOC {
  return { id: over.value, firstSeen: "2026-06-04T00:00:00Z", ...over };
}
function asset(over: Partial<GraphAsset> & { name: string; type: GraphAsset["type"] }): GraphAsset {
  return { id: `${over.type}:${over.name}`, compromised: false, iocIds: [], findingIds: [], eventCount: 1, maxSeverity: "Info", ...over };
}
function event(over: Partial<ForensicEvent> & { timestamp: string; description: string }): ForensicEvent {
  return { id: over.timestamp, severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over };
}

describe("irisMap", () => {
  it("formats a timeline date as %Y-%m-%dT%H:%M:%S.%f (UTC, microseconds, no Z)", () => {
    expect(irisEventDate("2026-06-04T13:45:09.123Z")).toBe("2026-06-04T13:45:09.123000");
    expect(irisEventDate("not a date")).toBeNull();
  });

  it("maps a hash IOC to the right type by length, with intel description + tags", () => {
    const body = mapIoc(ioc({
      value: "d41d8cd98f00b204e9800998ecf8427e", type: "hash",
      enrichments: [{ source: "VirusTotal", verdict: "malicious", score: "52/70", fetchedAt: "t", tags: ["emotet"] }],
    }), IOC_TYPES)!;
    expect(body.ioc_type_id).toBe(20);                  // md5 (32 hex)
    expect(body.ioc_tlp_id).toBe(2);
    expect(body.ioc_description).toContain("VirusTotal: malicious (52/70)");
    expect(String(body.ioc_tags)).toContain("malicious");
    expect(String(body.ioc_tags)).toContain("emotet");
  });

  it("maps ip/domain/url/sha256 IOC types and returns null for an unmappable kind", () => {
    expect(mapIoc(ioc({ value: "8.8.8.8", type: "ip" }), IOC_TYPES)!.ioc_type_id).toBe(5);
    expect(mapIoc(ioc({ value: "evil.com", type: "domain" }), IOC_TYPES)!.ioc_type_id).toBe(9);
    expect(mapIoc(ioc({ value: "http://x", type: "url" }), IOC_TYPES)!.ioc_type_id).toBe(30);
    expect(mapIoc(ioc({ value: "a".repeat(64), type: "hash" }), IOC_TYPES)!.ioc_type_id).toBe(22);
    // "process" has no candidate in this map (only filename present → it DOES map to filename)
    expect(mapIoc(ioc({ value: "evil.exe", type: "process" }), IOC_TYPES)!.ioc_type_id).toBe(40);
    // "other" has no candidate in this map → null (skipped)
    expect(mapIoc(ioc({ value: "weird", type: "other" }), IOC_TYPES)).toBeNull();
  });

  it("maps a host asset (with IP / FQDN detection) and a compromise status", () => {
    const host = mapAsset(asset({ name: "DC01.corp.local", type: "host", compromised: true, maxSeverity: "Critical", eventCount: 4 }), ASSET_TYPES)!;
    expect(host.asset_type_id).toBe(9);
    expect(host.asset_compromise_status_id).toBe(1);    // compromised
    expect(host.asset_domain).toBe("DC01.corp.local");
    const ipHost = mapAsset(asset({ name: "10.0.0.5", type: "host" }), ASSET_TYPES)!;
    expect(ipHost.asset_ip).toBe("10.0.0.5");
    const acct = mapAsset(asset({ name: "CORP\\admin", type: "account" }), ASSET_TYPES)!;
    expect(acct.asset_type_id).toBe(1);
  });

  it("maps a forensic event, links assets/IOCs, flags high severity into summary, skips no-timestamp", () => {
    const ctx = { assetByName: new Map([["dc01", 7]]), iocByValue: new Map([["8.8.8.8", 3]]), categoryByName: CATEGORY_MAP };
    const e = mapEvent(event({
      timestamp: "2026-06-04T13:00:00Z", description: "C2 beacon to 8.8.8.8", severity: "High",
      asset: "DC01", mitreTechniques: ["T1071"], sources: ["THOR"],
    }), ctx)!;
    expect(e.event_date).toBe("2026-06-04T13:00:00.000000");
    expect(e.event_in_summary).toBe(true);
    expect(e.event_assets).toEqual([7]);
    expect(e.event_iocs).toEqual([3]);                  // value appears in description
    expect(String(e.event_content)).toContain("Sources: THOR");
    expect(mapEvent(event({ timestamp: "bad", description: "x" }), ctx)).toBeNull();
  });

  it("keeps the full event title (no 150-char truncation) and only trims a runaway line", () => {
    const long = "THOR Warning [Filescan]: Malware file found — C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Exfiltration\\Invoke-TokenManipulation.ps1 (owner: BUILTIN\\Administrators)";
    const e = mapEvent(event({ timestamp: "2026-06-04T13:00:00Z", description: long }), { assetByName: new Map(), iocByValue: new Map() })!;
    expect(e.event_title).toBe(long);                   // 168 chars — kept in full (was cut at 150)
    const runaway = "x ".repeat(400);                   // 800 chars
    const e2 = mapEvent(event({ timestamp: "2026-06-04T13:00:00Z", description: runaway }), { assetByName: new Map(), iocByValue: new Map() })!;
    expect((e2.event_title as string).length).toBeLessThanOrEqual(301);
    expect(e2.event_title as string).toMatch(/…$/);
  });

  it("auto-assigns the event category from MITRE technique → tactic, and links finding IOCs", () => {
    const ctx = {
      assetByName: new Map<string, number>(), iocByValue: new Map([["mimikatz.exe", 9]]), categoryByName: CATEGORY_MAP,
      findingIocValues: () => ["mimikatz.exe"],          // linked via the event's finding, not its text
    };
    const e = mapEvent(event({
      timestamp: "2026-06-04T13:00:00Z", description: "LSASS access observed", mitreTechniques: ["T1003.001"],
      relatedFindingIds: ["f1"],
    }), ctx)!;
    expect(e.event_category_id).toBe("9");              // T1003 → Credential Access → id 9
    expect(e.event_iocs).toEqual([9]);                  // pulled in via the finding link
  });

  it("derives a tactic from techniques (priority) and from keywords when no technique is present", () => {
    expect(tacticForTechniques(["T1059.001"])).toBe("Execution");
    expect(tacticForTechniques(["T1083", "T1486"])).toBe("Impact");        // worst stage wins
    expect(tacticForTechniques([], "Trigona ransomware encrypted files")).toBe("Impact");
    expect(tacticForTechniques([], "nothing notable here")).toBeUndefined();
  });

  it("maps a next step to an IRIS task body (title ≥2 chars, priority tag)", () => {
    const step: NextStep = { id: "s1", priority: "critical", action: "Isolate DC01", rationale: "Active C2", pointer: "host DC01" };
    const t = mapNextStepTask(step);
    expect(t.task_title).toBe("[critical] Isolate DC01");
    expect(String(t.task_description)).toContain("Active C2");
    expect(String(t.task_tags)).toContain("critical");
  });

  it("builds notes only for non-empty sections; summary override beats the AI summary", () => {
    const state = { ...emptyState("c1"), attackerPath: "phish → exec → exfil", lastSummary: "AI summary" };
    const meta = { ...emptyReportMeta(), businessImpact: "Prod down 4h", recommendations: ["Rotate creds"] };
    const notes = buildNotes(state, meta);
    const titles = notes.map((n) => n.title);
    expect(titles).toContain("Attacker Path");
    expect(titles).toContain("Business Impact Analysis");
    expect(titles).toContain("Recommendations");
    expect(titles).not.toContain("Findings");           // none present
    expect(executiveSummaryMarkdown(state, meta)).toBe("AI summary");
    expect(executiveSummaryMarkdown(state, { ...meta, executiveSummary: "Human wins" })).toBe("Human wins");
  });
});

// ---- orchestrator with a recording mock client -----------------------------

class MockIris implements IrisClientLike {
  cases: IrisCaseRef[] = [];
  addedAssets: IrisAssetBody[] = [];
  addedIocs: IrisIocBody[] = [];
  addedEvents: IrisEventBody[] = [];
  addedTasks: IrisTaskBody[] = [];
  addedNotes: { dir: number; title: string }[] = [];
  existingAssets: IrisAssetRef[] = [];
  existingIocs: IrisIocRef[] = [];
  existingEvents: IrisEventRef[] = [];
  existingTasks: IrisTaskRef[] = [];
  dirs: IrisDirRef[] = [];
  deletedDirs: number[] = [];
  summary?: string;
  pinged = false;
  private seq = 100;

  async ping() { this.pinged = true; }
  async findCaseByName(name: string) { return this.cases.find((c) => c.caseName === name) ?? null; }
  async createCase(body: IrisCaseCreate) { const ref = { caseId: 1, caseName: body.case_name }; this.cases.push(ref); return ref; }
  async setSummary(_cid: number, md: string) { this.summary = md; }
  async iocTypeMap() { return IOC_TYPES; }
  async assetTypeMap() { return ASSET_TYPES; }
  async eventCategoryMap() { return CATEGORY_MAP; }
  async taskStatusMap() { return STATUS_MAP; }
  async listAssets() { return this.existingAssets; }
  async addAsset(_cid: number, body: IrisAssetBody) { this.addedAssets.push(body); return this.seq++; }
  async listIocs() { return this.existingIocs; }
  async addIoc(_cid: number, body: IrisIocBody) { this.addedIocs.push(body); return this.seq++; }
  async listEvents() { return this.existingEvents; }
  async addEvent(_cid: number, body: IrisEventBody) { this.addedEvents.push(body); return this.seq++; }
  async listTasks() { return this.existingTasks; }
  async addTask(_cid: number, body: IrisTaskBody) { this.addedTasks.push(body); return this.seq++; }
  async listDirectories() { return this.dirs; }
  async addDirectory(_cid: number, name: string) { const d = { id: this.seq++, name }; this.dirs.push(d); return d.id; }
  async deleteDirectory(_cid: number, id: number) { this.deletedDirs.push(id); this.dirs = this.dirs.filter((d) => d.id !== id); }
  async addNote(_cid: number, dir: number, title: string) { this.addedNotes.push({ dir, title }); return this.seq++; }
}

function sampleState(): InvestigationState {
  return {
    ...emptyState("Case Alpha"),
    iocs: [ioc({ value: "8.8.8.8", type: "ip" }), ioc({ value: "evil.com", type: "domain" })],
    forensicTimeline: [event({ timestamp: "2026-06-04T10:00:00Z", description: "logon to DC01", asset: "DC01", severity: "High" })],
    nextSteps: [{ id: "s1", priority: "critical", action: "Isolate DC01", rationale: "Active C2", pointer: "DC01" }],
    attackerPath: "phish → exec",
    lastSummary: "Two hosts compromised.",
  };
}

describe("pushCaseToIris", () => {
  it("creates the case when missing and pushes assets, IOCs, timeline, summary and notes", async () => {
    const m = new MockIris();
    const res = await pushCaseToIris(m, { caseName: "Case Alpha", state: sampleState() }, { baseUrl: "https://iris.example.org/" });
    expect(m.pinged).toBe(true);
    expect(res.created).toBe(true);
    expect(res.caseId).toBe(1);
    expect(m.summary).toContain("Two hosts compromised.");
    expect(res.iocs.added).toBe(2);
    expect(res.assets.added).toBe(1);                   // DC01 host derived from the event
    expect(res.timeline.added).toBe(1);
    expect(res.tasks.added).toBe(1);                    // the one recommended next step → a task
    expect(m.addedTasks[0].task_title).toBe("[critical] Isolate DC01");
    expect(m.addedTasks[0].task_status_id).toBe(1);     // "To do"
    expect(m.addedTasks[0].task_assignees_id).toEqual([]);
    expect(res.notes).toBeGreaterThanOrEqual(1);        // Attacker Path note
    expect(res.caseUrl).toBe("https://iris.example.org/case?cid=1");
  });

  it("dedupes a next-step task that already exists in IRIS (by title)", async () => {
    const m = new MockIris();
    m.existingTasks = [{ id: 9, title: "[critical] Isolate DC01" }];
    const res = await pushCaseToIris(m, { caseName: "Case Alpha", state: sampleState() });
    expect(res.tasks.existing).toBe(1);
    expect(res.tasks.added).toBe(0);
    expect(m.addedTasks).toHaveLength(0);
  });

  it("updates an existing case (matched by name) and dedupes already-present IOCs", async () => {
    const m = new MockIris();
    m.cases.push({ caseId: 42, caseName: "Case Alpha" });
    m.existingIocs = [{ id: 5, value: "8.8.8.8" }];     // already in IRIS
    const res = await pushCaseToIris(m, { caseName: "Case Alpha", state: sampleState() });
    expect(res.created).toBe(false);
    expect(res.caseId).toBe(42);
    expect(res.iocs.existing).toBe(1);                  // 8.8.8.8 skipped
    expect(res.iocs.added).toBe(1);                     // only evil.com added
    expect(m.addedIocs.map((b) => b.ioc_value)).toEqual(["evil.com"]);
  });

  it("clean-replaces the managed notes directory on re-push", async () => {
    const m = new MockIris();
    m.dirs.push({ id: 77, name: "DFIR Companion" });    // pre-existing from a prior push
    await pushCaseToIris(m, { caseName: "Case Alpha", state: sampleState() });
    expect(m.deletedDirs).toContain(77);                // old dir removed before re-adding
    expect(m.dirs.some((d) => d.name === "DFIR Companion")).toBe(true);
  });

  it("records a warning and skips an IOC with no mappable IRIS type", async () => {
    const m = new MockIris();
    const state = { ...emptyState("Case Beta"), iocs: [ioc({ value: "mystery", type: "other" })] };
    const res = await pushCaseToIris(m, { caseName: "Case Beta", state });
    expect(res.iocs.skipped).toBe(1);
    expect(res.iocs.added).toBe(0);
    expect(res.warnings.some((w) => w.includes("mystery"))).toBe(true);
  });
});
