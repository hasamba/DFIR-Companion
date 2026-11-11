import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { createImportIngest, type ImportIngestDeps } from "../../src/composition/importIngest.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

// End to end for #2302: each newly recognized export goes through the real import spine —
// resolveImportKind, then dispatchImport into a real AnalysisPipeline — and lands in the forensic
// timeline with the expected count, grade and description. Fixtures are the synthetic #2300 ones.

const fixture = (p: string): string =>
  readFileSync(new URL(`../fixtures/cloudCompat/${p}`, import.meta.url), "utf8");

async function realIngest(): Promise<ReturnType<typeof createImportIngest>> {
  const root = await mkdtemp(join(tmpdir(), "dfir-cloud-export-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const pipeline = new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore: new StateStore(caseStore),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const deps = {
    store: caseStore,
    options: { pipeline },
    runStateExclusive: async (_c: string, fn: () => Promise<unknown>) => fn(),
    importLock: new ImportLock(),
    recordImporterRun: () => {},
    redactErr: (err: unknown) => String(err),
    autoTagImported: async () => {},
    getControl: async () => ({ enabled: true }),
    applyWhitelistToCase: async () => ({ matched: 0, added: 0 }),
    applyNsrlToCase: async () => ({ matchedIocs: 0, matchedEvents: 0, added: 0 }),
    applyDeobfuscationToCase: async () => ({ deobfuscated: 0, newIocs: 0, reanalyzed: 0 }),
    resynthesizeInBackground: () => {},
  } as unknown as ImportIngestDeps;
  return createImportIngest(deps);
}

async function importFile(name: string, text: string): Promise<{ kind: string; state: InvestigationState }> {
  const ingest = await realIngest();
  const kind = ingest.resolveImportKind(name, text);
  const state = (await ingest.dispatchImport(kind, "c1", text, {
    label: name,
    idPrefix: "x1",
    importedAt: "2026-11-02T00:00:00Z",
  })) as InvestigationState;
  return { kind, state };
}

interface Expect {
  file: string;
  kind: string;
  events: number;
  /** The description prefix and the severity of the event that matters in the file. */
  prefix: string;
  severity: string;
}

const CASES: Expect[] = [
  {
    file: "log-analytics/SigninLogs.json",
    kind: "m365",
    events: 2,
    prefix: "Entra sign-in: [interactive] user1@",
    severity: "Medium",
  },
  {
    file: "log-analytics/SigninLogs.csv",
    kind: "m365",
    events: 2,
    prefix: "Entra sign-in: [interactive] user1@",
    severity: "Medium",
  },
  {
    file: "log-analytics/AADNonInteractiveUserSignInLogs.json",
    kind: "m365",
    events: 1,
    prefix: "Entra sign-in: [non-interactive] user1@",
    severity: "Medium",
  },
  {
    file: "log-analytics/AADNonInteractiveUserSignInLogs.csv",
    kind: "m365",
    events: 1,
    prefix: "Entra sign-in: [non-interactive] user1@",
    severity: "Medium",
  },
  {
    file: "log-analytics/AuditLogs.json",
    kind: "m365",
    events: 1,
    prefix: "Entra audit: Add member to role by admin@",
    severity: "Medium",
  },
  {
    file: "log-analytics/AuditLogs.csv",
    kind: "m365",
    events: 1,
    prefix: "Entra audit: Add member to role by admin@",
    severity: "Medium",
  },
  {
    file: "log-analytics/OfficeActivity.csv",
    kind: "m365",
    events: 1,
    prefix: "M365 audit: New-InboxRule by user1@",
    severity: "High",
  },
  {
    file: "mes-4.1.0/mailboxAuditLog-user1@example.com.csv",
    kind: "m365",
    events: 3,
    prefix: "M365 Exchange: HardDelete by user1@",
    severity: "Low",
  },
  {
    file: "log-analytics/AzureActivity.csv",
    kind: "cloud",
    events: 1,
    prefix: "Azure Run Command on Virtual Machine by admin@",
    severity: "Low",
  },
  {
    file: "aws-cloudtrail/event_history.csv",
    kind: "aws",
    events: 3,
    prefix: "AWS StopLogging (cloudtrail) by user1",
    severity: "High",
  },
];

describe("cloud exports through the import spine (#2302)", () => {
  it.each(CASES.map((c) => [c.file, c] as const))("%s", async (_f, c) => {
    const name = c.file.slice(c.file.lastIndexOf("/") + 1);
    const { kind, state } = await importFile(name, fixture(c.file));
    expect(kind).toBe(c.kind);
    // Every cloud import also adds the case-level coverage-gap row; the file's own events are the rest.
    const own = state.forensicTimeline.filter((e) => !e.description.startsWith("Cloud coverage gap"));
    expect(own).toHaveLength(c.events);
    const hit = state.forensicTimeline.find((e) => e.description.startsWith(c.prefix));
    expect(hit, state.forensicTimeline.map((e) => e.description).join("\n")).toBeDefined();
    expect(hit?.severity).toBe(c.severity);
    expect(hit?.timestamp).toMatch(/^2026-11-01T/);
  });

  it("the import note discloses the repairs made to read a `][` file", async () => {
    const file = "dfir-o365rc-2.0/UnifiedAuditLog_example.com_2026-11-01_11-00-00.json";
    const { kind, state } = await importFile("UnifiedAuditLog.json", `\uFEFF${fixture(file)}`);
    expect(kind).toBe("m365");
    const note = state.timeline.map((t) => t.description).find((d) => d.startsWith("Microsoft 365 import"));
    expect(note).toContain(
      "file repaired on read: a UTF-8 byte-order mark removed, 1 join(s) between concatenated JSON documents",
    );
  });

  it("an AzureActivity CSV maps exactly as its JSON export does", async () => {
    const view = (t: string) =>
      parseCloudActivity(t, { aggregate: false }).events.map((e) => [e.timestamp, e.severity, e.description]);
    expect(view(fixture("log-analytics/AzureActivity.csv"))).toEqual(
      view(fixture("log-analytics/AzureActivity.json")),
    );
  });

  it("a file that needed no repair says nothing about repairs", async () => {
    const { state } = await importFile("SigninLogs.json", fixture("log-analytics/SigninLogs.json"));
    expect(state.timeline.map((t) => t.description).join("\n")).not.toContain("repaired");
  });
});

// Codex review of #2302 (high): a document recovered by the repair path must be unwrapped by the
// same container rules a clean document gets, or a single garbage line loses every event in it.
describe("wrapped documents read on the repair path keep their events (#2302)", () => {
  const trail = (name: string, id: string) => ({
    eventVersion: "1.08",
    eventTime: "2026-11-01T10:02:00Z",
    eventSource: "cloudtrail.amazonaws.com",
    eventName: name,
    awsRegion: "us-east-1",
    sourceIPAddress: "203.0.113.50",
    eventID: id,
    userIdentity: { type: "IAMUser", userName: "user1", arn: "arn:aws:iam::123456789012:user/user1" },
  });
  const azure = (op: string, id: string) => ({
    operationName: { value: op, localizedValue: op },
    caller: "admin@example.com",
    callerIpAddress: "203.0.113.30",
    resourceId: "/subscriptions/00000000-0000-4000-8000-000000000700/resourceGroups/rg1",
    correlationId: id,
    eventTimestamp: "2026-11-01T12:00:00Z",
    status: { value: "Succeeded" },
  });
  const pretty = (v: unknown): string => JSON.stringify(v, null, 2);
  const view = (events: Array<{ severity: string; description: string }>) =>
    events
      .filter((e) => !e.description.startsWith("Cloud coverage gap"))
      .map((e) => [e.severity, e.description]);

  it("CloudTrail { Records: [...] } with a trailing garbage line keeps its StopLogging event", async () => {
    const clean = pretty({ Records: [trail("StopLogging", "00000000-0000-4000-8000-000000002001")] });
    const want = view(parseCloudTrail(clean, { aggregate: false }).events);
    expect(want.some(([, d]) => d.includes("StopLogging"))).toBe(true);
    const broken = `${clean}\n-- download interrupted --`;
    expect(view(parseCloudTrail(broken, { aggregate: false }).events)).toEqual(want);
    const { kind, state } = await importFile("trail.json", broken);
    expect(kind).toBe("aws");
    expect(state.forensicTimeline.some((e) => e.description.includes("StopLogging"))).toBe(true);
    const note = state.timeline.map((t) => t.description).find((d) => d.startsWith("AWS CloudTrail import"));
    expect(note).toContain("1 unreadable stretch(es) of text skipped");
    expect(note).toContain("records in them were not imported");
  });

  it("Azure REST { value: [...] } with trailing garbage keeps its events", async () => {
    const clean = pretty({ value: [azure("Microsoft.Compute/virtualMachines/runCommand/action", "c1")] });
    const want = view(parseCloudActivity(clean, { aggregate: false }).events);
    expect(want.length).toBeGreaterThan(0);
    const broken = `${clean}\ngarbage`;
    expect(view(parseCloudActivity(broken, { aggregate: false }).events)).toEqual(want);
    const { kind, state } = await importFile("activity.json", broken);
    expect(kind).toBe("cloud");
    expect(view(state.forensicTimeline)).toHaveLength(want.length);
  });

  it("two concatenated wrapped documents yield every event of both", () => {
    const a = pretty({ Records: [trail("StopLogging", "00000000-0000-4000-8000-000000002002")] });
    const b = pretty({ Records: [trail("DeleteTrail", "00000000-0000-4000-8000-000000002003")] });
    const parsed = parseCloudTrail(`${a}\n${b}`, { aggregate: false });
    expect(parsed.total).toBe(2);
    expect(parsed.repairs?.documentsJoined).toBe(1);
    const names = parsed.events.map((e) => e.description);
    expect(names.some((d) => d.includes("StopLogging"))).toBe(true);
    expect(names.some((d) => d.includes("DeleteTrail"))).toBe(true);
    const azureBoth = parseCloudActivity(
      `${pretty({ value: [azure("Microsoft.Compute/virtualMachines/write", "c2")] })}${pretty({
        value: [azure("Microsoft.Compute/virtualMachines/delete", "c3")],
      })}`,
    );
    expect(azureBoth.total).toBe(2);
  });
});

// Codex review of #2302 (medium): the MES mailbox audit date order is decided per FILE, never by
// AM/PM, and every row left without a time is counted in the import note.
describe("mailbox audit date order is decided per file (#2302)", () => {
  const HEADER = '"Operation","LogonType","MailboxOwnerUPN","ClientIPAddress","LastAccessed"';
  const csv = (...times: string[]): string =>
    [HEADER, ...times.map((t) => `"HardDelete","Owner","user1@example.com","203.0.113.10","${t}"`)].join(
      "\n",
    );
  const times = (text: string) => parseM365Audit(text, { aggregate: false }).events.map((e) => e.timestamp);

  it("a day-first file with a 12-hour clock reads every row day-first", () => {
    // 13/1 fixes the order; 1/2 1:05 PM is then 1 February, not 2 January.
    expect(times(csv("13/1/2026 9:00:00 AM", "1/2/2026 1:05:00 PM"))).toEqual([
      "2026-01-13T09:00:00Z",
      "2026-02-01T13:05:00Z",
    ]);
  });

  it("a month-first file with a 12-hour clock reads every row month-first", () => {
    expect(times(csv("1/13/2026 9:00:00 AM", "1/2/2026 1:05:00 PM"))).toEqual([
      "2026-01-02T13:05:00Z",
      "2026-01-13T09:00:00Z",
    ]);
  });

  it("an all-ambiguous file leaves every time unread and says so in the import note", async () => {
    const text = csv("1/2/2026 1:05:00 PM", "3/4/2026 10:00:00 AM");
    expect(times(text)).toEqual(["", ""]);
    const { state } = await importFile("mailboxAuditLog-user1@example.com.csv", text);
    const note = state.timeline.map((t) => t.description).find((d) => d.startsWith("Microsoft 365 import"));
    expect(note).toContain("2 audit row(s) have no time: the file's day/month order could not be determined");
  });

  it("a file mixing both orders reads only the unambiguous rows and discloses the rest", () => {
    const text = csv("13/1/2026 9:00:00 AM", "1/13/2026 9:00:00 AM", "1/2/2026 1:05:00 PM");
    const parsed = parseM365Audit(text, { aggregate: false });
    expect(parsed.events.map((e) => e.timestamp).sort()).toEqual([
      "",
      "2026-01-13T09:00:00Z",
      "2026-01-13T09:00:00Z",
    ]);
    expect(parsed.undatedRows).toEqual({ rows: 1, mixedOrders: true });
  });
});

describe("single-line wrapped documents on the JSON-lines path (#2302)", () => {
  const rec = (name: string, id: string) => ({
    eventTime: "2026-11-01T10:02:00Z",
    eventSource: "cloudtrail.amazonaws.com",
    eventName: name,
    eventID: id,
    sourceIPAddress: "203.0.113.50",
    userIdentity: { type: "IAMUser", userName: "user1" },
  });
  const line = (name: string, id: string) => JSON.stringify({ Records: [rec(name, id)] });

  it("a compact CloudTrail object followed by a garbage line keeps its event", () => {
    const parsed = parseCloudTrail(`${line("StopLogging", "e1")}\ngarbage`, { aggregate: false });
    expect(parsed.events.some((e) => e.description.includes("StopLogging"))).toBe(true);
    expect(parsed.repairs?.garbageSkipped).toBe(1);
  });

  it("two compact CloudTrail objects run together yield both events", () => {
    const parsed = parseCloudTrail(`${line("StopLogging", "e2")}\n${line("DeleteTrail", "e3")}`);
    expect(parsed.total).toBe(2);
    expect(parsed.repairs?.documentsJoined).toBe(1);
  });

  it("plain JSON lines are read unchanged, with no repair", () => {
    const parsed = parseCloudTrail(
      `${JSON.stringify(rec("StopLogging", "e4"))}\n${JSON.stringify(rec("DeleteTrail", "e5"))}`,
    );
    expect(parsed.total).toBe(2);
    expect(parsed.repairs).toEqual({ bomStripped: 0, documentsJoined: 0, garbageSkipped: 0 });
  });
});
