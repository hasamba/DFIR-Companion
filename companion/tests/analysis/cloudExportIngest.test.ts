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
    prefix: "Entra sign-in: user1@",
    severity: "Medium",
  },
  {
    file: "log-analytics/SigninLogs.csv",
    kind: "m365",
    events: 2,
    prefix: "Entra sign-in: user1@",
    severity: "Medium",
  },
  {
    file: "log-analytics/AADNonInteractiveUserSignInLogs.json",
    kind: "m365",
    events: 1,
    prefix: "Entra sign-in: user1@",
    severity: "Medium",
  },
  {
    file: "log-analytics/AADNonInteractiveUserSignInLogs.csv",
    kind: "m365",
    events: 1,
    prefix: "Entra sign-in: user1@",
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
    events: 2,
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
