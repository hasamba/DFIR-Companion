// Caller names end to end through the pipeline's importers and the settle seam (#2490): an Entra
// service-principal sign-in graded Info teaches the case its name; the Azure activity row that names
// the principal by GUID shows " (<name>)" after the id — whichever upload came first — and loses it
// when another upload brings a second name.
import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { settleForensicImport } from "../../src/routes/importSettle.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";

const SP = "3f2a1b4c-1111-2222-3333-444455556666";
const APP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const AT = "2026-11-10T12:00:00.000Z";

async function pipeline(): Promise<{ p: AnalysisPipeline; stateStore: StateStore }> {
  const root = await mkdtemp(join(tmpdir(), "dfir-principal-names-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(caseStore);
  const p = new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    cloudRecordStore: new CloudRecordStore(caseStore), // records dedup across uploads (#2301)
  });
  return { p, stateStore };
}

// A role assignment by the service principal: High, so it stays in the forensic timeline.
const ACTIVITY = JSON.stringify({
  records: [
    {
      operationName: { value: "Microsoft.Authorization/roleAssignments/write" },
      caller: SP,
      eventTimestamp: "2026-01-01T00:02:00Z",
      status: { value: "Succeeded" },
      resourceId: "/subscriptions/x/providers/Microsoft.Authorization/roleAssignments/ra1",
    },
  ],
});

// A service-principal sign-in with no status code: outcome unknown, graded Info.
const signIn = (name: string, id = "s1") =>
  JSON.stringify([
    {
      id,
      createdDateTime: "2026-01-01T00:00:00Z",
      servicePrincipalId: SP,
      servicePrincipalName: name,
      appId: APP,
      resourceDisplayName: "Microsoft Graph",
      ipAddress: "",
      status: {},
    },
  ]);

const settle = (stateStore: StateStore, before: InvestigationState) =>
  settleForensicImport(
    {
      stateStore,
      autoTagImported: async () => {},
      demoteForensicForCase: async (caseId) => stateStore.load(caseId),
    },
    "c1",
    before,
  );

const azureRow = (s: InvestigationState) =>
  s.forensicTimeline.find((e) =>
    e.description.startsWith("Azure Microsoft.Authorization/roleAssignments/write"),
  );

describe("caller names learned at import (#2490)", () => {
  it("an Info sign-in imported AFTER the activity names the row at its settle", async () => {
    const { p, stateStore } = await pipeline();
    const first = await p.importCloudActivity("c1", ACTIVITY, {
      label: "activity.json",
      idPrefix: "a",
      importedAt: AT,
    });
    expect(azureRow(first)?.description).toContain(`by ${SP}`);
    expect(azureRow(first)?.description).not.toContain("(backup-automation)");

    const before = await stateStore.load("c1");
    const taught = await p.importM365("c1", signIn("backup-automation"), {
      label: "signins.json",
      idPrefix: "m",
      importedAt: AT,
    });
    expect(taught.principalNames).toEqual([
      { id: SP, names: ["backup-automation"] },
      { id: APP, names: ["backup-automation"] },
    ]);
    const settled = await settle(stateStore, before);
    expect(settled.principalNamesChanged).toBe(true);
    const row = azureRow(await stateStore.load("c1"));
    expect(row?.description).toContain(`by ${SP} (backup-automation)`);
    expect(row?.canonical?.actor?.name ?? SP).toBe(SP); // the envelope keeps the raw caller
  });

  it("an activity upload imported AFTER the sign-in is named at its own settle", async () => {
    const { p, stateStore } = await pipeline();
    await p.importM365("c1", signIn("backup-automation"), {
      label: "signins.json",
      idPrefix: "m",
      importedAt: AT,
    });
    const before = await stateStore.load("c1");
    await p.importCloudActivity("c1", ACTIVITY, { label: "activity.json", idPrefix: "a", importedAt: AT });
    const settled = await settle(stateStore, before);
    expect(settled.principalNamesChanged).toBeUndefined();
    expect(azureRow(await stateStore.load("c1"))?.description).toContain(`by ${SP} (backup-automation)`);
  });

  it("a second, different name removes the suffix", async () => {
    const { p, stateStore } = await pipeline();
    await p.importM365("c1", signIn("backup-automation"), {
      label: "signins.json",
      idPrefix: "m",
      importedAt: AT,
    });
    let before = await stateStore.load("c1");
    await p.importCloudActivity("c1", ACTIVITY, { label: "activity.json", idPrefix: "a", importedAt: AT });
    await settle(stateStore, before);
    before = await stateStore.load("c1");
    await p.importM365("c1", signIn("other-app", "s2"), {
      label: "signins2.json",
      idPrefix: "n",
      importedAt: AT,
    });
    await settle(stateStore, before);
    const after = await stateStore.load("c1");
    expect(after.principalNames?.find((r) => r.id === SP)?.names).toEqual(["backup-automation", "other-app"]);
    expect(azureRow(after)?.description).not.toContain("(backup-automation)");
    expect(azureRow(after)?.description).not.toContain("(other-app)");
    expect(azureRow(after)?.callerName).toBeUndefined();
  });

  it("a re-upload of sign-ins the case already holds still teaches their names (a case from before #2490)", async () => {
    const { p, stateStore } = await pipeline();
    await p.importM365("c1", signIn("backup-automation"), {
      label: "signins.json",
      idPrefix: "m",
      importedAt: AT,
    });
    // The case as it was before this feature: the records are in its ledger, no names are.
    const { principalNames: _gone, ...old } = await stateStore.load("c1");
    await stateStore.save(old);
    const again = await p.importM365("c1", signIn("backup-automation"), {
      label: "signins-again.json",
      idPrefix: "n",
      importedAt: AT,
    });
    expect(again.timeline.at(-1)?.description).toMatch(/0 event\(s\) from 1 record/);
    expect(again.principalNames?.find((r) => r.id === SP)?.names).toEqual(["backup-automation"]);
  });
});

describe("caller names from a streamed M365 import (#2490)", () => {
  it("every batch's names reach the case, Info sign-ins included", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-principal-stream-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const pipeline = new AnalysisPipeline({
      stateStore: new StateStore(cases),
      cloudRecordStore: new CloudRecordStore(cases),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const path = join(root, "signins.json");
    const other = "cccccccc-1111-2222-3333-444455556666";
    const records = [
      ...JSON.parse(signIn("backup-automation")),
      { ...JSON.parse(signIn("deployer", "s9"))[0], servicePrincipalId: other, appId: "" },
    ];
    await writeFile(path, JSON.stringify(records));
    const { state } = await pipeline.importCloudFile("c1", "m365", path, {
      label: "signins.json",
      idPrefix: "m",
      importedAt: AT,
      batchRecords: 1, // one record per batch: the names must accumulate across batches
    });
    expect(state.principalNames).toEqual([
      { id: SP, names: ["backup-automation"] },
      { id: APP, names: ["backup-automation"] },
      { id: other, names: ["deployer"] },
    ]);
  });
});

describe("caller names on promotion (#2490)", () => {
  it("a raw super-timeline Azure row promoted into the forensic timeline is named at once", async () => {
    const { p, stateStore } = await pipeline();
    await p.importM365("c1", signIn("backup-automation"), {
      label: "signins.json",
      idPrefix: "m",
      importedAt: AT,
    });
    const raw = {
      id: "sup1",
      timestamp: "2026-01-01T00:03:00.000Z",
      description: `Azure Microsoft.Compute/virtualMachines/read by ${SP} on virtualMachines/vm1`,
      severity: "Info" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Azure Activity"],
    };
    await p.promoteSuperTimeline("c1", [raw], { importedAt: AT, intent: "manual" });
    const promoted = (await stateStore.load("c1")).forensicTimeline.find((e) => e.id === "sup1");
    expect(promoted?.description).toBe(
      `Azure Microsoft.Compute/virtualMachines/read by ${SP} (backup-automation) on virtualMachines/vm1`,
    );
    expect(promoted?.promotedAt).toBe(AT);
  });
});
