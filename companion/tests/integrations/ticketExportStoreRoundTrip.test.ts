// Regression guard for the Jira / ServiceNow export stores (#272).
//
// The push orchestrators hand the store a *refs map*, not the loaded envelope. Spreading the
// envelope instead wrote `issueRefs` / `lastExportedAt` into the map as bogus sibling entries —
// and because the schema's `.catch({})` wraps the WHOLE record, the next load then failed
// validation and silently reset every remembered ref to `{}`, so re-push could never find the
// ticket it had already opened. The mocked-store unit tests can't see that; these round-trip
// through the real store on disk.

import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JiraExportStore } from "../../src/integrations/jira/jiraExportStore.js";
import { ServiceNowExportStore } from "../../src/integrations/servicenow/servicenowExportStore.js";
import { pushFindingToJira } from "../../src/integrations/jira/jiraPush.js";
import { pushFindingToServiceNow } from "../../src/integrations/servicenow/servicenowPush.js";
import type { JiraClientLike } from "../../src/integrations/jira/jiraClient.js";
import type { ServiceNowClientLike } from "../../src/integrations/servicenow/servicenowClient.js";
import type { Finding } from "../../src/analysis/stateTypes.js";

const finding = {
  id: "finding-1",
  title: "Suspicious PowerShell download cradle",
  description: "Encoded PowerShell payload downloaded from 192.0.2.5.",
  severity: "High",
  confidence: 82,
  relatedIocs: ["ioc-1"],
  relatedEventIds: ["evt-1"],
  sourceScreenshots: [],
  mitreTechniques: ["T1059.001"],
  firstSeen: "2026-07-24T10:00:00Z",
} as unknown as Finding;

async function seedCase(): Promise<CaseStore> {
  const root = await mkdtemp(join(tmpdir(), "dfir-ticket-store-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "Ransomware FS01", investigator: "i", aiProvider: null });
  return cases;
}

describe("JiraExportStore round-trip", () => {
  it("persists only finding-keyed refs, and reloads them intact", async () => {
    const cases = await seedCase();
    const store = new JiraExportStore(cases);
    let creates = 0;
    const client: JiraClientLike = {
      me: async () => ({ id: "u1" }),
      createIssue: async () => {
        creates += 1;
        return { id: "issue-100", key: "IR-42", url: "https://jira.example.com/browse/IR-42" };
      },
      updateIssue: async (idOrKey) => ({ id: "", key: idOrKey, url: undefined }),
    };

    await pushFindingToJira(client, store, { caseId: "c1", projectKey: "IR", finding });

    const onDisk = JSON.parse(await readFile(join(cases.stateDir("c1"), "jira-export.json"), "utf8"));
    expect(Object.keys(onDisk.issueRefs)).toEqual(["finding-1"]);
    expect(onDisk.lastExportedAt).not.toBe("");

    const reloaded = await store.load("c1");
    expect(reloaded.issueRefs["finding-1"]).toEqual({
      id: "issue-100",
      key: "IR-42",
      url: "https://jira.example.com/browse/IR-42",
    });

    // The remembered ref must survive the reload well enough to route the re-push to an update.
    const again = await pushFindingToJira(client, store, { caseId: "c1", projectKey: "IR", finding });
    expect(again.updated).toBe(true);
    expect(creates).toBe(1);
  });

  it("keeps refs for other findings when a second one is pushed", async () => {
    const cases = await seedCase();
    const store = new JiraExportStore(cases);
    const client: JiraClientLike = {
      me: async () => ({ id: "u1" }),
      createIssue: async (body) => ({ id: `id-${body.summary.length}`, key: `IR-${body.summary.length}` }),
      updateIssue: async (idOrKey) => ({ id: "", key: idOrKey, url: undefined }),
    };

    await pushFindingToJira(client, store, { caseId: "c1", projectKey: "IR", finding });
    await pushFindingToJira(client, store, {
      caseId: "c1",
      projectKey: "IR",
      finding: { ...finding, id: "finding-2", title: "Second" },
    });

    const reloaded = await store.load("c1");
    expect(Object.keys(reloaded.issueRefs).sort()).toEqual(["finding-1", "finding-2"]);
  });
});

describe("ServiceNowExportStore round-trip", () => {
  it("persists only finding-keyed refs, and reloads them intact", async () => {
    const cases = await seedCase();
    const store = new ServiceNowExportStore(cases);
    let creates = 0;
    const client: ServiceNowClientLike = {
      me: async () => ({ userId: "admin" }),
      createIncident: async () => {
        creates += 1;
        return {
          id: "sys-100",
          number: "INC0012345",
          url: "https://snow.example.com/incident.do?sys_id=sys-100",
        };
      },
      updateIncident: async (sysId) => ({
        id: sysId,
        number: "INC0012345",
        url: `https://snow.example.com/incident.do?sys_id=${sysId}`,
      }),
    };

    await pushFindingToServiceNow(client, store, { caseId: "c1", finding });

    const onDisk = JSON.parse(await readFile(join(cases.stateDir("c1"), "servicenow-export.json"), "utf8"));
    expect(Object.keys(onDisk.incidentRefs)).toEqual(["finding-1"]);

    const reloaded = await store.load("c1");
    expect(reloaded.incidentRefs["finding-1"].number).toBe("INC0012345");

    const again = await pushFindingToServiceNow(client, store, { caseId: "c1", finding });
    expect(again.updated).toBe(true);
    expect(creates).toBe(1);
  });
});
