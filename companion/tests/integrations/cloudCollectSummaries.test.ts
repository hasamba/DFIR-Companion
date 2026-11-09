import { describe, it, expect } from "vitest";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import type { CloudCollectSession, CollectPage } from "../../src/integrations/cloudCollect/collectTypes.js";
import type { StreamKind } from "../../src/analysis/ingest/cloudStreamProviders.js";
import { faultFs, pipelineImporter, tempCase, type TempCase } from "../helpers/cloudCollectFakes.js";
import {
  PATH_APP,
  pathAction,
  pathCredential,
  pathGrant,
  pathSignIn,
  spraySignIn,
} from "../helpers/entraPathRecords.js";

// #2493 — a live Microsoft or GCP collection builds its whole-export summaries (Entra privilege
// paths, mailbox chains, password spray, GCP service-account joins, GCP / Azure compute lifecycles)
// ONCE over every page of the run, through #2482's collection summary step, not once per page.

type Row = Record<string, unknown>;
const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" };
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

/** A Graph-shaped session: each source serves its pages ({ value: [...] }) one after another. */
function graphSession(pagesBySource: Record<string, Row[][]>): CloudCollectSession {
  return {
    identity: async () => ({
      accountRef: "6f1b7a5e-5555-4eee-8fff-000000000006",
      caller: "collector@example.invalid",
      sdkVersions: { fake: "1.0.0" },
    }),
    fetchPage: async (req): Promise<CollectPage> => {
      const pages = pagesBySource[req.source] ?? [[]];
      const index = req.pageToken ? Number(req.pageToken.slice(1)) : 0;
      const records = pages[index];
      const next = index + 1 < pages.length ? `t${index + 1}` : undefined;
      return {
        body: Buffer.from(JSON.stringify({ value: records })),
        extension: "json",
        recordCount: records.length,
        ...(next ? { nextPageToken: next } : {}),
        requestId: `req-${req.source}-${index}`,
        requestParams: { page: String(index), source: req.source },
      };
    },
  };
}

async function collect(t: TempCase, pagesBySource: Record<string, Row[][]>, kind: StreamKind = "m365") {
  const ids = Object.keys(pagesBySource);
  const session = graphSession(pagesBySource);
  const fs = faultFs();
  await createCollection(
    fs,
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      accountName: "lab",
      provider: "microsoft",
      sources: ids,
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
  const importer = pipelineImporter(t);
  const sources = ids.map((id) => ({ id, label: id, streamKind: kind }));
  const cp = await runCollection({ fs, session, importer, sources, now }, t.dir, { resume: false });
  return { cp, importer };
}

const forensic = async (t: TempCase, prefix: string) =>
  (await t.stateStore.load("c1")).forensicTimeline.filter((e) => e.description.startsWith(prefix));

describe("Entra privilege path over a live collection (#2493)", () => {
  it("audits and sign-ins saved as separate sources join into one four-stage path, graded High", async () => {
    const t = await tempCase();
    const { cp, importer } = await collect(t, {
      "entra-audits": [[pathCredential()], [pathGrant()], [pathAction()]],
      "entra-signins": [[pathSignIn()]],
    });
    expect(cp.status).toBe("complete");
    expect(importer.summaries).toEqual(["evidence/cloud/cc-test-abc123/summary-m365"]);
    expect(cp.summarized).toEqual({ m365: 4 });
    const rows = await forensic(t, "Entra privilege path:");
    expect(rows).toHaveLength(1);
    const [row] = rows;
    expect(row.severity).toBe("High");
    expect(row.description).toContain(`Sync (app id ${PATH_APP})`);
    expect(row.description).toContain(
      "signed in → Microsoft Graph (clientSecret k-new) — with the new credential",
    );
    expect(row.description).toContain("all four stages in order]");
    expect(row.description).not.toContain("log not in this");
    expect(row.sourceScreenshots).toEqual(["evidence/cloud/cc-test-abc123/summary-m365"]);
    expect(row.canonical?.entra?.basis).toMatch(/^records of this collection only \(4 pages;/);
  });
});

describe("password spray over a live collection (#2493)", () => {
  it("a spray split over two pages of one run is one within-collection row, not 'across N uploads'", async () => {
    const t = await tempCase();
    const first = ["alice", "bob", "carol"].map((a, i) => spraySignIn(`${a}@example.invalid`, i * 20));
    const second = ["dave", "erin", "frank"].map((a, i) => spraySignIn(`${a}@example.invalid`, (3 + i) * 20));
    await collect(t, { "entra-signins": [first, second] });
    const rows = (await t.stateStore.load("c1")).forensicTimeline.filter((e) =>
      e.mitreTechniques.includes("T1110.003"),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toMatch(/^Password-spray pattern \(low-and-slow\): /);
    expect(rows[0].description).not.toContain("uploads");
    expect(rows[0].description).toContain("6 distinct accounts");
    expect(rows[0].sourceScreenshots).toEqual(["evidence/cloud/cc-test-abc123/summary-m365"]);
  });
});

// Azure Activity records (the Microsoft collector's Azure Activity source uses the `cloud` kind).
const SUB = "11111111-1111-1111-1111-111111111111";
const VM_ID = `/subscriptions/${SUB}/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/web-1`;
const azure = (op: string, at: string, id: string): Row => ({
  operationName: { value: op },
  eventTimestamp: at,
  eventDataId: id,
  correlationId: id,
  caller: "alice@example.com",
  status: { value: "Succeeded" },
  resourceId: VM_ID,
});

describe("compute lifecycle over a live collection (#2493)", () => {
  it("a VM written on page 1 and deleted on page 3 is one lifecycle row that names both", async () => {
    const t = await tempCase();
    const write = async (name: string, recs: Row[], batch: string) => {
      const path = join(t.root, name);
      await writeFile(path, JSON.stringify(recs));
      return { path, records: recs.length, batch };
    };
    const pages = [
      await write(
        "p1.json",
        [azure("Microsoft.Compute/virtualMachines/write", "2024-05-01T09:00:00Z", "a1")],
        "b1",
      ),
      await write(
        "p2.json",
        [azure("Microsoft.Compute/virtualMachines/start/action", "2024-05-01T10:00:00Z", "a2")],
        "b2",
      ),
      await write(
        "p3.json",
        [azure("Microsoft.Compute/virtualMachines/delete", "2024-05-01T11:00:00Z", "a3")],
        "b3",
      ),
    ];
    const opts = {
      collectionId: "cc-x",
      label: "evidence/cloud/cc-x/summary-cloud",
      idPrefix: "ccxscloud",
      importedAt: "2024-05-02T00:00:00Z",
    };
    const r = await t.pipeline.importCloudCollectionSummary("c1", "cloud", pages, opts);
    const rows = r.state.forensicTimeline.filter((e) => e.description.startsWith("Azure compute lifecycle"));
    expect(rows).toHaveLength(1);
    expect(rows[0].description).not.toContain("not in this upload");
    expect(rows[0].description).not.toContain("not in this collection");
    expect(rows[0].description).toContain("virtualMachines/delete");
    expect(rows[0].canonical?.azureCompute?.basis).toMatch(/^records of this collection only \(3 pages;/);

    // A rebuild (Resume / replay) upserts the same row in place.
    const again = await t.pipeline.importCloudCollectionSummary("c1", "cloud", pages, opts);
    const after = again.state.forensicTimeline.filter((e) =>
      e.description.startsWith("Azure compute lifecycle"),
    );
    expect(after.map((e) => e.id)).toEqual(rows.map((e) => e.id));
  });

  it("the same record saved on two pages (a re-fetched window) is read once", async () => {
    const t = await tempCase();
    const rec = azure("Microsoft.Compute/virtualMachines/write", "2024-05-01T09:00:00Z", "a1");
    const path1 = join(t.root, "d1.json");
    const path2 = join(t.root, "d2.json");
    await writeFile(path1, JSON.stringify([rec]));
    await writeFile(path2, JSON.stringify([rec]));
    const r = await t.pipeline.importCloudCollectionSummary(
      "c1",
      "cloud",
      [
        { path: path1, records: 1, batch: "b1" },
        { path: path2, records: 1, batch: "b2" },
      ],
      {
        collectionId: "cc-y",
        label: "evidence/cloud/cc-y/summary-cloud",
        idPrefix: "ccysc",
        importedAt: "2024-05-02T00:00:00Z",
      },
    );
    const [row] = r.state.forensicTimeline.filter((e) => e.description.startsWith("Azure compute lifecycle"));
    expect(row.canonical?.azureCompute?.coverage.records).toBe(1);
  });
});
