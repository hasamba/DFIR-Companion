import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { collectionsRoot } from "../../src/integrations/cloudCollect/collectStore.js";

// #2487 — after a cloud import, the collector's own calls in the case carry the dfir-collector tag
// and its note; the same identity outside the run, another session of the role and a write by the
// collector identity do not; no grade changes. Driven through the real import route (streamed).

const ACCOUNT = "123456789012";
const COLLECTION = "cc-20261001t100000-aaaaaaaa";
const ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/dfir-companion-read`;

function identity(session: string) {
  return {
    type: "AssumedRole",
    principalId: `AROAEXAMPLEROLEID:${session}`,
    arn: `arn:aws:sts::${ACCOUNT}:assumed-role/dfir-companion-read/${session}`,
    accountId: ACCOUNT,
    accessKeyId: "ASIAEXAMPLEKEY",
    sessionContext: {
      sessionIssuer: {
        type: "Role",
        principalId: "AROAEXAMPLEROLEID",
        arn: ROLE_ARN,
        accountId: ACCOUNT,
        userName: "dfir-companion-read",
      },
      attributes: { creationDate: "2026-10-01T09:59:00Z", mfaAuthenticated: "false" },
    },
  };
}

let n = 0;
function record(
  eventName: string,
  eventSource: string,
  eventTime: string,
  session = "dfir-companion-collect",
) {
  n++;
  return {
    eventVersion: "1.09",
    userIdentity: identity(session),
    eventTime,
    eventSource,
    eventName,
    awsRegion: "us-east-1",
    sourceIPAddress: "198.51.100.7",
    readOnly: !/^Create/.test(eventName),
    eventID: `00000000-0000-4000-b000-${String(n).padStart(12, "0")}`,
    eventType: "AwsApiCall",
  };
}

async function writeCollection(store: CaseStore) {
  const dir = join(collectionsRoot(store.caseDir("c1")), COLLECTION);
  await mkdir(join(dir, "pages"), { recursive: true });
  const header = {
    type: "header",
    version: 1,
    collectionId: COLLECTION,
    provider: "aws",
    accountId: "acct1",
    accountName: "lab",
    accountRef: ACCOUNT,
    caller: `arn:aws:sts::${ACCOUNT}:assumed-role/dfir-companion-read/dfir-companion-collect`,
    sources: ["cloudtrail-lookup"],
    window: { start: "2026-09-30T00:00:00Z", end: "2026-10-01T00:00:00Z" },
    filters: {},
    sdkVersions: {},
    companionVersion: "0.0.0-test",
    startedAt: "2026-10-01T10:00:00.000Z",
  };
  await writeFile(join(dir, "manifest.jsonl"), `${JSON.stringify(header)}\n`);
  await writeFile(
    join(dir, "checkpoint.json"),
    JSON.stringify({
      version: 1,
      collectionId: COLLECTION,
      caseId: "c1",
      accountId: "acct1",
      provider: "aws",
      sources: ["cloudtrail-lookup"],
      window: header.window,
      status: "complete",
      stage: "done",
      subWindows: [],
      imported: [],
      quarantined: [],
      missing: [],
      networkSpans: [{ from: header.startedAt, to: "2026-10-01T10:30:00.000Z" }],
      startedAt: header.startedAt,
      updatedAt: "2026-10-01T11:30:00.000Z",
    }),
  );
}

async function waitFor<T>(fn: () => Promise<T | null | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > until) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 50));
  }
}

describe("collector footprint tags on a cloud import (#2487)", () => {
  it("tags the collector's own reads inside the run, and nothing else", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-collector-footprint-"));
    const store = new CaseStore(join(root, "cases"));
    const stateStore = new StateStore(store);
    const importMetaStore = new ImportMetaStore(store);
    const superTimelineStore = new SuperTimelineStore(store);
    const tagsStore = new TagsStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore, importMetaStore, superTimelineStore, tagsStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await writeCollection(store);

    const records = [
      record("DescribeRegions", "ec2.amazonaws.com", "2026-10-01T10:05:00Z"), // collector, in the run
      record("LookupEvents", "cloudtrail.amazonaws.com", "2026-10-01T10:06:00Z"), // collector, in the run
      record("DescribeRegions", "ec2.amazonaws.com", "2026-10-01T14:00:00Z"), // same identity, no run
      record("CreateAccessKey", "iam.amazonaws.com", "2026-10-01T10:07:00Z"), // a write by it: stands out
      record("LookupEvents", "cloudtrail.amazonaws.com", "2026-10-01T10:08:00Z", "someone-else"), // other session
    ];
    const path = join(root, `${ACCOUNT}_CloudTrail_us-east-1_20261001T1000Z_EXAMPLE.json.gz`);
    await writeFile(path, gzipSync(JSON.stringify({ Records: records })));
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    await waitFor(async () => ((await importMetaStore.load("c1")).lastImportKind === "aws" ? true : null));

    const rows: Array<{ id: string; description: string; timestamp: string; severity: string }> = [];
    for await (const batch of superTimelineStore.eventBatches("c1")) rows.push(...batch);
    const tags = (await tagsStore.load("c1")).filter((t) => t.label === "dfir-collector");
    const tagged = rows.filter((r) => tags.some((t) => t.targetId === r.id));
    expect(
      tagged.map((r) => `${r.timestamp} ${/DescribeRegions|LookupEvents/.exec(r.description)?.[0]}`).sort(),
    ).toEqual(["2026-10-01T10:05:00Z DescribeRegions", "2026-10-01T10:06:00Z LookupEvents"]);
    for (const t of tags) expect(t.author).toBe(`tagger:dfir-collector:${COLLECTION}`);
    // No grade changes: the same file in a case with no collection grades every row the same.
    await request(app).post("/cases").send({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    const res2 = await request(app).post("/cases/c2/import-file").send({ path });
    expect(res2.status, JSON.stringify(res2.body)).toBe(202);
    await waitFor(async () => ((await importMetaStore.load("c2")).lastImportKind === "aws" ? true : null));
    const control: typeof rows = [];
    for await (const batch of superTimelineStore.eventBatches("c2")) control.push(...batch);
    const grades = (list: typeof rows) =>
      list.map((r) => `${r.timestamp}|${r.description}|${r.severity}`).sort();
    expect(grades(rows)).toEqual(grades(control));
    expect((await tagsStore.load("c2")).some((t) => t.label === "dfir-collector")).toBe(false);
    const write = rows.find((r) => /CreateAccessKey/.test(r.description));
    expect(write && tags.some((t) => t.targetId === write.id)).toBe(false);
  });
});
