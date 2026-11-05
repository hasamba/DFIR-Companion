import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { streamsCloudImport } from "../../src/routes/importCloudStream.js";
import { CLOUD_STREAM_MIN_BYTES } from "../../src/analysis/cloudStreamLimits.js";

// #2303 — Import-from-path reads a CloudTrail object as downloaded (.json.gz): sniffed from its
// decompressed head, streamed, and its disclosure lands on the "last import" record. A gzip file of
// a kind that does not stream is refused with a sentence, not read as text.

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-gz-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = new StateStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, root, importMetaStore, stateStore };
}

const record = (i: number, eventName: string) => ({
  eventVersion: "1.09",
  userIdentity: {
    type: "IAMUser",
    arn: `arn:aws:iam::123456789012:user/ops${i}`,
    accountId: "123456789012",
    userName: `ops${i}`,
  },
  eventTime: "2026-10-01T10:00:00Z",
  eventSource: eventName === "StopLogging" ? "cloudtrail.amazonaws.com" : "iam.amazonaws.com",
  eventName,
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  eventID: `00000000-0000-4000-b000-${String(i).padStart(12, "0")}`,
  eventType: "AwsApiCall",
});

async function waitFor<T>(fn: () => Promise<T | null | undefined>, ms = 8000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > until) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 50));
  }
}

describe("POST /cases/:id/import-file — gzip cloud exports (#2303)", () => {
  it("imports a CloudTrail .json.gz as downloaded and records its disclosure", async () => {
    const { app, root, importMetaStore, stateStore } = await makeApp();
    const path = join(root, "123456789012_CloudTrail_us-east-1_20261001T1000Z_EXAMPLE.json.gz");
    await writeFile(
      path,
      gzipSync(JSON.stringify({ Records: [record(1, "StopLogging"), record(2, "ListUsers")] })),
    );
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({ kind: "aws" });
    const meta = await waitFor(async () => {
      const m = await importMetaStore.load("c1");
      return m.lastImportKind === "aws" ? m : null;
    });
    expect(meta.streamDisclosure?.join(" ")).toContain("gzip, decompressed on read");
    expect(meta.linesIn).toBe(2);
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.some((e) => /StopLogging/.test(e.description))).toBe(true);
  });

  it("refuses a gzip file of a kind that does not stream, with a sentence", async () => {
    const { app, root } = await makeApp();
    const path = join(root, "auth.log.gz");
    await writeFile(
      path,
      gzipSync(
        "Oct  1 10:00:00 host sshd[1]: Accepted password for root from 192.0.2.1 port 22\n".repeat(50),
      ),
    );
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status).toBe(415);
    expect(res.body.error).toMatch(/gzip uploads are read only for cloud audit exports/);
  });

  it("streams a cloud upload when it is gzip or at least the size threshold, and nothing else", () => {
    expect(streamsCloudImport("aws", 10, true)).toBe(true);
    expect(streamsCloudImport("m365", CLOUD_STREAM_MIN_BYTES, false)).toBe(true);
    expect(streamsCloudImport("m365", CLOUD_STREAM_MIN_BYTES - 1, false)).toBe(false);
    expect(streamsCloudImport("cloud", CLOUD_STREAM_MIN_BYTES, false)).toBe(true);
    expect(streamsCloudImport("siem", CLOUD_STREAM_MIN_BYTES * 2, true)).toBe(false);
  });
});
