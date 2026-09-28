import { describe, expect, it } from "vitest";
import { mkdtemp, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { pollFor } from "../helpers/poll.js";

// #1802: a binary sent to a text import was classified csv/log (and, with AI on, sent to the model
// as one). It is now refused at detection with a sentence the dashboard shows verbatim — on the
// DECODED text, so a UTF-16 Windows export with a BOM still imports.

const HAYABUSA =
  "Timestamp,Computer,Channel,EventID,Level,RuleTitle,Details\r\n" +
  "2026-05-02 10:00:00.000 +00:00,WS1,Sec,4624,info,Logon,User: bob\r\n" +
  "2026-05-02 10:01:00.000 +00:00,WS1,Sec,4688,low,Proc Exec,Cmd: whoami\r\n";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-binary-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, root };
}

async function storedImports(store: CaseStore): Promise<string[]> {
  return readdir(store.importsDir("c1")).catch(() => []);
}

async function waitForEvent(stateStore: StateStore, needle: string): Promise<string[]> {
  return pollFor(`a forensic event containing "${needle}"`, async () => {
    const s = await stateStore.load("c1");
    const hits = s.forensicTimeline.map((e) => e.description).filter((d) => d.includes(needle));
    return hits.length ? hits : undefined;
  });
}

function peHeader(): Buffer {
  const b = Buffer.alloc(2048);
  b.write("MZ", 0, "latin1");
  b[2] = 0x90;
  b[4] = 0x03;
  b.write("This program cannot be run in DOS mode.", 0x4e, "latin1");
  return b;
}

describe("binary files are refused by the text imports (#1802)", () => {
  it("/import refuses a PE read as text, with a sentence, and stores nothing", async () => {
    const { app, store } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "payload.exe", text: peHeader().toString("utf8") });
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.refused).toBe(true);
    expect(res.body.error).toMatch(/"payload\.exe" is a binary file/);
    expect(await storedImports(store)).toEqual([]);
  });

  it("/import-file refuses random bytes and stores nothing", async () => {
    const { app, store, root } = await makeApp();
    const bytes = Buffer.alloc(8192);
    let x = 7;
    for (let i = 0; i < bytes.length; i++) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      bytes[i] = x & 0xff;
    }
    const path = join(root, "corrupt.bin");
    await writeFile(path, bytes);
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.refused).toBe(true);
    expect(await storedImports(store)).toEqual([]);
  });

  it.each([
    ["UTF-16LE", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(HAYABUSA, "utf16le")])],
    ["UTF-16BE", Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(HAYABUSA, "utf16le").swap16()])],
  ])("/import-file imports a %s CSV with a BOM and parses it cleanly", async (_label, bytes) => {
    const { app, store, stateStore, root } = await makeApp();
    const path = join(root, "hayabusa.csv");
    await writeFile(path, bytes);
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("hayabusa");
    expect(await storedImports(store)).toHaveLength(1);
    // The full-file read honours the BOM too: no NUL-interleaved mojibake reaches the parser.
    const hits = await waitForEvent(stateStore, "whoami");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.join("")).not.toContain("\0");
  });

  it("/import still accepts a UTF-16 export the browser already decoded", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "hayabusa.csv", text: HAYABUSA });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("hayabusa");
  });
});

// #1795: event-shaped JSON no importer recognises falls to the SIEM importer's auto-detection and
// lands at the generic Low severity. The answer now says the kind was a guess.
describe("an unrecognised JSON import carries a warning (#1795)", () => {
  it("/import of arbitrary JSON answers kind siem with a warning", async () => {
    const { app } = await makeApp();
    const text = JSON.stringify({ name: "dfir-companion", version: "1.0.0", private: true });
    const res = await request(app).post("/cases/c1/import").send({ filename: "package.json", text });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("siem");
    expect(res.body.warning).toMatch(/unrecognised JSON — imported as generic SIEM/);
  });

  it("/import-file of arbitrary JSON carries the same warning", async () => {
    const { app, root } = await makeApp();
    const path = join(root, "notes.json");
    await writeFile(path, JSON.stringify([{ title: "a", body: "b" }]));
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("siem");
    expect(res.body.warning).toBeDefined();
  });

  it("a real SIEM export is not flagged", async () => {
    const { app } = await makeApp();
    const text = JSON.stringify([
      { "@timestamp": "2026-05-20T09:00:00Z", "host.name": "WS1", "event.action": "logon", message: "ok" },
    ]);
    const res = await request(app).post("/cases/c1/import").send({ filename: "elastic.json", text });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.warning).toBeUndefined();
  });
});
