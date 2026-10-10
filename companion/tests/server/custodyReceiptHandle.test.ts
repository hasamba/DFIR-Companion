import { beforeEach, describe, expect, it, vi } from "vitest";
import { appendFile, mkdtemp, readdir, readFile, rename, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";

// #2111 review: the receipt middleware and the server-path handlers must work on ONE open of the
// file. Otherwise a file replaced between the two opens is receipted as old bytes and imported as
// new ones; a file that grows between hashing and copying imports bytes the receipt never covered.

const hooks = vi.hoisted(() => ({
  afterGuard: null as null | (() => Promise<void>),
  afterHash: null as null | (() => Promise<void>),
  guardCalls: 0,
}));

vi.mock("../../src/routes/serverPathGuard.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/routes/serverPathGuard.js")>();
  return {
    ...real,
    openImportPath: async (...args: Parameters<typeof real.openImportPath>) => {
      hooks.guardCalls++;
      const result = await real.openImportPath(...args);
      await hooks.afterGuard?.();
      return result;
    },
  };
});

vi.mock("../../src/analysis/custody.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/analysis/custody.js")>();
  return {
    ...real,
    hashHandleBoth: async (...args: Parameters<typeof real.hashHandleBoth>) => {
      const result = await real.hashHandleBoth(...args);
      await hooks.afterHash?.();
      return result;
    },
  };
});

const hunt = (msg: string): string =>
  JSON.stringify([
    {
      group: "Sigma",
      kind: "individual",
      document: {
        kind: "evtx",
        path: "Sysmon.evtx",
        data: {
          Event: {
            System: {
              Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
              EventID: 1,
              Channel: "Microsoft-Windows-Sysmon/Operational",
              Computer: "WIN-TEST01",
              TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
            },
            EventData: {
              UtcTime: "2023-01-02 10:00:00.000",
              Image: "C:\\Windows\\System32\\cmd.exe",
              CommandLine: msg,
            },
          },
        },
      },
      rule: { name: "Test Rule", level: "high", tags: ["attack.execution"] },
      timestamp: "2023-01-02T10:00:00.000Z",
    },
  ]);
const sha = (s: string | Buffer): string => createHash("sha256").update(s).digest("hex");

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-receipt-handle-")));
  const stateStore = new StateStore(store);
  const custody = new CustodyStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    custodyStore: custody,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, custody };
}

beforeEach(() => {
  hooks.afterGuard = null;
  hooks.afterHash = null;
  hooks.guardCalls = 0;
});

describe("receipt and handler share one open of the server file (#2111)", () => {
  it("import-file: a file swapped after the receipt's open imports the receipted bytes", async () => {
    const { app, store, custody } = await makeApp();
    const dir = await mkdtemp(join(tmpdir(), "dfir-receipt-swap-"));
    const src = join(dir, "hunt.json");
    const original = hunt("whoami original");
    await writeFile(src, original);
    hooks.afterGuard = async () => {
      hooks.afterGuard = null;
      await writeFile(join(dir, "other.tmp"), hunt("whoami REPLACED"));
      // Windows refuses to replace a file that is open (EPERM/EBUSY): the OS blocks the swap there,
      // which is the safe outcome. The assertions below hold either way.
      await rename(join(dir, "other.tmp"), src).catch(() => undefined);
    };
    const res = await request(app).post("/cases/c1/import-file").send({ path: src });
    expect(res.status).toBe(202);
    expect(hooks.guardCalls).toBe(1); // the handler reused the receipt's handle
    const stored = (await readdir(store.importsDir("c1")))[0];
    const storedBytes = await readFile(join(store.importsDir("c1"), stored));
    expect(sha(storedBytes)).toBe(sha(original));
    const received = (await custody.load("c1")).filter((r) => r.event === "received");
    expect(received.map((r) => r.sha256)).toContain(sha(storedBytes));
  });

  it("import-file: a file that grows between hash and copy is refused with 409 and not kept", async () => {
    const { app, store, custody } = await makeApp();
    const dir = await mkdtemp(join(tmpdir(), "dfir-receipt-grow-"));
    const src = join(dir, "hunt.json");
    await writeFile(src, hunt("whoami"));
    hooks.afterHash = async () => {
      hooks.afterHash = null;
      await appendFile(src, "\n// appended after the receipt hash\n");
    };
    const res = await request(app).post("/cases/c1/import-file").send({ path: src });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/file changed while it was being imported/);
    expect(await readdir(store.importsDir("c1")).catch(() => [])).toEqual([]);
    expect((await custody.load("c1")).filter((r) => r.event === "collected")).toEqual([]);
  });

  it("import-mac-login-item: opens the file once and refuses a file that grew after the receipt", async () => {
    const { app } = await makeApp();
    const dir = await mkdtemp(join(tmpdir(), "dfir-receipt-mac-"));
    const src = join(dir, "item.plist");
    await writeFile(src, "<plist>x</plist>");
    hooks.afterHash = async () => {
      hooks.afterHash = null;
      await appendFile(src, "<!-- grown -->");
    };
    const res = await request(app).post("/cases/c1/import-mac-login-item").send({ path: src });
    expect(hooks.guardCalls).toBe(1);
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/file changed while it was being imported/);
  });

  it("sharing the handle changes nothing the handler reads: import-file still reads from byte 0", async () => {
    const { app, store } = await makeApp();
    const dir = await mkdtemp(join(tmpdir(), "dfir-receipt-share-"));
    const src = join(dir, "hunt.json");
    const text = hunt("whoami shared");
    await writeFile(src, text);
    const res = await request(app).post("/cases/c1/import-file").send({ path: src });
    expect(res.status).toBe(202);
    const stored = (await readdir(store.importsDir("c1")))[0];
    expect((await readFile(join(store.importsDir("c1"), stored), "utf8")).replace(/\r\n/g, "\n")).toBe(
      text.replace(/\r\n/g, "\n"),
    );
  });
});
