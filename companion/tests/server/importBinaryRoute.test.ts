import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { MockProvider } from "../../src/providers/provider.js";
import { createApp } from "../../src/server.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";
import { EVIDENCE_IMPORT_ROUTES } from "../../src/routes/importCaseGuard.js";
import { MAX_INPUT_BYTES } from "../../src/analysis/bplistReader.js";

// #1301: the dashboard's manual upload reads every non-image file as TEXT, which corrupts a binary
// plist, and the only binary route (import-mac-login-item) takes a SERVER path behind a global-admin
// gate. POST /cases/:id/import-binary carries the caller's own bytes (base64 in JSON — the same
// envelope routes/tools.ts's run-upload uses) and dispatches on detectBinaryImportKind(), so it is
// an ordinary case-scoped write. Fixtures: tests/analysis/macLoginItemImport.test.ts's own.

const LEGACY_BTM_HEX =
  "62706c6973743030d4010203040506282b5924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572aa07080d101215171a1d2255246e756c6cd2090a0b0c5f100f6261636b67726f756e644974656d735776657273696f6e80021002d10e0f5d616c6c436f6e7461696e6572738003a1118004d113145d696e7465726e616c4974656d738005a1168006d1181958626f6f6b6d61726b8007d11b1c54646174618008d21e1f20215624636c617373574e532e6461746180094f110184626f6f6b84010000000004103000000000000000000000000000000000000000000000000000000000000000000000000401000010000000010600001c0000002c000000380000004c000000050000000101000055736572730000000300000001010000626f62000c000000010100004170706c69636174696f6e730d000000010100004c65676163794170702e61707000000010000000010600007c0000008800000094000000a000000004000000030300000200000004000000030300003200000004000000030300003c0000000400000003030000460000000c000000010100004d6163696e746f7368204844240000000101000041414141414141412d313131312d323232322d333333332d3434343434343434343434340d000000010100004c65676163794170702e61707000000034000000feffffff01000000000000000500000004100000040000000000000005100000640000000000000010200000ac0000000000000011200000c00000000000000017f00000ec00000000000000d2232425265824636c61737365735a24636c6173736e616d65a22627564e5344617461584e534f626a656374d1292a54726f6f74800112000186a000080011001b0024002900320044004f0055005a006c007400760078007b0089008b008d008f009200a000a200a400a600a900b200b400b700bc00be00c300ca00d200d4025c0261026a02750278027f0288028b029002920000000000000201000000000000002c00000000000000000000000000000297";
const LOGINITEMS_PLIST_HEX =
  "62706c6973743030d2010203185c53657373696f6e4974656d735f101353657373696f6e4974656d7356657273696f6ed104055f100f437573746f6d4c6973744974656d73a5060d101316d30708090a0b0c55416c6961735f1014437573746f6d4974656d50726f70657274696573544e616d654f110162000000000162000200000c4d6163696e746f7368204844000000000000000000000000000000d11c433f482b0000000004d20d4576696c4167656e742e61707000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000162ed3a51e730000000000000000ffffffff000000000000000000000000000000000000000c4170706c69636174696f6e73001000080000d11c433f0000001100080000d3a51e7300000001000c00000002000004d20000162e000200274d6163696e746f73682048443a4170706c69636174696f6e733a4576696c4167656e742e61707000000e001c000d004500760069006c004100670065006e0074002e006100700070000f001a000c004d006100630069006e0074006f007300680020004800440012001b2f4170706c69636174696f6e732f4576696c4167656e742e61707000001300012f00ffff0000d0594576696c4167656e74d207090e0f4f10ba616c697300ba000300010000d11c433f0000482b0000000000000063000010920000d3a51e730000000000000000000000000000000000000000001000080000d11c433f0000001100080000d3a51e7300000001000c000000020000006300001092000e00120008005000610079006c006f006100640073000f000a00040044006100740061001200132f55736572732f626f622f5061796c6f61647300001300142f53797374656d2f566f6c756d65732f44617461ffff0000585061796c6f616473d2070911124f110148626f6f6b4801000000000410300000000000000000000000000000000000000000000000000000000000000000000000c8000000080000000106000014000000280000000c000000010100004170706c69636174696f6e731100000001010000426f6f6b6d61726b65644170702e6170700000000800000001060000540000006000000004000000030300000200000004000000030300004d0000000c000000010100004d6163696e746f7368204844240000000101000043434343434343432d313131312d323232322d333333332d3434343434343434343434341100000001010000426f6f6b6d61726b65644170702e61707000000034000000feffffff010000000000000005000000041000000400000000000000051000004400000000000000102000006c0000000000000011200000800000000000000017f00000ac000000000000005a426f6f6b6d61726b6564d2070914154f101c0000000000c8000299999999999999999999999999999999999999995642726f6b656ed10917574e6f416c69617310010008000d001a003000330045004b00520058006f007401da01db01e501ea02a702b002b50401040c041104300437043a04420000000000000201000000000000001900000000000000000000000000000444";
const SFL2_HEX =
  "62706c6973743030d401020304050674775924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572af102907080f13171a1f2028292a2b2c2d2e2f30313e4228292a2b2c4546474828295556575e6465666b6c6d55246e756c6cd2090a0b0c5824636c61737365735a24636c6173736e616d65a30c0d0e5f10134e534d757461626c6544696374696f6e6172795c4e5344696374696f6e617279584e534f626a656374d2090a1011a311120e5e4e534d757461626c654172726179574e534172726179d2090a1415a315160e5d4e534d757461626c6544617461564e5344617461d2090a1819a2190e564e5344617465d21b1c1d1e5624636c617373574e532e74696d6580042341bdcd65000000005f1027636f6d2e6170706c652e4c5353686172656446696c654c6973742e446174654c6173745365656ed31b2122232426574e532e6b6579735a4e532e6f626a656374738001a1258006a1278005544e616d6554757569645a7669736962696c69747958426f6f6b6d61726b5f1014437573746f6d4974656d50726f70657274696573594576696c4167656e745f102441414141414141412d303030302d303030302d303030302d30303030303030303030303110004f110148626f6f6b4801000000000410300000000000000000000000000000000000000000000000000000000000000000000000c8000000080000000106000014000000280000000c000000010100004170706c69636174696f6e731100000001010000426f6f6b6d61726b65644170702e6170700000000800000001060000540000006000000004000000030300000200000004000000030300004d0000000c000000010100004d6163696e746f7368204844240000000101000043434343434343432d313131312d323232322d333333332d3434343434343434343434341100000001010000426f6f6b6d61726b65644170702e61707000000034000000feffffff010000000000000005000000041000000400000000000000051000004400000000000000102000006c0000000000000011200000800000000000000017f00000ac00000000000000d31b2122233238a5333435363780088009800a800b800ca5393a3b3c3d800d800e800f80108007d21b3f4041574e532e6461746180034f110140626f6f6b4001000000000410300000000000000000000000000000000000000000000000000000000000000000000000cc00000010000000010600001c0000002c0000003800000048000000050000000101000055736572730000000300000001010000626f620007000000010100004c696272617279000a0000000101000048656c7065722e6170700000100000000106000074000000800000008c000000980000000400000003030000020000000400000003030000030000000400000003030000040000000400000003030000050000000c000000010100004d6163696e746f73682048440a0000000101000048656c7065722e617070000028000000feffffff010000000000000004000000041000000400000000000000051000005c0000000000000010200000a40000000000000017f00000b800000000000000d31b2122234344a0a05648656c7065725f102441414141414141412d303030302d303030302d303030302d3030303030303030303030321001d31b212223494fa54a4b4c4d4e80148015801680178018a550515253548019801a801b801280135a4e6f426f6f6b6d61726b5f102441414141414141412d303030302d303030302d303030302d303030303030303030303033d31b212223585ba2595a801d801ea25c5d801f8020d21b225f608002a36162638011801c80215f1024636f6d2e6170706c652e4c5353686172656446696c654c6973742e4d6178416d6f756e74100ad31b2122236769a1688023a16a8024556974656d735a70726f70657274696573d31b2122236e71a26f7080268027a2727380228025d1757654726f6f74802812000186a000080011001b002400290032004400700076007b0084008f009300a900b600bf00c400c800d700df00e400e800f600fd01020105010c0111011801200122012b0155015c0164016f01710173017501770179017e0183018e019701ae01b801df01e1032d0334033a033c033e034003420344034a034c034e03500352035403590361036304a704ae04af04b004b704de04e004e704ed04ef04f104f304f504f704fd04ff0501050305050507051205390540054305450547054a054c054e055305550559055b055d055f05860588058f0591059305950597059d05a805af05b205b405b605b905bb05bd05c005c505c700000000000002010000000000000078000000000000000000000000000005cc";

const b64 = (hex: string): string => Buffer.from(hex, "hex").toString("base64");

function findingPipeline(stateStore: StateStore): AnalysisPipeline {
  return new AnalysisPipeline({
    provider: new MockProvider(
      "mock",
      JSON.stringify({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "n",
        summary: "s",
      }),
    ),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-binary-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const jobManager = new JobManager();
  const app = createApp(store, { pipeline: findingPipeline(stateStore), stateStore, jobManager });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  return { app, store, stateStore, jobManager };
}

async function waitForMacEvent(stateStore: StateStore, caseId: string, count: number): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const state = await stateStore.load(caseId);
    if (state.forensicTimeline.filter((e) => e.canonical?.macLoginItem).length >= count) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("mac login-item events did not land");
}

async function ledgerRows(
  store: CaseStore,
  caseId: string,
): Promise<Array<{ originalName: string; rows: number; filename: string }>> {
  const raw = await readFile(store.importsLogPath(caseId), "utf8").catch(() => "");
  return raw
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

describe("POST /cases/:id/import-binary — the browser's byte-native path (#1301)", () => {
  it("imports a BTM file from base64 bytes and lands the same events the path route would", async () => {
    const { app, store, stateStore } = await harness();
    const res = await request(app)
      .post("/cases/c1/import-binary")
      .send({ filename: "backgrounditems.btm", dataBase64: b64(LEGACY_BTM_HEX) });
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({
      accepted: true,
      events: 1,
      sourceFormat: "btm-legacy",
      kind: "macloginitem",
    });
    await waitForMacEvent(stateStore, "c1", 1);
    const rows = await ledgerRows(store, "c1");
    expect(rows).toHaveLength(1);
    expect(rows[0].originalName).toBe("backgrounditems.btm");
    expect(rows[0].rows).toBe(1);
  });

  it("imports the classic loginitems plist and the SessionLoginItems sfl2 through the same route", async () => {
    const { app, stateStore } = await harness();
    const r1 = await request(app)
      .post("/cases/c1/import-binary")
      .send({ filename: "com.apple.loginitems.plist", dataBase64: b64(LOGINITEMS_PLIST_HEX) });
    expect(r1.status).toBe(202);
    expect(r1.body.sourceFormat).toBe("loginitems-plist");
    expect(r1.body.events).toBe(5);
    const r2 = await request(app)
      .post("/cases/c1/import-binary")
      .send({ filename: "com.apple.LSSharedFileList.SessionLoginItems.sfl2", dataBase64: b64(SFL2_HEX) });
    expect(r2.status).toBe(202);
    expect(r2.body.sourceFormat).toBe("sfl2");
    await waitForMacEvent(stateStore, "c1", 8);
    const state = await stateStore.load("c1");
    const kinds = new Set(
      state.forensicTimeline.map((e) => e.canonical?.macLoginItem?.sourceFormat).filter(Boolean),
    );
    expect(kinds).toEqual(new Set(["loginitems-plist", "sfl2"]));
  });

  it("400s a matching name whose bytes are not a bplist — never coerced, never parsed as text", async () => {
    const { app, store } = await harness();
    const res = await request(app)
      .post("/cases/c1/import-binary")
      .send({
        filename: "com.apple.loginitems.plist",
        dataBase64: Buffer.from('<?xml version="1.0"?><plist/>').toString("base64"),
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/bplist00/);
    expect(await ledgerRows(store, "c1")).toHaveLength(0);
  });

  it("400s an unrelated filename and a non-login-item sfl2, even with real bplist bytes", async () => {
    const { app } = await harness();
    for (const filename of ["Spotlight.bplist", "com.apple.LSSharedFileList.RecentDocuments.sfl2"]) {
      const res = await request(app)
        .post("/cases/c1/import-binary")
        .send({ filename, dataBase64: b64(SFL2_HEX) });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/not a recognized/);
    }
  });

  it("rejects a filename with path separators or control bytes, and an invalid base64 body", async () => {
    const { app } = await harness();
    for (const filename of [
      "../../etc/backgrounditems.btm",
      "x\\backgrounditems.btm",
      "back\u0000grounditems.btm",
      "",
      "a".repeat(300),
    ]) {
      const res = await request(app)
        .post("/cases/c1/import-binary")
        .send({ filename, dataBase64: b64(LEGACY_BTM_HEX) });
      expect(res.status, filename).toBe(400);
      expect(res.body.error).toMatch(/filename/);
    }
    const bad = await request(app)
      .post("/cases/c1/import-binary")
      .send({ filename: "backgrounditems.btm", dataBase64: "not*base64!" });
    expect(bad.status).toBe(400);
    expect(bad.body.error).toMatch(/base64/);
    const missing = await request(app)
      .post("/cases/c1/import-binary")
      .send({ filename: "backgrounditems.btm" });
    expect(missing.status).toBe(400);
  });

  it("413s a body whose decoded size would exceed the parser's own bound, before decoding it", async () => {
    const { app } = await harness();
    // A base64 string long enough to decode past MAX_INPUT_BYTES, without allocating that much:
    // every 4 chars decode to 3 bytes, so (MAX/3*4)+8 chars is enough.
    const chars = Math.floor(MAX_INPUT_BYTES / 3) * 4 + 8;
    const res = await request(app)
      .post("/cases/c1/import-binary")
      .send({ filename: "backgrounditems.btm", dataBase64: "A".repeat(chars) });
    expect(res.status).toBe(413);
  }, 60_000);

  it("404s an unknown case and is listed in EVIDENCE_IMPORT_ROUTES", async () => {
    const { app } = await harness();
    expect(EVIDENCE_IMPORT_ROUTES).toContain("import-binary");
    const res = await request(app)
      .post("/cases/ghost/import-binary")
      .send({ filename: "backgrounditems.btm", dataBase64: b64(LEGACY_BTM_HEX) });
    expect(res.status).toBe(404);
  });

  it("the TEXT path refuses a login-item name with an actionable hint — an XML plutil export is never minted as a launchd job", async () => {
    const { app, store } = await harness();
    const xml =
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>SessionItems</key><dict><key>CustomListItems</key><array><dict><key>Name</key><string>EvilAgent</string></dict></array></dict></dict></plist>';
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "com.apple.loginitems.plist", text: xml });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/binary macOS login-item container/);
    expect(res.body.error).toMatch(/import-binary/);
    expect(await ledgerRows(store, "c1")).toHaveLength(0);
    // And a corrupt text-read of the real binary is refused the same way, not sniffed as something else.
    const asText = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "backgrounditems.btm", text: Buffer.from(LEGACY_BTM_HEX, "hex").toString("latin1") });
    expect(asText.status).toBe(400);
    expect(asText.body.error).toMatch(/binary macOS login-item container/);
  });

  it("is a case-scoped WRITE, not the global-admin gate the server-path route needs", () => {
    expect(resolveRequestPolicy("POST", "/cases/c1/import-binary")).toEqual({
      kind: "case",
      permission: "write",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/import-mac-login-item")).toEqual({
      kind: "global",
      permission: "admin",
    });
  });
});
