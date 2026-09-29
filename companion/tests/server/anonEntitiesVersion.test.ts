import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { createApp } from "../../src/server.js";
import type { CustomEntity } from "../../src/analysis/anonymize.js";

// #1839: the custom-entity editor saves the WHOLE list. Before this, a stale second window could
// erase a value the analyst had just hidden in the first — and once the value was gone from the
// list, it went to the AI in clear. Every save now names the version it was loaded at; a stale base
// is refused with the current list and changes nothing.

let app: ReturnType<typeof createApp>;
let custom: CustomEntitiesStore;
let pending: PresidioPendingStore;
const JANE: CustomEntity = { value: "Jane Doe", category: "PERSON" };
const DC9: CustomEntity = { value: "DC9", category: "HOST" };

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-anonversion-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { stateStore: new StateStore(cases) });
  custom = new CustomEntitiesStore(cases);
  pending = new PresidioPendingStore(cases);
  await pending.save("c1", [JANE]);
});

/** One dashboard window: what it loaded, and its Save. */
async function openWindow() {
  const got = await request(app).get("/cases/c1/anon-entities");
  expect(got.status).toBe(200);
  return {
    custom: got.body.custom as { value: string; category: string }[],
    version: got.body.customVersion as number,
  };
}
const save = (entities: unknown, version: unknown) =>
  request(app).post("/cases/c1/anon-entities").send({ entities, version });
const hide = () => request(app).post("/cases/c1/presidio-pending/approve").send(JANE);
const values = async () => (await custom.load("c1")).map((e) => e.value);

describe("versioned custom-entity save (#1839)", () => {
  it("GET reports a version; a save from it applies and returns the next version", async () => {
    const w = await openWindow();
    expect(typeof w.version).toBe("number");
    const res = await save([DC9], w.version);
    expect(res.status).toBe(200);
    expect(res.body.custom).toEqual([DC9]);
    expect(res.body.customVersion).toBeGreaterThan(w.version);
    expect(await values()).toEqual(["DC9"]);
  });

  it("refuses a save with no version, and changes nothing", async () => {
    await hide();
    for (const version of [undefined, null, "0", 1.5]) {
      const res = await save([DC9], version);
      expect(res.status).toBe(409);
      expect(res.body.error).toBe("anon_entities_stale");
    }
    expect(await values()).toEqual(["Jane Doe"]);
  });

  it("order 1: window B loads, window A hides a value, B's stale save is refused and the value stays hidden", async () => {
    const b = await openWindow();
    expect((await hide()).status).toBe(200);
    const res = await save([...b.custom, DC9], b.version);
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("anon_entities_stale");
    // The answer carries what the dashboard needs to rebase: the current list and its version.
    expect(res.body.custom).toEqual([JANE]);
    expect(await values()).toEqual(["Jane Doe"]);
    // Saving again from the version the 409 handed back applies.
    const again = await save([JANE, DC9], res.body.customVersion);
    expect(again.status).toBe(200);
    expect(await values()).toEqual(["Jane Doe", "DC9"]);
  });

  it("order 2: B saves first, then A hides — A's Hide lands and a later stale save from A's editor is refused", async () => {
    const a = await openWindow();
    const b = await openWindow();
    expect((await save([DC9], b.version)).status).toBe(200);
    expect((await hide()).status).toBe(200);
    expect(await values()).toEqual(["DC9", "Jane Doe"]);
    const res = await save([], a.version);
    expect(res.status).toBe(409);
    expect(await values()).toEqual(["DC9", "Jane Doe"]);
  });

  it("two editor windows: the first save wins, the second is refused", async () => {
    const a = await openWindow();
    const b = await openWindow();
    expect((await save([DC9], a.version)).status).toBe(200);
    const res = await save([], b.version);
    expect(res.status).toBe(409);
    expect(await values()).toEqual(["DC9"]);
  });

  // A content hash would miss this one: the re-Hide leaves the list unchanged, but a window that
  // loaded it before the Hide may be about to remove the value.
  it("a Hide of a value already listed still makes an older editor window stale", async () => {
    await custom.save("c1", [JANE]);
    const b = await openWindow();
    expect((await hide()).status).toBe(200);
    const res = await save([], b.version); // B had removed Jane locally
    expect(res.status).toBe(409);
    expect(await values()).toEqual(["Jane Doe"]);
  });

  it("a Hide and a stale save fired together, in both orders, always end with the value hidden", async () => {
    for (const hideFirst of [true, false]) {
      await custom.save("c1", []);
      await pending.save("c1", [JANE]);
      const b = await openWindow();
      const reqs = hideFirst ? [hide(), save([DC9], b.version)] : [save([DC9], b.version), hide()];
      await Promise.all(reqs);
      expect(await values()).toContain("Jane Doe");
    }
  });
});

describe("versioned settings save (#1839)", () => {
  const control = () => request(app).get("/cases/c1/anon-control");
  const post = (body: object) => request(app).post("/cases/c1/anon-control").send(body);

  it("refuses a stale settings form, so it cannot turn masking off under another window", async () => {
    const b = (await control()).body;
    expect(typeof b.version).toBe("string");
    // Window A changes a category; window B still holds the old form and posts "anonymization off".
    expect((await post({ categories: { IP: false }, version: b.version })).status).toBe(200);
    const res = await post({ enabled: false, version: b.version });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("anon_control_stale");
    expect(res.body.control.enabled).toBe(true);
    expect(res.body.control.categories.IP).toBe(false);
    expect((await control()).body.enabled).toBe(true);
  });

  it("applies a save from the current version", async () => {
    const v = (await control()).body.version;
    const ok = await post({ enabled: false, version: v });
    expect(ok.status).toBe(200);
    expect(ok.body.version).not.toBe(v);
  });

  // The request an already-open dashboard from before this fix sends: the whole form, no version.
  it("refuses a save with no version — an old cached dashboard's whole-form post", async () => {
    const res = await post({ enabled: false, categories: { IP: true }, redactSecrets: true });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("anon_control_stale");
    expect((await control()).body.enabled).toBe(true);
  });
});
