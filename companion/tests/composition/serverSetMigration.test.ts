import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { seedServerSets, listCaseIdsSync } from "../../src/composition/serverSetMigration.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";

let dir: string;
let store: ServerSetStore;
const env = {
  DFIR_IRIS_URL: "https://iris.example.com",
  DFIR_IRIS_KEY: "iris-key-sentinel-alpha",
  DFIR_IRIS_INSECURE: "TRUE",
  DFIR_VELOCIRAPTOR_API_CONFIG: "/etc/velo/api.yaml",
};

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ss-mig-"));
  store = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 7)));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("seedServerSets", () => {
  it("first run creates Testing as default and links every case", () => {
    expect(seedServerSets(store, env, ["a", "b"])).toEqual({ seeded: true, linked: 2 });
    const sets = store.list();
    expect(sets).toHaveLength(1);
    expect(sets[0].name).toBe("Testing");
    expect(sets[0].iris?.url).toBe("https://iris.example.com");
    expect(sets[0].iris?.apiKey).toBe("iris-key-sentinel-alpha");
    expect(sets[0].iris?.insecure).toBe(true);
    expect(sets[0].velociraptor?.apiConfigPath).toBe("/etc/velo/api.yaml");
    expect(sets[0].timesketch).toBeUndefined();
    expect(store.defaultId()).toBe(sets[0].id);
    expect(store.caseSetId("a")).toBe(sets[0].id);
  });

  it("second run is a no-op", () => {
    seedServerSets(store, env, ["a"]);
    expect(seedServerSets(store, env, ["a"])).toEqual({ seeded: false, linked: 0 });
    expect(store.list()).toHaveLength(1);
  });

  it("unlinked case on later start is linked to default", () => {
    seedServerSets(store, env, ["a"]);
    expect(seedServerSets(store, env, ["a", "c"])).toEqual({ seeded: false, linked: 1 });
    expect(store.caseSetId("c")).toBe(store.defaultId());
  });

  it("empty env still creates an empty Testing set", () => {
    expect(seedServerSets(store, {}, ["a"])).toEqual({ seeded: true, linked: 1 });
    const [s] = store.list();
    expect(s.iris).toBeUndefined();
    expect(s.timesketch).toBeUndefined();
    expect(s.velociraptor).toBeUndefined();
  });

  it("keeps an incomplete tool as given", () => {
    seedServerSets(store, { DFIR_IRIS_URL: "https://iris.example.com" }, []);
    expect(store.list()[0].iris).toMatchObject({ url: "https://iris.example.com", apiKey: "" });
  });

  it("omits a tool the store rejects and still seeds", () => {
    const r = seedServerSets(store, { ...env, DFIR_IRIS_URL: "ftp://bad.example.com" }, ["a"]);
    expect(r.seeded).toBe(true);
    expect(store.list()[0].iris).toBeUndefined();
    expect(store.list()[0].velociraptor).toBeDefined();
  });

  it("never touches case folders", () => {
    const root = join(dir, "cases");
    mkdirSync(join(root, "a"), { recursive: true });
    writeFileSync(join(root, "a", "case.json"), "{}");
    const snap = () => readdirSync(root, { recursive: true }).sort();
    const before = snap();
    seedServerSets(store, env, listCaseIdsSync(root));
    expect(snap()).toEqual(before);
    expect(listCaseIdsSync(root)).toEqual(["a"]);
  });
});
