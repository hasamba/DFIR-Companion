import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServerClients } from "../../src/composition/serverSetClients.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import type { IrisSettings } from "../../src/integrations/serverSets/types.js";

let dir: string;
let store: ServerSetStore;
const NO_LINK = "This case has no server set. Choose one in the case header.";
const DANGLING = "This case's server set was deleted. Choose another in the case header.";

const iris = (key = "iris-key-sentinel-alpha"): IrisSettings => ({
  url: "https://iris.example.com",
  apiKey: key,
});

function fakes() {
  const irisB = vi.fn((s: IrisSettings) => ({ fake: "iris", s }) as never);
  const tsB = vi.fn(() => ({ fake: "ts" }) as never);
  const veloB = vi.fn(() => ({ fake: "velo" }) as never);
  return { irisB, tsB, veloB, builders: { iris: irisB, timesketch: tsB, velociraptor: veloB } };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ss-clients-"));
  store = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 7)));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("createServerClients", () => {
  it("forCase builds clients from the linked set", () => {
    const f = fakes();
    const set = store.create({ name: "Acme", iris: iris() });
    store.linkCase("c1", set.id);
    const r = createServerClients(store, {}, f.builders).forCase("c1");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.servers.setName).toBe("Acme");
    expect(r.servers.setId).toBe(set.id);
    expect(f.irisB).toHaveBeenCalledWith(
      expect.objectContaining({ url: "https://iris.example.com", apiKey: "iris-key-sentinel-alpha" }),
    );
    expect(r.servers.irisPush?.baseUrl).toBe("https://iris.example.com");
  });

  it("cache reuses the client for the same revision", () => {
    const f = fakes();
    const set = store.create({ name: "Acme", iris: iris() });
    store.linkCase("c1", set.id);
    const sc = createServerClients(store, {}, f.builders);
    sc.forCase("c1");
    sc.forCase("c1");
    expect(f.irisB).toHaveBeenCalledTimes(1);
  });

  it("revision bump rebuilds the client", () => {
    const f = fakes();
    const set = store.create({ name: "Acme", iris: iris() });
    store.linkCase("c1", set.id);
    const sc = createServerClients(store, {}, f.builders);
    sc.forCase("c1");
    store.update(set.id, { name: "Acme", iris: iris("iris-key-sentinel-beta") });
    sc.forCase("c1");
    expect(f.irisB).toHaveBeenCalledTimes(2);
    expect(f.irisB).toHaveBeenLastCalledWith(expect.objectContaining({ apiKey: "iris-key-sentinel-beta" }));
  });

  it("invalidate drops one set or all", () => {
    const f = fakes();
    const set = store.create({ name: "Acme", iris: iris() });
    store.linkCase("c1", set.id);
    const sc = createServerClients(store, {}, f.builders);
    sc.forCase("c1");
    sc.invalidate(set.id);
    sc.forCase("c1");
    sc.invalidate();
    sc.forCase("c1");
    expect(f.irisB).toHaveBeenCalledTimes(3);
  });

  it("dangling link is an error, not the default set", () => {
    const f = fakes();
    const def = store.create({ name: "Default", iris: iris() });
    store.setDefault(def.id);
    const gone = store.create({ name: "Gone", iris: iris() });
    store.linkCase("c1", gone.id);
    const p = join(dir, "server-sets", "sets.json");
    const sets = JSON.parse(readFileSync(p, "utf8")) as { id: string }[];
    writeFileSync(p, JSON.stringify(sets.filter((s) => s.id !== gone.id)));
    const r = createServerClients(store, {}, f.builders).forCase("c1");
    expect(r).toEqual({ ok: false, status: 409, error: DANGLING });
    expect(f.irisB).not.toHaveBeenCalled();
  });

  it("unlinked case is an error", () => {
    const f = fakes();
    expect(createServerClients(store, {}, f.builders).forCase("c1")).toEqual({
      ok: false,
      status: 409,
      error: NO_LINK,
    });
  });

  it("incomplete tool fails the resolve with the set name", () => {
    const f = fakes();
    const set = store.create({ name: "Acme", iris: { url: "https://iris.example.com", apiKey: "" } });
    store.linkCase("c1", set.id);
    expect(createServerClients(store, {}, f.builders).forCase("c1")).toEqual({
      ok: false,
      status: 409,
      error: "Server set 'Acme' has incomplete IRIS settings. Fix it in Settings → Server sets.",
    });
  });

  it("missing tool is undefined, not an error", () => {
    const f = fakes();
    const set = store.create({ name: "Acme", velociraptor: { apiConfigPath: "/etc/velo/api.yaml" } });
    store.linkCase("c1", set.id);
    const r = createServerClients(store, {}, f.builders).forCase("c1");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.servers.iris).toBeUndefined();
    expect(r.servers.timesketch).toBeUndefined();
    expect(r.servers.velociraptor).toBeDefined();
  });

  it("forDefault resolves the default set and errors when none", () => {
    const f = fakes();
    const sc = createServerClients(store, {}, f.builders);
    expect(sc.forDefault()).toEqual({
      ok: false,
      status: 409,
      error: "No default server set. Choose one in Settings → Server sets.",
    });
    const set = store.create({ name: "Def", iris: iris() });
    store.setDefault(set.id);
    expect(sc.forDefault().ok).toBe(true);
    expect(sc.forSet(set.id).ok).toBe(true);
  });

  it("a decrypt failure is a 409 with a generic message", () => {
    const set = store.create({ name: "Acme", iris: iris() });
    store.linkCase("c1", set.id);
    const other = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 9)));
    const r = createServerClients(other, {}, fakes().builders).forCase("c1");
    expect(r).toEqual({ ok: false, status: 409, error: "Server sets cannot be read. Check the server log." });
  });

  it("logs a read error once per key until a resolve for that key succeeds", () => {
    const set = store.create({ name: "Acme", iris: iris() });
    store.linkCase("c1", set.id);
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => undefined);
    const broken = vi.spyOn(store, "caseSetId").mockImplementation(() => {
      throw new Error("server set secret cannot decrypt");
    });
    const sc = createServerClients(store, {}, fakes().builders);
    sc.forCase("c1");
    sc.forCase("c1");
    expect(warn).toHaveBeenCalledTimes(1);
    broken.mockRestore();
    expect(sc.forCase("c1").ok).toBe(true);
    vi.spyOn(store, "caseSetId").mockImplementation(() => {
      throw new Error("server set secret cannot decrypt");
    });
    sc.forCase("c1");
    expect(warn).toHaveBeenCalledTimes(2);
    vi.restoreAllMocks();
  });
});
