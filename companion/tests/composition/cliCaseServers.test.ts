import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cliCaseTool } from "../../src/composition/cliCaseServers.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import { serverSetStoreDir } from "../../src/integrations/serverSets/storePath.js";
import { loadOrCreateInstanceSecret } from "../../src/analysis/instanceSecret.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";
import type { IrisSettings } from "../../src/integrations/serverSets/types.js";

// The CLI scripts (iris:push, iris:import, timesketch:push) pick the case's own server set, exactly
// as the server does. There is no fallback to the default set or to the DFIR_* values in .env.
let dir: string;
let casesRoot: string;
const built: string[] = [];
const builders = {
  iris: (s: IrisSettings) => {
    built.push(s.url);
    return { url: s.url } as unknown as IrisClient;
  },
};
const ENV = { DFIR_IRIS_URL: "https://iris-env.example.com", DFIR_IRIS_KEY: "iris-key-sentinel-env" };

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cli-sets-"));
  casesRoot = join(dir, "cases");
  built.length = 0;
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function seed() {
  const store = new ServerSetStore(
    serverSetStoreDir(casesRoot),
    deriveServerSetKey(loadOrCreateInstanceSecret(casesRoot)),
  );
  const a = store.create({
    name: "A",
    iris: { url: "https://iris-a.example.com", apiKey: "iris-key-sentinel-a" },
  });
  const b = store.create({
    name: "B",
    iris: { url: "https://iris-b.example.com", apiKey: "iris-key-sentinel-b" },
  });
  const none = store.create({ name: "Bare" });
  store.setDefault(a.id);
  store.linkCase("c-b", b.id);
  store.linkCase("c-bare", none.id);
  return store;
}

describe("cliCaseTool", () => {
  it("uses the case's own set, not the default set", () => {
    seed();
    const r = cliCaseTool(casesRoot, "c-b", "iris", { env: ENV, builders });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.setName).toBe("B");
    expect(r.servers.irisPush).toBeDefined();
    expect(built).toEqual(["https://iris-b.example.com"]);
  });

  it("an unlinked case fails with the resolver's message, never the env or default server", () => {
    seed();
    const r = cliCaseTool(casesRoot, "c-none", "iris", { env: ENV, builders });
    expect(r).toEqual({ ok: false, error: "This case has no server set. Choose one in the case header." });
    expect(built).toEqual([]);
  });

  it("a set without the tool fails with a clear message", () => {
    seed();
    const r = cliCaseTool(casesRoot, "c-bare", "iris", { env: ENV, builders });
    expect(r).toEqual({
      ok: false,
      error: "DFIR-IRIS is not configured in server set 'Bare'. Add it in Settings → Server sets.",
    });
  });

  it("with no store yet it fails and creates nothing", () => {
    const r = cliCaseTool(casesRoot, "c-b", "iris", { env: ENV, builders });
    expect(r.ok).toBe(false);
    expect(existsSync(serverSetStoreDir(casesRoot))).toBe(false);
    expect(existsSync(join(casesRoot, ".instance-secret"))).toBe(false);
  });
});
