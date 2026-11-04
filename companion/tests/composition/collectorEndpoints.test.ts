import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { configuredCollectorServers } from "../../src/analysis/collectorDeployment.js";
import { setCollectorEndpointSource } from "../../src/analysis/collectorEndpointSource.js";
import { registerCollectorEndpoints } from "../../src/composition/collectorEndpoints.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";

// Collector recognition is read-only: an analyst's own collector traffic from ANY of their server
// sets is their own, so every set's Velociraptor host counts, and the env values count for nothing.
let dir: string;
afterEach(() => {
  setCollectorEndpointSource(() => []);
  vi.unstubAllEnvs();
  rmSync(dir, { recursive: true, force: true });
});

describe("collector recognition reads every server set", () => {
  it("recognizes the GUI URL host and api_connection_string host of a non-default set, with env empty", () => {
    dir = mkdtempSync(join(tmpdir(), "collector-ep-"));
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", "");
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", "");
    const api = join(dir, "api.yaml");
    writeFileSync(api, "api_connection_string: velo-api.example.com:8001\n");
    const store = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 3)));
    const a = store.create({
      name: "A",
      velociraptor: { apiConfigPath: "", guiUrl: "https://velo-a.example.com:8889" },
    });
    store.create({
      name: "B",
      velociraptor: { apiConfigPath: api, guiUrl: "https://velo-b.example.com:8889" },
    });
    store.setDefault(a.id);
    registerCollectorEndpoints(store);
    expect(configuredCollectorServers().sort()).toEqual([
      "velo-a.example.com",
      "velo-api.example.com",
      "velo-b.example.com",
    ]);
  });

  it("ignores the env values", () => {
    dir = mkdtempSync(join(tmpdir(), "collector-ep-"));
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", "https://velo-env.example.com:8889");
    const store = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 3)));
    registerCollectorEndpoints(store);
    expect(configuredCollectorServers()).toEqual([]);
  });

  it("a set whose secret cannot decrypt still yields its Velociraptor host", () => {
    dir = mkdtempSync(join(tmpdir(), "collector-ep-"));
    const sdir = join(dir, "server-sets");
    new ServerSetStore(sdir, deriveServerSetKey(Buffer.alloc(32, 3))).create({
      name: "A",
      iris: { url: "https://iris.example.com", apiKey: "iris-key-sentinel-alpha" },
      velociraptor: { apiConfigPath: "", guiUrl: "https://velo-a.example.com:8889" },
    });
    registerCollectorEndpoints(new ServerSetStore(sdir, deriveServerSetKey(Buffer.alloc(32, 4))));
    expect(configuredCollectorServers()).toEqual(["velo-a.example.com"]);
  });
});
