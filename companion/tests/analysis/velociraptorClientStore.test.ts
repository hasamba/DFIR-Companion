import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VelociraptorClientStore } from "../../src/analysis/velociraptorClientStore.js";
import type { VeloClientRecord } from "../../src/integrations/velociraptor/velociraptorApi.js";

const NOW = "2026-06-12T00:00:00.000Z";

async function tmpFile(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-veloclients-"));
  return join(dir, "velociraptor", "clients.json");   // a not-yet-created subdir, like the real layout
}

const recs: VeloClientRecord[] = [
  { clientId: "C.win11", hostname: "WIN11", fqdn: "WIN11.windomain.local", lastSeen: "t1" },
  { clientId: "C.kali", hostname: "kaliPurple", fqdn: "kaliPurple.windomain.local" },
];

describe("VelociraptorClientStore", () => {
  let file: string;
  beforeEach(async () => { file = await tmpFile(); });

  it("returns an empty inventory before anything is saved", async () => {
    const inv = await new VelociraptorClientStore(file).load();
    expect(inv).toEqual({ updatedAt: "", clients: [] });
  });

  it("saves and reloads the inventory (creating the subdir)", async () => {
    const store = new VelociraptorClientStore(file);
    const saved = await store.save(recs, NOW);
    expect(saved).toEqual({ updatedAt: NOW, clients: recs });
    const loaded = await store.load();
    expect(loaded.updatedAt).toBe(NOW);
    expect(loaded.clients).toHaveLength(2);
    expect(loaded.clients[0].clientId).toBe("C.win11");
  });

  it("drops records with no clientId on load", async () => {
    await mkdir(join(file, ".."), { recursive: true });
    await writeFile(file, JSON.stringify({ updatedAt: NOW, clients: [{ hostname: "x" }, { clientId: "C.a", hostname: "a", fqdn: "" }] }), "utf8");
    const inv = await new VelociraptorClientStore(file).load();
    expect(inv.clients).toHaveLength(1);
    expect(inv.clients[0].clientId).toBe("C.a");
  });

  it("returns an empty inventory for malformed JSON", async () => {
    await mkdir(join(file, ".."), { recursive: true });
    await writeFile(file, "{ not json", "utf8");
    expect((await new VelociraptorClientStore(file).load()).clients).toEqual([]);
  });
});
