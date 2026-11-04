import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { serverSetStoreDir } from "../../src/integrations/serverSets/storePath.js";

// The server set store (encrypted keys of every IRIS / Timesketch / Velociraptor connection) lives
// beside the cases root, at /data/server-sets in the image. If the container does not persist it,
// a restart loses every set while the cases keep their links: every case then fails closed.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

describe("server set store persists in the container", () => {
  it("builds the store path beside the cases root", () => {
    expect(serverSetStoreDir(join("/data", "cases"))).toBe(join("/data", "server-sets"));
  });

  it("docker-compose mounts ./server-sets at /data/server-sets", () => {
    const doc = parse(read("docker-compose.yml")) as {
      services: { companion: { volumes?: string[] } };
    };
    const volumes = (doc.services.companion.volumes ?? []).map((v) => v.split("#")[0].trim());
    expect(volumes).toContain("./server-sets:/data/server-sets");
  });

  it("the image creates /data/server-sets and the entrypoint hands it to the run user", () => {
    expect(read("Dockerfile")).toMatch(/mkdir -p [^\n]*\/data\/server-sets/);
    const known = /KNOWN_STORES="([^"]*)"/.exec(read("docker-entrypoint.sh"))?.[1] ?? "";
    expect(known.split(/\s+/)).toContain("server-sets");
  });
});
