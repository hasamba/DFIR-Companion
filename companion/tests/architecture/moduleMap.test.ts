import { readFile, readdir } from "node:fs/promises";
import { describe, expect, it } from "vitest";

// ARCHITECTURE.md is what people read; scripts/module-map.json is what CI enforces. A document
// allowed to drift from the gate is worse than no document — it teaches rules that are not real.
// These tests are the join between them.

const ROOT = new URL("../../../", import.meta.url);

async function readMap(): Promise<{
  layerRank: Record<string, number>;
  domains: Record<string, { layer: string; tier?: number; paths: string[] }>;
  flatAnalysisFiles: Record<string, string>;
}> {
  return JSON.parse(await readFile(new URL("companion/scripts/module-map.json", ROOT), "utf8")) as never;
}

const readDoc = (): Promise<string> => readFile(new URL("ARCHITECTURE.md", ROOT), "utf8");

describe("module map ↔ ARCHITECTURE.md", () => {
  it("documents every analysis domain, with the tier the map assigns it", async () => {
    const map = await readMap();
    const doc = await readDoc();

    // The domain table rows look like: | **3** | `ingest/` | … |
    const documented = new Map<string, number>();
    for (const m of doc.matchAll(/^\|\s*\*\*(\d)\*\*\s*\|\s*`([a-z]+)\/`\s*\|/gm)) {
      documented.set(`analysis/${m[2]}`, Number(m[1]));
    }

    const inMap = Object.entries(map.domains).filter(([name]) => name.startsWith("analysis/"));
    expect(inMap.length).toBeGreaterThan(0);

    for (const [name, def] of inMap) {
      expect(documented.has(name), `${name} is in module-map.json but not in ARCHITECTURE.md`).toBe(true);
      expect(documented.get(name), `${name} tier disagrees between the map and the doc`).toBe(def.tier);
    }
    for (const name of documented.keys()) {
      expect(map.domains[name], `${name} is in ARCHITECTURE.md but not in module-map.json`).toBeDefined();
    }
  });

  it("documents every layer the map ranks, in the map's order", async () => {
    const map = await readMap();
    const doc = await readDoc();

    // The layer table rows look like: | **Delivery** | … |
    const documented = [...doc.matchAll(/^\|\s*\*\*([A-Z][a-z]+)\*\*\s*\|/gm)].map((m) => m[1].toLowerCase());
    const ranked = Object.entries(map.layerRank)
      .sort(([, a], [, b]) => b - a)
      .map(([name]) => name);

    expect(documented.slice(0, ranked.length)).toEqual(ranked);
  });

  it("states the current violation count that the ledger actually holds", async () => {
    const ledger = JSON.parse(
      await readFile(new URL("companion/scripts/boundary-violations.json", ROOT), "utf8"),
    ) as string[];
    const doc = await readDoc();

    // Any "63 imports across 33 edges"-shaped claim must match the ledger, or the doc is telling
    // people the problem is a different size than it is.
    const claims = [...doc.matchAll(/(\d+)\s+(?:recorded\s+)?(?:file-pair\s+)?violations?/gi)].map((m) =>
      Number(m[1]),
    );
    expect(claims.length, "ARCHITECTURE.md should state the violation count").toBeGreaterThan(0);
    for (const claimed of claims) expect(claimed).toBe(ledger.length);
  });
});

describe("module map internals", () => {
  it("gives every domain a layer the rank table knows", async () => {
    const map = await readMap();
    for (const [name, def] of Object.entries(map.domains)) {
      expect(map.layerRank[def.layer], `${name} has unknown layer "${def.layer}"`).toBeDefined();
    }
  });

  it("only tiers domains in the domain layer", async () => {
    const map = await readMap();
    for (const [name, def] of Object.entries(map.domains)) {
      if (def.tier !== undefined) {
        expect(def.layer, `${name} has a tier but is not in the domain layer`).toBe("domain");
      }
    }
  });

  it("classifies exactly the files still sitting flat in src/analysis/", async () => {
    // Both directions, because each rots differently. A file with no entry is an unclassified
    // module the gate cannot reason about; an entry with no file is a classification left behind by
    // a move, which makes the map look current when it has drifted. check-boundaries.mjs enforces
    // both too — this asserts it in the test job, where the failure names the file directly.
    const map = await readMap();
    const dir = new URL("companion/src/analysis/", ROOT);
    const onDisk = (await readdir(dir, { withFileTypes: true }))
      .filter((e) => e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".d.ts"))
      .map((e) => e.name)
      .sort();

    expect(Object.keys(map.flatAnalysisFiles).sort()).toEqual(onDisk);
  });

  it("points every flat-file assignment at a domain that exists", async () => {
    const map = await readMap();
    for (const [file, domain] of Object.entries(map.flatAnalysisFiles)) {
      expect(map.domains[domain], `${file} is assigned to unknown domain "${domain}"`).toBeDefined();
    }
  });
});
