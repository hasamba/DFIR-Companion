import { execFileSync } from "node:child_process";
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

/**
 * The counts, from the gate itself rather than recomputed here.
 *
 * Recomputing would mean re-implementing domainOf, rankOf and the import scanner in the test, and a
 * re-implemented rule agrees with the original right up until it silently doesn't — that is exactly
 * how the ready-count filter in dashboardInventory.test.ts came to certify a flag the script had
 * stopped consulting. One resolver, two readers.
 */
const boundaryCounts = (): {
  crossDomain: number;
  complying: number;
  violations: number;
  violationEdges: number;
} =>
  JSON.parse(
    execFileSync(
      process.execPath,
      [new URL("companion/scripts/check-boundaries.mjs", ROOT).pathname, "--json"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ),
  );

/** "1,679" -> 1679. The doc writes thousands separators; nothing else in it does. */
const num = (s: string): number => Number(s.replace(/,/g, ""));

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

  it("states a comply/total pair that the boundary scan actually produces", async () => {
    // The number that rotted. The doc read "1,275 of the 1,323 cross-domain file dependencies
    // already comply", a difference that contradicted the ledger sitting beside it — and both
    // halves were stale besides. Every other figure in that document stayed right because the test
    // above guarded it; this one had nothing, so it drifted quietly while still reading as
    // authoritative, which is the failure mode a wrong number in prose always has.
    //
    // Both halves are asserted, not just the difference: a pair can be internally consistent and
    // still describe a codebase two hundred dependencies smaller than this one.
    const counts = boundaryCounts();
    const doc = await readDoc();

    const m = doc.match(/([\d,]+) of the ([\d,]+) cross-domain file dependencies already comply/);
    expect(m, "ARCHITECTURE.md should state the cross-domain comply/total pair").not.toBeNull();

    const [, complying, total] = m as RegExpMatchArray;
    expect(num(complying), "the complying figure has drifted from check-boundaries").toBe(counts.complying);
    expect(num(total), "the cross-domain total has drifted from check-boundaries").toBe(counts.crossDomain);

    // The pair and the ledger have to agree with each other too. Asserting each against the scan
    // separately would let a scan whose two counts disagreed satisfy both — and the whole reason
    // the old pair looked wrong was that its difference contradicted the ledger.
    const ledger = JSON.parse(
      await readFile(new URL("companion/scripts/boundary-violations.json", ROOT), "utf8"),
    ) as string[];
    expect(counts.crossDomain - counts.complying).toBe(ledger.length);
    expect(counts.violations).toBe(ledger.length);
  });

  it("states the number of domain edges the violations actually span", async () => {
    // Correct today — #549 fixed it — and unguarded, which is the same position the comply/total
    // pair was in before it drifted. A number that is right for now and watched by nothing is a
    // number waiting its turn.
    const counts = boundaryCounts();
    const doc = await readDoc();

    const claims = [...doc.matchAll(/spanning (\d+) domain edges/gi)].map((mm) => Number(mm[1]));
    expect(claims.length, "ARCHITECTURE.md should state the domain-edge span").toBeGreaterThan(0);
    for (const claimed of claims) expect(claimed).toBe(counts.violationEdges);
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
