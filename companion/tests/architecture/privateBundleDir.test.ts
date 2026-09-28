// Every test app owns its bundle store (#1748).
//
// vitest.config.ts points TMPDIR at ONE per-run root for every worker, so every mkdtemp() root in a
// run is a sibling of every other. Six server test files built their bundle store at
// `join(dirname(root), "bundles")` — one directory shared by every file in every worker.
// veloBundle.test.ts saves overrides of the built-in `best-practice` bundle and never resets them,
// so a later file that launched `best-practice` collected ONE artifact instead of two. In a full
// run that read as flake: it passed alone and failed only when veloBundle.test.ts ran first.
//
// Two checks. The behavioural one proves the helper isolates two apps under one parent. The source
// one stops a new file from deriving its bundle store from the shared run root again.
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { privateBundleDir } from "../helpers/bundleDir.js";

const TESTS_DIR = fileURLToPath(new URL("../", import.meta.url));

async function testFiles(dir = TESTS_DIR, prefix = ""): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) found.push(...(await testFiles(join(dir, entry.name), rel)));
    else if (entry.name.endsWith(".test.ts")) found.push(rel);
  }
  return found;
}

// The spellings that reach the run root every file shares: its parent, the OS temp dir, or a
// timestamp that two workers can hit in the same millisecond.
const SHARED_ROOT = /\bdirname\s*\(|\btmpdir\s*\(|\bDate\.now\s*\(/;

/** `line: argument` for each `new ArtifactBundleStore(arg)` whose argument reaches a shared root. */
function sharedBundleStores(source: string, file: string): string[] {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const hits: string[] = [];
  const visit = (node: ts.Node): void => {
    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "ArtifactBundleStore"
    ) {
      const arg = node.arguments?.[0];
      const isHelper =
        arg !== undefined &&
        ts.isCallExpression(arg) &&
        ts.isIdentifier(arg.expression) &&
        arg.expression.text === "privateBundleDir";
      if (arg && !isHelper && SHARED_ROOT.test(arg.getText(sf))) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        hits.push(`${file}:${line}: ${arg.getText(sf)}`);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return hits;
}

describe("private bundle store per test app (#1748)", () => {
  it("an override saved through one app's store does not reach a sibling app's store", async () => {
    const parent = await mkdtemp(join(tmpdir(), "dfir-bundledir-"));
    const rootA = await mkdtemp(join(parent, "case-"));
    const rootB = await mkdtemp(join(parent, "case-"));
    expect(privateBundleDir(rootA)).not.toBe(privateBundleDir(rootB));

    const a = new ArtifactBundleStore(privateBundleDir(rootA));
    const b = new ArtifactBundleStore(privateBundleDir(rootB));
    await a.save({
      id: "best-practice",
      name: "Overridden",
      description: "d",
      artifacts: ["Generic.System.Pstree"],
    });

    expect((await a.get("best-practice"))?.customized).toBe(true);
    const untouched = await b.get("best-practice");
    expect(untouched?.customized).toBe(false);
    expect(untouched?.name).toBe("Best Practice");
  });

  it("the source check flags a store built on the shared run root, and passes the helper", () => {
    const bad = [
      'new ArtifactBundleStore(join(dirname(root), "bundles"));',
      "new ArtifactBundleStore(pathJoin(dirname(root), `bundles-${Date.now()}`));",
      'new ArtifactBundleStore(join(tmpdir(), "bundles"));',
    ];
    for (const src of bad) expect(sharedBundleStores(src, "x.ts")).toHaveLength(1);
    expect(sharedBundleStores("new ArtifactBundleStore(privateBundleDir(root));", "x.ts")).toEqual([]);
    expect(sharedBundleStores('new ArtifactBundleStore(join(storesRoot, "bundles"));', "x.ts")).toEqual([]);
  });

  it("no test builds its bundle store on the run root that every test file shares", async () => {
    const offenders: string[] = [];
    for (const rel of await testFiles()) {
      const source = await readFile(join(TESTS_DIR, rel), "utf8");
      if (!source.includes("ArtifactBundleStore")) continue;
      offenders.push(...sharedBundleStores(source, rel));
    }
    expect(offenders).toEqual([]);
  });
});
