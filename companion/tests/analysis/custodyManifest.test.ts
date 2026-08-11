import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, appendFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import {
  buildCustodyManifest,
  verifyCustodyManifest,
  type CustodyManifest,
} from "../../src/analysis/custodyManifest.js";

let cases: CaseStore;
let custody: CustodyStore;
let one: string;
let two: string;

const SECRET = Buffer.from("a".repeat(64), "hex");
const OTHER_SECRET = Buffer.from("b".repeat(64), "hex");
const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

async function collect(path: string, text: string): Promise<void> {
  await writeFile(path, text, "utf8");
  await custody.record("c1", {
    artifactPath: path,
    sha256: sha(text),
    collectedBy: "alice",
    collectedAt: "2026-07-28T10:00:00.000Z",
    source: "host-a",
    trigger: "import",
    caseId: "c1",
  });
}

const build = () => buildCustodyManifest(cases, custody, "c1", SECRET);

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-custodymanifest-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  custody = new CustodyStore(cases);
  one = join(cases.importsDir("c1"), "one.csv");
  two = join(cases.importsDir("c1"), "two.csv");
});

describe("buildCustodyManifest", () => {
  it("groups every custody record under the artifact it belongs to", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");
    await custody.recordExport("c1", { exportedBy: "alice", destination: "zip" });

    const manifest = await build();

    expect(manifest.artifacts).toHaveLength(2);
    const first = manifest.artifacts.find((a) => a.path.endsWith("one.csv"));
    expect(first?.chain.map((r) => r.event)).toEqual(["collected", "exported"]);
  });

  it("records artifact paths relative to the case dir, so the manifest travels with the case", async () => {
    await collect(one, "first\n");

    const manifest = await build();

    expect(manifest.artifacts[0].path).toBe(join("imports", "one.csv"));
  });

  it("keeps an absolute path for evidence collected outside the case dir", async () => {
    const external = join(await mkdtemp(join(tmpdir(), "dfir-manifest-ext-")), "image.dd");
    await collect(external, "mounted\n");

    const manifest = await build();

    expect(manifest.artifacts[0].path).toBe(external);
  });

  it("records the chain head, which is what makes truncating the log detectable", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");
    const lines = (await readFile(cases.custodyLogPath("c1"), "utf8")).split("\n").filter((l) => l.trim());

    const manifest = await build();

    expect(manifest.chain).toMatchObject({ records: 2, headSeq: 2, headHash: sha(lines[1]) });
  });

  it("reports chain breaks that already exist at signing time", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");
    const [first, second] = (await readFile(cases.custodyLogPath("c1"), "utf8"))
      .split("\n")
      .filter((l) => l.trim());
    const tampered = { ...(JSON.parse(first) as Record<string, unknown>), collectedBy: "mallory" };
    await writeFile(cases.custodyLogPath("c1"), JSON.stringify(tampered) + "\n" + second + "\n", "utf8");

    const manifest = await build();

    expect(manifest.chain.breaks).toEqual([{ line: 2, seq: 2, reason: "prev-hash-mismatch" }]);
  });

  it("signs an empty case rather than refusing one", async () => {
    const manifest = await build();

    expect(manifest.artifacts).toEqual([]);
    expect(manifest.chain).toMatchObject({ records: 0, headSeq: null, headHash: "" });
    expect(verifyCustodyManifest(manifest, SECRET)).toBe(true);
  });
});

describe("verifyCustodyManifest", () => {
  it("verifies a manifest under the secret that signed it", async () => {
    await collect(one, "first\n");

    expect(verifyCustodyManifest(await build(), SECRET)).toBe(true);
  });

  it("rejects a manifest whose contents were edited after signing", async () => {
    await collect(one, "first\n");
    const manifest = await build();

    manifest.artifacts[0].chain[0].collectedBy = "mallory";

    expect(verifyCustodyManifest(manifest, SECRET)).toBe(false);
  });

  it("rejects a manifest whose recorded chain head was swapped", async () => {
    await collect(one, "first\n");
    const manifest = await build();

    manifest.chain.headHash = sha("something else");

    expect(verifyCustodyManifest(manifest, SECRET)).toBe(false);
  });

  it("rejects a manifest signed by a different instance", async () => {
    await collect(one, "first\n");

    expect(verifyCustodyManifest(await build(), OTHER_SECRET)).toBe(false);
  });

  it("rejects a manifest carrying no signature at all", async () => {
    await collect(one, "first\n");
    const manifest = await build();

    expect(
      verifyCustodyManifest({ ...manifest, signature: undefined } as unknown as CustodyManifest, SECRET),
    ).toBe(false);
  });

  it("verifies after a round trip through JSON, whatever order the keys come back in", async () => {
    await collect(one, "first\n");
    const manifest = await build();

    const roundTripped = JSON.parse(JSON.stringify(manifest)) as Record<string, unknown>;
    // Rebuild with the keys in reverse order — a signature over a naive JSON.stringify would break.
    const reordered = Object.fromEntries(
      Object.entries(roundTripped).reverse(),
    ) as unknown as CustodyManifest;

    expect(verifyCustodyManifest(reordered, SECRET)).toBe(true);
  });
});

describe("CustodyStore.chainHead", () => {
  it("reports an empty head before anything is recorded", async () => {
    expect(await custody.chainHead("c1")).toEqual({ records: 0, headSeq: null, headHash: "" });
  });

  it("advances as records are appended", async () => {
    await collect(one, "first\n");
    await appendFile(cases.custodyLogPath("c1"), "\n", "utf8"); // blank lines are not records

    const head = await custody.chainHead("c1");

    expect(head).toMatchObject({ records: 1, headSeq: 1 });
  });
});
