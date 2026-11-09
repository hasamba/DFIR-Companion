import { describe, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeCollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import { parseManifest } from "../../src/integrations/cloudCollect/collectManifest.js";
import { collectorRunOf, createCollectorRunReader } from "../../src/integrations/cloudCollect/collectRuns.js";
import type { CollectionCheckpoint } from "../../src/integrations/cloudCollect/collectTypes.js";

// #2487 — the spans a collection's own API calls are matched in.

const CALLER = "arn:aws:sts::111122223333:assumed-role/dfir-companion-read/dfir-companion-collect";
const header = (startedAt = "2026-11-05T10:00:00.000Z", caller = CALLER) => ({
  type: "header",
  version: 1,
  collectionId: "cc-20261105t100000-aaaaaaaa",
  provider: "aws",
  accountId: "a1",
  accountName: "lab",
  accountRef: "111122223333",
  caller,
  sources: ["ct"],
  window: { start: "2026-11-01T00:00:00Z", end: "2026-11-02T00:00:00Z" },
  filters: {},
  sdkVersions: {},
  companionVersion: "0",
  startedAt,
});
const page = (seq: number, retrievedAt: string) => ({
  type: "page",
  seq,
  source: "ct",
  subWindowId: "w",
  requestParams: {},
  retrievedAt,
  file: `p${seq}.json`,
  bytes: 1,
  sha256: "x",
  records: 1,
});
const manifest = (...lines: object[]) => parseManifest(lines.map((l) => `${JSON.stringify(l)}\n`).join(""));
const cp = (over: Partial<CollectionCheckpoint>): CollectionCheckpoint =>
  ({ status: "complete", updatedAt: "2026-11-05T12:00:00.000Z", ...over }) as CollectionCheckpoint;

describe("collectorRunOf", () => {
  it("ends a run at its recorded network end, not at the import stage's last checkpoint", () => {
    const run = collectorRunOf(
      manifest(header(), page(1, "2026-11-05T10:10:00.000Z")),
      cp({ networkSpans: [{ from: "2026-11-05T10:00:00.000Z", to: "2026-11-05T10:20:00.000Z" }] }),
    );
    expect(run).toEqual({
      collectionId: "cc-20261105t100000-aaaaaaaa",
      provider: "aws",
      spans: [{ from: "2026-11-05T10:00:00.000Z", to: "2026-11-05T10:20:00.000Z", caller: CALLER }],
    });
  });

  it("without a recorded end: the last saved page, or the live checkpoint while running", () => {
    const m = manifest(header(), page(1, "2026-11-05T10:10:00.000Z"), page(2, "2026-11-05T10:15:00.000Z"));
    expect(collectorRunOf(m, cp({ status: "interrupted" }))?.spans[0].to).toBe("2026-11-05T10:15:00.000Z");
    expect(collectorRunOf(m, null)?.spans[0].to).toBe("2026-11-05T10:15:00.000Z");
    expect(
      collectorRunOf(m, cp({ status: "running", updatedAt: "2026-11-05T10:16:00.000Z" }))?.spans[0].to,
    ).toBe("2026-11-05T10:16:00.000Z");
    expect(collectorRunOf(manifest(header()), cp({ status: "failed" }))?.spans[0].to).toBe(
      "2026-11-05T10:00:00.000Z",
    );
  });

  it("a resume is its own span with its own caller; a resume line without one is unmatched", () => {
    const resumed = collectorRunOf(
      manifest(
        header(),
        page(1, "2026-11-05T10:10:00.000Z"),
        { type: "resume", at: "2026-11-06T09:00:00.000Z", caller: "arn:aws:iam::111122223333:user/other" },
        page(2, "2026-11-06T09:05:00.000Z"),
        { type: "resume", at: "2026-11-07T09:00:00.000Z" },
        page(3, "2026-11-07T09:05:00.000Z"),
      ),
      cp({ status: "complete" }),
    );
    expect(resumed?.spans).toEqual([
      { from: "2026-11-05T10:00:00.000Z", to: "2026-11-05T10:10:00.000Z", caller: CALLER },
      {
        from: "2026-11-06T09:00:00.000Z",
        to: "2026-11-06T09:05:00.000Z",
        caller: "arn:aws:iam::111122223333:user/other",
      },
    ]);
  });

  it("an unknown caller or a missing header gives nothing", () => {
    expect(collectorRunOf(manifest(header(undefined, "unknown")), null)?.spans).toEqual([]);
    expect(collectorRunOf(manifest(page(1, "2026-11-05T10:10:00.000Z")), null)).toBeNull();
  });
});

describe("createCollectorRunReader", () => {
  it("reads every collection of a case, skips damaged ones, and sees a changed manifest at once", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "dfir-collectruns-"));
    const root = join(caseDir, "evidence", "cloud");
    const good = join(root, "cc-20261105t100000-aaaaaaaa");
    const bad = join(root, "cc-20261105t110000-bbbbbbbb");
    await mkdir(good, { recursive: true });
    await mkdir(bad, { recursive: true });
    await mkdir(join(root, "not-a-collection"), { recursive: true });
    await writeFile(
      join(good, "manifest.jsonl"),
      `${JSON.stringify(header())}\n${JSON.stringify(page(1, "2026-11-05T10:10:00.000Z"))}\n`,
    );
    await writeFile(join(bad, "manifest.jsonl"), "garbage\n");
    const read = createCollectorRunReader(nodeCollectFs);
    const first = await read(caseDir);
    expect(first.map((r) => r.collectionId)).toEqual(["cc-20261105t100000-aaaaaaaa"]);
    expect(first[0].spans[0].to).toBe("2026-11-05T10:10:00.000Z");
    await appendFile(
      join(good, "manifest.jsonl"),
      `${JSON.stringify(page(2, "2026-11-05T10:25:00.000Z"))}\n`,
    );
    expect((await read(caseDir))[0].spans[0].to).toBe("2026-11-05T10:25:00.000Z");
    expect(await read(join(caseDir, "missing"))).toEqual([]);
  });
});
