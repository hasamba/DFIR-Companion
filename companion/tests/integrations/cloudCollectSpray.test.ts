import { describe, it, expect } from "vitest";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  pageIdPrefix,
  summaryIdPrefix,
  summaryLabel,
} from "../../src/integrations/cloudCollect/collectSummary.js";
import { uploadBatchOf } from "../../src/analysis/ingest/cloudStreamSpray.js";
import { tempCase, type TempCase } from "../helpers/cloudCollectFakes.js";
import { spraySignIn } from "../helpers/entraPathRecords.js";

// #2493 (Codex review) — a collection's password spray is read from the sign-in store:
//   - its OWN observations in full, never through the newest-100,000 window cap, and a build whose
//     other-upload history was capped never reconciles away an earlier summary row;
//   - every collection counts as ONE upload, earlier collections included, so cross-upload
//     dominance and "across N uploads" count collections, not pages.

type Row = Record<string, unknown>;
const isSpray = (e: { mitreTechniques: string[] }) => e.mitreTechniques.includes("T1110.003");

/** Import `pages` of one collection as its page step does, and return its summary-step pages. */
async function importPages(t: TempCase, collectionId: string, pages: Row[][]) {
  const out: Array<{ path: string; records: number; batch: string }> = [];
  for (const [i, recs] of pages.entries()) {
    const seq = i + 1;
    const path = join(t.root, `${collectionId}-p${seq}.json`);
    await writeFile(path, JSON.stringify(recs));
    const batch = pageIdPrefix(collectionId, seq);
    await t.pipeline.importCloudFile("c1", "m365", path, {
      label: `evidence/cloud/${collectionId}/p${seq}.json`,
      idPrefix: batch,
      importedAt: "2026-06-02T00:00:00Z",
      skipSummaries: true,
    });
    out.push({ path, records: recs.length, batch });
  }
  return out;
}

const summarize = (t: TempCase, collectionId: string, pages: Awaited<ReturnType<typeof importPages>>) =>
  t.pipeline.importCloudCollectionSummary("c1", "m365", pages, {
    collectionId,
    label: summaryLabel(collectionId, "m365"),
    idPrefix: summaryIdPrefix(collectionId, "m365"),
    importedAt: "2026-06-02T00:00:00Z",
  });

const accounts = (names: string[], fromMinute: number) =>
  names.map((n, i) => spraySignIn(`${n}@example.invalid`, fromMinute + i * 20));

describe("collection spray reads its own evidence in full (#2493)", () => {
  it("a page batch maps to its collection; a file upload's batch stays its own", () => {
    expect(uploadBatchOf(pageIdPrefix("cc-test-abc123", 7))).toBe(
      uploadBatchOf(pageIdPrefix("cc-test-abc123", 1)),
    );
    expect(uploadBatchOf(pageIdPrefix("cc-test-abc123", 7))).not.toBe(
      uploadBatchOf(pageIdPrefix("cc-other-xyz789", 7)),
    );
    expect(uploadBatchOf("c12")).toBe("c12");
    expect(uploadBatchOf("m3")).toBe("m3");
  });

  it("a rebuild whose sign-in history is capped by newer uploads keeps the collection's spray row", async () => {
    const t = await tempCase();
    const pages = await importPages(t, "cc-old-aaa111", [
      accounts(["alice", "bob", "carol"], 0),
      accounts(["dave", "erin", "frank"], 60),
    ]);
    const first = await summarize(t, "cc-old-aaa111", pages);
    const before = first.state.forensicTimeline.filter(isSpray);
    expect(before).toHaveLength(1);

    // Newer uploads have filled the store's newest-100,000 window: none of this collection's rows
    // come back from it, and the read says it was capped.
    t.authObservationStore.queryWindow = async () => ({ observations: [], truncated: true });
    const again = await summarize(t, "cc-old-aaa111", pages);
    const after = again.state.forensicTimeline.filter(isSpray);
    expect(after.map((e) => e.id)).toEqual(before.map((e) => e.id));
    expect(after[0].description).toContain("6 distinct accounts");
    expect(
      again.state.timeline.some((e) => (e.description ?? "").includes("were kept, not reconciled")),
    ).toBe(true);
  });
});

describe("every collection counts as one upload (#2493)", () => {
  it("an earlier collection that met the threshold across its pages adds no cross-upload row", async () => {
    const t = await tempCase();
    await summarize(
      t,
      "cc-first-aaa111",
      await importPages(t, "cc-first-aaa111", [
        accounts(["alice", "bob", "carol"], 0),
        accounts(["dave", "erin", "frank"], 60),
      ]),
    );
    const second = await summarize(
      t,
      "cc-second-bbb222",
      await importPages(t, "cc-second-bbb222", [accounts(["gina"], 120), accounts(["hank"], 140)]),
    );
    const spray = second.state.forensicTimeline.filter(isSpray);
    expect(
      spray.filter((e) => e.sourceScreenshots.includes(summaryLabel("cc-second-bbb222", "m365"))),
    ).toEqual([]);
    expect(spray).toHaveLength(1); // the first collection's own within-collection row
  });

  it("a spray across two collections says 'across 2 uploads', however many pages they had", async () => {
    const t = await tempCase();
    await summarize(
      t,
      "cc-first-aaa111",
      await importPages(t, "cc-first-aaa111", [accounts(["alice"], 0), accounts(["bob"], 20)]),
    );
    const second = await summarize(
      t,
      "cc-second-bbb222",
      await importPages(t, "cc-second-bbb222", [accounts(["carol", "dave"], 40), accounts(["erin"], 80)]),
    );
    const cross = second.state.forensicTimeline
      .filter(isSpray)
      .filter((e) => e.sourceScreenshots.includes(summaryLabel("cc-second-bbb222", "m365")));
    expect(cross).toHaveLength(1);
    expect(cross[0].description).toMatch(/^Password-spray pattern \(low-and-slow, across 2 uploads\): /);
    expect(cross[0].description).toContain("5 distinct accounts");
  });
});
