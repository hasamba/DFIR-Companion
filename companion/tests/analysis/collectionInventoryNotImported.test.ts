import { describe, it, expect } from "vitest";
import {
  buildCollectionInventory,
  emptySettledClasses,
  inventorySignature,
  renderCollectionInventory,
  sanitizeHuntJobs,
} from "../../src/analysis/collectionInventory.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";

// #2838 — the collection inventory the AI reads called a held or analyst-skipped hunt artifact
// "fetch failed" (it was READ, and not imported), and left out a hunt whose collect stopped part-way
// although its earlier artifacts are in the case. Every job here goes through sanitizeHuntJobs, the
// real path: the mark must survive it.

const PF = "Windows.Forensics.Prefetch";
const MFT = "Windows.NTFS.MFT";
// Shaped like the stored reasons: a file path, sizes and a machine name. None may reach the prompt.
const HELD_WHY =
  "held over the hunt artifact size limit (61 MB from one PC (limit 50 MB per PC)) — saved in _held/H.1/Windows.NTFS.MFT.json; Import anyway or Skip in the dashboard";
const STOPPED_WHY = "Import refused to protect the server on WS-SECRET-01.";

function job(over: Partial<VeloHuntJob>): VeloHuntJob {
  return {
    bundleId: "b",
    bundleName: "B",
    artifacts: [],
    huntId: "H.1",
    launchedAt: "2026-08-28T10:00:00Z",
    waitMinutes: 5,
    collectAt: "2026-08-28T10:05:00Z",
    status: "imported",
    clientCounts: { scheduled: 1, completed: 1, errors: 0 },
    reachedClients: [{ clientId: "C.1", hostname: "WS01", fqdn: "", os: "windows" }],
    ...over,
  };
}

function build(raw: unknown[]) {
  const hunts = sanitizeHuntJobs(raw);
  return buildCollectionInventory({ events: [], hunts });
}
const states = (inv: ReturnType<typeof build>) => inv.hunts.map((h) => `${h.artifact}=${h.state}`);

/** A collect that kept Custom.X, found nothing for Prefetch, and stopped at the MFT. */
const partial = (over: Partial<VeloHuntJob> = {}) =>
  job({
    status: "error",
    artifacts: ["Custom.X", PF, MFT, "Custom.Later"],
    truncatedArtifacts: [{ name: "Custom.X", kept: 500, total: 501 }],
    emptyArtifacts: [PF],
    skippedArtifacts: [
      { name: MFT, error: STOPPED_WHY, notImported: "stopped" },
      {
        name: "Custom.Later",
        error: `not imported: the collect stopped when ${MFT} failed`,
        notImported: "stopped",
      },
    ],
    ...over,
  });

describe("a hunt artifact that was read but not imported (#2838)", () => {
  it("says a held artifact was read but not imported, never 'fetch failed', and keeps the reason out", () => {
    const inv = build([
      job({
        artifacts: [MFT, "Custom.Slow"],
        skippedArtifacts: [
          { name: MFT, error: HELD_WHY, notImported: "held" },
          { name: "Custom.Slow", error: "timeout" },
        ],
        // A held artifact keeps the precedence a failed one has: no cut-short or unread line for it.
        truncatedArtifacts: [{ name: MFT, kept: 500, total: 501 }],
        unreadArtifacts: [{ name: MFT, rows: 3 }],
      }),
    ]);
    expect(states(inv)).toEqual(["Custom.Slow=failed", `${MFT}=not-imported`]);
    const text = renderCollectionInventory(inv);
    expect(text).toContain(`${MFT} — read but NOT imported by this hunt (held over a size limit`);
    expect(text).toContain("Custom.Slow — fetch failed");
    expect(text).not.toContain(`${MFT} — fetch failed`);
    expect(text).not.toContain("_held/");
    expect(text).not.toContain("61 MB");
  });

  it("drops a mark that is not one of the two known values", () => {
    const [j] = sanitizeHuntJobs([
      {
        ...job({ artifacts: ["A", "B", "C", "D"] }),
        skippedArtifacts: [
          { name: "A", error: "x", notImported: true },
          { name: "B", error: "x", notImported: "imported" },
          { name: "C", error: "x", notImported: "held" },
          { name: "D", error: "x", notImported: "stopped" },
        ],
      },
    ]);
    expect(j.skippedArtifacts).toEqual([
      { name: "A", error: "x" },
      { name: "B", error: "x" },
      { name: "C", error: "x", notImported: "held" },
      { name: "D", error: "x", notImported: "stopped" },
    ]);
  });
});

describe("a hunt whose collect stopped part-way (#2838)", () => {
  it("is listed with what it imported, and its empty result settles nothing", () => {
    const inv = build([partial()]);
    expect(states(inv)).toEqual([
      "Custom.Later=not-imported",
      "Custom.X=truncated",
      `${PF}=empty`,
      `${MFT}=not-imported`,
    ]);
    const empty = inv.hunts.find((h) => h.state === "empty");
    expect(empty).toMatchObject({ bounded: true, reached: [] });
    expect(empty?.detail).toContain("the collect stopped part-way");
    expect([...emptySettledClasses(inv, "WS01")]).toEqual([]);
    const text = renderCollectionInventory(inv);
    expect(text).toContain("Custom.X — partial — ");
    expect(text).toContain(`${MFT} — read but NOT imported by this hunt (the collect stopped part-way)`);
    expect(text).not.toContain("WS-SECRET-01");
    expect(text).not.toContain("fetch failed");
  });

  it("control: the same lists on an imported job DO settle the class on the reached host", () => {
    const inv = build([partial({ status: "imported", skippedArtifacts: undefined })]);
    expect([...emptySettledClasses(inv, "WS01")]).toEqual(["execution"]);
  });

  it("a later collect that failed early keeps the older records: still nothing settles", () => {
    // The stale window: fresh hosts from the new collect beside the earlier collect's lists.
    const inv = build([
      partial({
        reachedClients: [
          { clientId: "C.1", hostname: "WS01", fqdn: "", os: "windows" },
          { clientId: "C.2", hostname: "WS02", fqdn: "", os: "windows" },
        ],
      }),
    ]);
    expect(inv.hunts.find((h) => h.state === "empty")?.bounded).toBe(true);
    for (const h of ["WS01", "WS02"]) expect([...emptySettledClasses(inv, h)]).toEqual([]);
  });

  it("a stopped collect's bounded empty does not weaken another hunt's clean empty", () => {
    const inv = build([partial(), job({ huntId: "H.2", artifacts: [PF], emptyArtifacts: [PF] })]);
    expect([...emptySettledClasses(inv, "WS01")]).toEqual(["execution"]);
  });

  it("a failed collect with no stopped record says nothing: a held mark does not prove an import", () => {
    const inv = build([
      partial({ skippedArtifacts: [{ name: MFT, error: HELD_WHY, notImported: "held" }] }),
      partial({ huntId: "H.9", skippedArtifacts: [{ name: MFT, error: "timeout" }] }),
    ]);
    expect(inv.hunts).toEqual([]);
    expect([...emptySettledClasses(inv, "WS01")]).toEqual([]);
    expect(renderCollectionInventory(inv)).toBe("");
  });
});

describe("the inventory signature and the not-imported mark (#2838)", () => {
  const sig = (j: VeloHuntJob) => inventorySignature(sanitizeHuntJobs([j]));
  const skipped = (notImported?: "held" | "stopped") =>
    job({
      artifacts: [MFT],
      skippedArtifacts: [{ name: MFT, error: "x", ...(notImported ? { notImported } : {}) }],
    });

  it("a job without a mark keeps the signature it had before the mark was read", () => {
    expect(sig(skipped())).toMatchInlineSnapshot(
      `"["H.1","imported",["Windows.NTFS.MFT"],[],["Windows.NTFS.MFT"],[],false,"null","null",[],"{\\"scheduled\\":1,\\"completed\\":1,\\"errors\\":0}","[[\\"C.1\\",\\"WS01\\",\\"\\",\\"windows\\"]]"]"`,
    );
  });

  it("changes when a mark appears, and tells the two marks apart", () => {
    expect(new Set([sig(skipped()), sig(skipped("held")), sig(skipped("stopped"))]).size).toBe(3);
  });
});
