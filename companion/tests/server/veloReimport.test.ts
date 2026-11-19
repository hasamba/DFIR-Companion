import { describe, it, expect, vi } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { planVeloReimport, ledgerTracker, veloReimportGate } from "../../src/routes/veloReimport.js";
import {
  readVeloLedger,
  recordVeloArtifact,
  veloLedgerKey,
  type LedgerEntry,
} from "../../src/routes/veloImportLedger.js";
import type {
  ArtifactFingerprint,
  FlowMeta,
} from "../../src/integrations/velociraptor/veloArtifactFingerprint.js";

// #2700: a re-import reads only what is new, changed or was not read in full.

const SETTINGS = { superOnly: false, minSeverity: "" };
const fp = (hash: string, over: Partial<ArtifactFingerprint> = {}): ArtifactFingerprint => ({
  hash,
  live: false,
  listed: true,
  ...over,
});
const entry = (over: Partial<LedgerEntry> = {}): LedgerEntry => ({
  importedAt: "2026-11-19T10:00:00.000Z",
  status: "complete",
  rows: 5,
  fingerprint: "h1",
  ...SETTINGS,
  ...over,
});

describe("planVeloReimport", () => {
  const plan = (
    e: Record<string, LedgerEntry>,
    fps: Record<string, ArtifactFingerprint> | undefined,
    s = SETTINGS,
  ) => planVeloReimport(e, ["A"], fps, s);

  it.each([
    ["no record", {}, { A: fp("h1") }, "no-record"],
    ["a run that did not finish", { A: entry({ status: "pending" }) }, { A: fp("h1") }, "failed"],
    ["a failed read", { A: entry({ status: "failed" }) }, { A: fp("h1") }, "failed"],
    [
      "a cut-short read",
      { A: entry({ status: "partial", gaps: ["truncated"] }) },
      { A: fp("h1") },
      "truncated",
    ],
    [
      "a partly read artifact",
      { A: entry({ status: "partial", gaps: ["unread"] }) },
      { A: fp("h1") },
      "unread",
    ],
    ["an unknown server state", { A: entry() }, undefined, "unknown"],
    ["an entry with no fingerprint", { A: entry({ fingerprint: undefined }) }, { A: fp("h1") }, "unknown"],
    ["a host still collecting", { A: entry() }, { A: fp("h1", { live: true }) }, "live"],
    ["new rows since", { A: entry() }, { A: fp("h2") }, "changed"],
  ])("imports an artifact with %s", (_l, e, fps, reason) => {
    expect(plan(e as Record<string, LedgerEntry>, fps)).toEqual({
      toImport: [{ name: "A", reason }],
      upToDate: [],
    });
  });

  it("re-imports when the destination or severity floor differs from the recorded run", () => {
    expect(
      plan({ A: entry() }, { A: fp("h1") }, { superOnly: true, minSeverity: "" }).toImport[0].reason,
    ).toBe("settings");
    expect(
      plan({ A: entry() }, { A: fp("h1") }, { superOnly: false, minSeverity: "High" }).toImport[0].reason,
    ).toBe("settings");
  });

  it("skips an artifact read in full whose server state has not changed", () => {
    expect(plan({ A: entry() }, { A: fp("h1") })).toEqual({ toImport: [], upToDate: ["A"] });
  });
});

const FLOWS: FlowMeta[] = [
  {
    clientId: "C.1",
    flowId: "F.A",
    state: "FINISHED",
    rows: 3,
    created: 1,
    started: 2,
    active: 3,
    results: ["A", "B"],
  },
];

async function harness(opts: { meta?: FlowMeta[] | undefined | "throw"; list?: string[] | "throw" } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "dfir-velo-reimport-"));
  const logPath = join(dir, "imports.jsonl");
  const store = { metadataDir: () => dir, importsLogPath: () => logPath };
  const client = {
    sourceNamespace: () => "cfg|root",
    huntFlowMeta: vi.fn(async () => {
      if (opts.meta === "throw") throw new Error("down");
      return "meta" in opts ? opts.meta : FLOWS;
    }),
    flowMeta: vi.fn(async () => FLOWS),
  };
  const list = vi.fn(async () => {
    if (opts.list === "throw") throw new Error("list down");
    return opts.list ?? ["A", "B"];
  });
  const logLine = vi.fn();
  const gate = (reimport: unknown, settings = SETTINGS) =>
    veloReimportGate({
      store,
      caseId: "c1",
      ref: { kind: "hunt", huntId: "H.X" },
      reimport,
      settings,
      client,
      list,
      namesOf: (a: string[]) => a,
      identity: () => ({ kind: "hunt", huntId: "H.X" }),
      notFound: "hunt H.X not found",
      logLine,
    });
  const key = veloLedgerKey("cfg|root", { kind: "hunt", huntId: "H.X" });
  return { dir, store, client, list, gate, key, logLine, logPath };
}

describe("veloReimportGate", () => {
  it("a first import goes ahead with every artifact and tracks them", async () => {
    const h = await harness();
    const g = await h.gate(undefined);
    if ("answer" in g) throw new Error("expected go");
    expect(g.artifacts).toEqual(["A", "B"]);
    expect(g.requested).toEqual(["A", "B"]);
    await g.hooks.onStart?.("A");
    expect((await readVeloLedger(h.store, "c1", h.key)).A.status).toBe("pending");
  });

  it("answers 409 with the plan when the ledger knows the hunt (no audit line needed)", async () => {
    const h = await harness();
    const go = await h.gate(undefined);
    if ("answer" in go) throw new Error("expected go");
    await go.hooks.onStart?.("A");
    await go.hooks.onDone?.("A", { status: "complete", rows: 3 });
    await go.hooks.onStart?.("B");
    await go.hooks.onDone?.("B", { status: "partial", rows: 3, gaps: ["truncated"] });
    const again = await h.gate(undefined);
    if (!("answer" in again)) throw new Error("expected 409");
    expect(again.answer.status).toBe(409);
    expect(again.answer.body).toMatchObject({
      alreadyImported: {
        kind: "hunt",
        huntId: "H.X",
        artifacts: ["A", "B"],
        requested: ["A", "B"],
        toImport: [{ name: "B", reason: "truncated" }],
        upToDate: ["A"],
      },
    });
  });

  it("answers 409 from the audit log alone, every artifact with no record", async () => {
    const h = await harness();
    await writeFile(
      h.logPath,
      JSON.stringify({ originalName: "velo-hunt_H.X_A.json", importedAt: "2026-11-01T00:00:00.000Z" }) + "\n",
    );
    const g = await h.gate(undefined);
    if (!("answer" in g)) throw new Error("expected 409");
    expect(g.answer.body).toMatchObject({
      alreadyImported: {
        firstImportedAt: "2026-11-01T00:00:00.000Z",
        toImport: [
          { name: "A", reason: "no-record" },
          { name: "B", reason: "no-record" },
        ],
      },
    });
  });

  it("still answers 409 (without a plan) when the artifact list cannot be read", async () => {
    const h = await harness({ list: "throw" });
    await recordVeloArtifact(h.store, "c1", h.key, "A", entry());
    const g = await h.gate(undefined);
    if (!("answer" in g)) throw new Error("expected 409");
    expect(g.answer.status).toBe(409);
    expect(
      (g.answer.body as { alreadyImported: { toImport?: unknown } }).alreadyImported.toImport,
    ).toBeUndefined();
  });

  it("an empty artifact list is a 404 with the route's message", async () => {
    const h = await harness({ list: [] });
    const g = await h.gate(undefined);
    if (!("answer" in g)) throw new Error("expected an answer");
    expect(g.answer).toEqual({ status: 404, body: { error: "hunt H.X not found" } });
  });

  it("a failed list with no prior import is the route's error, not a 409", async () => {
    const h = await harness({ list: "throw" });
    await expect(h.gate(undefined)).rejects.toThrow("list down");
  });

  it("an unreachable server fingerprint plans every artifact as unknown", async () => {
    const h = await harness({ meta: "throw" });
    await recordVeloArtifact(h.store, "c1", h.key, "A", entry());
    const g = await h.gate(undefined);
    if (!("answer" in g)) throw new Error("expected 409");
    const body = g.answer.body as { alreadyImported: { toImport: { reason: string }[] } };
    expect(body.alreadyImported.toImport.map((t) => t.reason)).toEqual(["unknown", "no-record"]);
  });

  it("reimport 'changed' imports only the plan's artifacts", async () => {
    const h = await harness();
    const first = await h.gate(true);
    if ("answer" in first) throw new Error("expected go");
    await first.hooks.onStart?.("A");
    await first.hooks.onDone?.("A", { status: "complete", rows: 3 });
    const g = await h.gate("changed");
    if ("answer" in g) throw new Error("expected go");
    expect(g.artifacts).toEqual(["B"]);
    expect(g.requested).toEqual(["A", "B"]);
    expect(g.extra.upToDate).toEqual(["A"]);
  });

  it("reimport 'changed' with nothing to import answers 200 with no job", async () => {
    const h = await harness({ list: ["A"] });
    const first = await h.gate(true);
    if ("answer" in first) throw new Error("expected go");
    await first.hooks.onStart?.("A");
    await first.hooks.onDone?.("A", { status: "complete", rows: 3 });
    const g = await h.gate("changed");
    if (!("answer" in g)) throw new Error("expected an answer");
    expect(g.answer.status).toBe(200);
    expect(g.answer.body).toMatchObject({
      kind: "hunt",
      huntId: "H.X",
      artifacts: [],
      requestedArtifacts: ["A"],
      upToDate: ["A"],
      addedEvents: 0,
      note: "all 1 artifact(s) are up to date — nothing to import",
    });
  });

  it("reimport true re-reads everything even when nothing changed", async () => {
    const h = await harness({ list: ["A"] });
    const first = await h.gate(true);
    if ("answer" in first) throw new Error("expected go");
    await first.hooks.onDone?.("A", { status: "complete", rows: 3 });
    const g = await h.gate(true);
    if ("answer" in g) throw new Error("expected go");
    expect(g.artifacts).toEqual(["A"]);
  });
});

describe("ledgerTracker", () => {
  async function tracker(fps: Record<string, ArtifactFingerprint> | undefined) {
    const dir = await mkdtemp(join(tmpdir(), "dfir-velo-tracker-"));
    const store = { metadataDir: () => dir };
    return { store, t: ledgerTracker(store, "c1", "k", fps, SETTINGS, vi.fn()) };
  }

  it("records pending first, then the outcome with the run's fingerprint and settings", async () => {
    const { store, t } = await tracker({ A: fp("h9") });
    await t.onStart?.("A");
    expect((await readVeloLedger(store, "c1", "k")).A).toMatchObject({
      status: "pending",
      fingerprint: "h9",
    });
    await t.onDone?.("A", { status: "partial", rows: 4, gaps: ["truncated", "unread"] });
    expect((await readVeloLedger(store, "c1", "k")).A).toMatchObject({
      status: "partial",
      rows: 4,
      gaps: ["truncated", "unread"],
      fingerprint: "h9",
      superOnly: false,
      minSeverity: "",
    });
  });

  it("an empty read for an artifact the server lists results for is a failure, not complete", async () => {
    const { store, t } = await tracker({ A: fp("h9", { listed: true }), B: fp("h8", { listed: false }) });
    await t.onDone?.("A", { status: "complete", rows: 0 });
    await t.onDone?.("B", { status: "complete", rows: 0 });
    const l = await readVeloLedger(store, "c1", "k");
    expect(l.A.status).toBe("failed");
    expect(l.B.status).toBe("complete");
  });

  it("never throws: a write failure clears the ledger and logs", async () => {
    const logLine = vi.fn();
    const dir = await mkdtemp(join(tmpdir(), "dfir-velo-tracker-"));
    const notADir = join(dir, "file");
    await writeFile(notADir, "x");
    const store = { metadataDir: () => notADir }; // mkdir under a file fails at once (ENOTDIR)
    const t = ledgerTracker(store, "c1", "k", undefined, SETTINGS, logLine);
    await expect(t.onStart?.("A")).resolves.toBeUndefined();
    await expect(t.onDone?.("A", { status: "complete", rows: 1 })).resolves.toBeUndefined();
    expect(logLine).toHaveBeenCalled();
  });
});
