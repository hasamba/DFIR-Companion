import { describe, it, expect } from "vitest";
import { JobManager } from "../../src/analysis/jobManager.js";
import { externalImportFields, importArtifactsUnderJob } from "../../src/routes/veloExternalImportJob.js";

// The per-artifact loop both external-import branches share (#1428): read one artifact, ingest it,
// release it, and tell the import job where it is — so the Background jobs popover can draw a bar
// and an ETA, and the session log moves.

function deps(lines: string[], statuses: string[] = []) {
  return {
    jobManager: new JobManager({ perCaseConcurrency: 1 }),
    logLine: (m: string) => lines.push(m),
    onAiStatus: (_c: string, e: { status: string }) => statuses.push(e.status),
  };
}

describe("importArtifactsUnderJob", () => {
  it("reports each artifact to the job in order, with its name and row count, then N/N", async () => {
    const lines: string[] = [];
    const d = deps(lines);
    const seen: Array<{ done: number; total: number; detail?: string }> = [];
    const out = await importArtifactsUnderJob(
      d,
      "c1",
      "hunt H.1 (external import)",
      ["A.One", "B.Two"],
      async (art) => ({ rows: art === "A.One" ? [{ x: 1 }, { x: 2 }] : [{ x: 3 }] }),
      async (art) => {
        const job = d.jobManager.list("c1")[0];
        seen.push({ done: job.progress!.done, total: job.progress!.total, detail: job.detail });
        return { addedEvents: art === "A.One" ? 2 : 1, addedIocs: 0 };
      },
    );
    expect(out).toEqual({
      imported: ["A.One", "B.Two"],
      addedEvents: 3,
      addedIocs: 0,
      failed: [],
      truncated: [],
      unread: [],
    });
    expect(seen).toEqual([
      { done: 0, total: 2, detail: "artifact 1/2 · A.One (2 rows)" },
      { done: 1, total: 2, detail: "artifact 2/2 · B.Two (1 rows)" },
    ]);
    const job = d.jobManager.list("c1")[0];
    expect(job.status).toBe("succeeded");
    expect(job.label).toBe("velociraptor: hunt H.1 (external import)"); // reads like the collect's row
    expect(job.progress).toEqual({ done: 2, total: 2 });
    expect(lines.filter((l) => l.includes("importing artifact"))).toHaveLength(2);
  });

  it("skips an artifact whose read fails or returns nothing, and still counts it toward the total", async () => {
    const lines: string[] = [];
    const d = deps(lines);
    const out = await importArtifactsUnderJob(
      d,
      "c1",
      "label",
      ["Bad", "Empty", "Good"],
      async (art) => {
        if (art === "Bad") throw new Error("too large");
        return { rows: art === "Good" ? [{ x: 1 }] : [] };
      },
      async () => ({ addedEvents: 1, addedIocs: 1 }),
    );
    expect(out.imported).toEqual(["Good"]);
    expect(lines.some((l) => l.includes("Bad") && l.includes("too large"))).toBe(true);
    expect(d.jobManager.list("c1")[0].progress).toEqual({ done: 3, total: 3 });
  });

  it("fails the job and rethrows when an ingest throws, so the popover shows the error", async () => {
    const statuses: string[] = [];
    const d = deps([], statuses);
    await expect(
      importArtifactsUnderJob(
        d,
        "c1",
        "label",
        ["A"],
        async () => ({ rows: [{ x: 1 }] }),
        async () => {
          throw new Error("disk full");
        },
      ),
    ).rejects.toThrow("disk full");
    const job = d.jobManager.list("c1")[0];
    expect(job.status).toBe("failed");
    expect(job.error).toBe("disk full");
    expect(statuses.at(-1)).toBe("error");
  });

  it("stops at the next artifact when the analyst cancels the job", async () => {
    const d = deps([]);
    const ingested: string[] = [];
    await expect(
      importArtifactsUnderJob(
        d,
        "c1",
        "label",
        ["A", "B"],
        async () => ({ rows: [{ x: 1 }] }),
        async (art) => {
          ingested.push(art);
          await d.jobManager.cancel(d.jobManager.list("c1")[0].id);
          return { addedEvents: 1, addedIocs: 0 };
        },
      ),
    ).rejects.toThrow(/cancelled/);
    expect(ingested).toEqual(["A"]);
    expect(d.jobManager.list("c1")[0].status).toBe("cancelled");
  });

  it("runs without a job manager (minimal wirings) and still imports", async () => {
    const out = await importArtifactsUnderJob(
      { logLine: () => {} },
      "c1",
      "label",
      ["A"],
      async () => ({ rows: [{ x: 1 }] }),
      async () => ({ addedEvents: 1, addedIocs: 0 }),
    );
    expect(out.imported).toEqual(["A"]);
  });

  // #1645: the collect records these; the external import used to read only `.rows` and drop them.
  it("keeps the not-read, cut-short and failed reads in its outcome, and logs each as it happens", async () => {
    const lines: string[] = [];
    const out = await importArtifactsUnderJob(
      deps(lines),
      "c1",
      "hunt H.1 (external import)",
      ["Unread.Empty", "Unread.Partial", "Cut", "Bad", "Fine"],
      async (art) => {
        if (art === "Bad") throw new Error("too large");
        if (art === "Unread.Empty") return { rows: [], sourcesUnknown: true as const };
        if (art === "Unread.Partial") return { rows: [{ x: 1 }], sourcesUnknown: true as const };
        if (art === "Cut") return { rows: [{ x: 1 }, { x: 2 }], truncated: true, total: 3 };
        return { rows: [{ x: 1 }] };
      },
      async () => ({ addedEvents: 1, addedIocs: 0 }),
    );
    expect(out.imported).toEqual(["Unread.Partial", "Cut", "Fine"]);
    expect(out.unread).toEqual([
      { name: "Unread.Empty", rows: 0 },
      { name: "Unread.Partial", rows: 1 },
    ]);
    expect(out.truncated).toEqual([{ name: "Cut", kept: 2, total: 3 }]);
    expect(out.failed).toEqual([{ name: "Bad", error: "too large" }]);
    expect(lines.some((l) => l.includes("Unread.Empty") && /not read in full/.test(l))).toBe(true);
    expect(lines.some((l) => l.includes("Unread.Partial") && /not read in full/.test(l))).toBe(true);
    expect(lines.some((l) => l.includes("Cut") && /row cap/.test(l))).toBe(true);
  });

  it("logs a not-read artifact even when a later ingest fails the job", async () => {
    const lines: string[] = [];
    await expect(
      importArtifactsUnderJob(
        deps(lines),
        "c1",
        "label",
        ["Unread", "Boom"],
        async (art) =>
          art === "Unread" ? { rows: [], sourcesUnknown: true as const } : { rows: [{ x: 1 }] },
        async () => {
          throw new Error("disk full");
        },
      ),
    ).rejects.toThrow("disk full");
    expect(lines.some((l) => l.includes("Unread") && /not read in full/.test(l))).toBe(true);
  });
});

describe("externalImportFields (#1645)", () => {
  const base = { imported: [], addedEvents: 0, addedIocs: 0, failed: [], truncated: [], unread: [] };

  it("says 'no rows' only when every read was complete", () => {
    const f = externalImportFields(base, ["A", "B"], "the hunt returned no rows yet");
    expect(f).toEqual({
      artifacts: [],
      requestedArtifacts: ["A", "B"],
      note: "the hunt returned no rows yet",
    });
  });

  it("never says 'no rows' when an artifact was not read in full, and names it", () => {
    const f = externalImportFields(
      { ...base, unread: [{ name: "Windows.System.TaskScheduler", rows: 0 }] },
      ["Windows.System.TaskScheduler"],
      "the hunt returned no rows yet",
    );
    expect(f.artifacts).toEqual([]); // `artifacts` means imported, never the requested list
    expect(f.unreadArtifacts).toEqual([{ name: "Windows.System.TaskScheduler", rows: 0 }]);
    expect(f.note).not.toMatch(/returned no rows/);
    expect(f.note).toMatch(/not read in full/);
    expect(f.note).toMatch(/not evidence/);
  });

  it("never says 'no rows' when every read failed", () => {
    const f = externalImportFields(
      { ...base, failed: [{ name: "A", error: "timeout" }] },
      ["A"],
      "the hunt returned no rows yet",
    );
    expect(f.note).not.toMatch(/returned no rows/);
    expect(f.failedArtifacts).toEqual([{ name: "A", error: "timeout" }]);
  });

  it("carries the gaps with no note when rows did import", () => {
    const f = externalImportFields(
      {
        ...base,
        imported: ["A"],
        truncated: [{ name: "A", kept: 2, total: 3 }],
        unread: [{ name: "B", rows: 0 }],
      },
      ["A", "B"],
      "the hunt returned no rows yet",
    );
    expect(f).toEqual({
      artifacts: ["A"],
      requestedArtifacts: ["A", "B"],
      truncatedArtifacts: [{ name: "A", kept: 2, total: 3 }],
      unreadArtifacts: [{ name: "B", rows: 0 }],
    });
  });
});
