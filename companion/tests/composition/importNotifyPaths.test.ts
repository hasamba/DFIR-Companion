import { describe, expect, it } from "vitest";
import type { NotificationEvent } from "../../src/analysis/notifications.js";
import { artifactGaps, trackImportOutcome } from "../../src/analysis/importNotification.js";
import {
  notifyHuntCollect,
  notifyHuntFailed,
  notifyUploadsImport,
} from "../../src/composition/veloImportNotify.js";
import { notifyDropSweep, notifyDropSweepFailed } from "../../src/composition/dropImportNotify.js";
import { collectionGaps, notifySiemSearch } from "../../src/routes/importNotify.js";

// #2978 — each import path reports its OWN outcome; these pin what each one says. Synthetic data only.

function recorder() {
  const sent: NotificationEvent[] = [];
  return { sent, dispatch: (e: NotificationEvent) => void sent.push(e) };
}
const logger = { info: () => undefined } as never;
// notifyHuntCollect takes the app's notifier settings, as the collect has them.
const asNotifier = (dispatch: (e: NotificationEvent) => void) => ({
  notifier: { dispatch: async (e: NotificationEvent) => void dispatch(e) } as never,
});

describe("trackImportOutcome", () => {
  it("sends one message per attempt, with the counts of every settle it saw", () => {
    const r = recorder();
    const t = trackImportOutcome(r.dispatch, "c1", "a.evtx");
    t.settled({ timelineDiff: { added: [{ timestamp: "t", description: "d", severity: "High" }] } as never });
    t.settled(null); // a settle that produced nothing adds nothing
    t.finished();
    t.failed(new Error("late")); // the attempt already reported: ignored
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0].title).toBe("Import finished: a.evtx");
    expect(r.sent[0].lines).toContain("Forensic timeline: +1 event (1 High/Critical)");
  });

  it("reports a failure, and whether it can be retried", () => {
    const r = recorder();
    trackImportOutcome(r.dispatch, "c1", "a.csv").failed(new Error("parse error"), true);
    expect(r.sent[0].title).toBe("Import failed: a.csv");
    expect(r.sent[0].lines).toContain("It can be retried from the Jobs list.");
  });
});

describe("Velociraptor uploads-only import", () => {
  it("names the files no importer recognised as failed items", async () => {
    const r = recorder();
    const out = await notifyUploadsImport(
      r.dispatch,
      "c1",
      "velo-flow-uploads_F.EXAMPLE",
      Promise.resolve({
        addedEvents: 2,
        addedIocs: 0,
        imported: ["thor.json"],
        skipped: ["notes.bin"],
        counts: { added: 2, highCritical: 1 },
      }),
    );
    expect(out.imported).toEqual(["thor.json"]); // the result passes through untouched
    expect(r.sent[0].title).toBe("Import finished, 1 failed: velociraptor: velo-flow-uploads_F.EXAMPLE");
    expect(r.sent[0].lines.join("\n")).toContain("Failed: notes.bin — not imported");
  });

  it("reads an uploads-only import where every file was skipped as failed", async () => {
    const r = recorder();
    await notifyUploadsImport(
      r.dispatch,
      "c1",
      "u",
      Promise.resolve({ addedEvents: 0, addedIocs: 0, imported: [], skipped: ["a.json", "b.json"] }),
    );
    expect(r.sent[0].title).toBe("Import failed: velociraptor: u");
    expect(r.sent[0].lines).toContain("Reason: no uploaded file could be imported");
  });

  it("reports a failed import and rethrows", async () => {
    const r = recorder();
    await expect(
      notifyUploadsImport(r.dispatch, "c1", "x", Promise.reject(new Error("refused"))),
    ).rejects.toThrow("refused");
    expect(r.sent[0].title).toBe("Import failed: velociraptor: x");
  });
});

describe("Velociraptor hunt collect", () => {
  const job = { bundleName: "Best Practice", huntId: "H.EXAMPLE", artifacts: ["A", "B", "C"] };

  it("summarises a clean collect under its bundle name", () => {
    const r = recorder();
    notifyHuntCollect(asNotifier(r.dispatch), "c1", job, {
      counts: { added: 40, highCritical: 3, superAdded: 900 },
    });
    expect(r.sent[0].title).toBe("Import finished: velociraptor: Best Practice");
    expect(r.sent[0].lines).toEqual([
      "Files: 3",
      "Forensic timeline: +40 events (3 High/Critical)",
      "Super-timeline: +900 rows",
      "Case: c1",
    ]);
  });

  // A collect that failed partway imported what came before the failure: not "Import failed".
  it("reads a partial collect as finished with its failed artifacts", () => {
    const r = recorder();
    notifyHuntCollect(
      asNotifier(r.dispatch),
      "c1",
      { ...job, error: "server short of memory", skippedArtifacts: [{ name: "C", error: "not imported" }] },
      { counts: { added: 5, highCritical: 0 } },
    );
    expect(r.sent[0].title).toBe("Import finished, 1 failed: velociraptor: Best Practice");
  });

  it("reads a collect that failed with nothing settled as failed", () => {
    const r = recorder();
    notifyHuntCollect(asNotifier(r.dispatch), "c1", { ...job, error: "read failed" }, {});
    expect(r.sent[0].title).toBe("Import failed: velociraptor: Best Practice");
    expect(r.sent[0].lines).toContain("Reason: read failed");
  });

  it("reads a collect whose every artifact failed to download as failed", () => {
    const r = recorder();
    const skippedArtifacts = job.artifacts.map((name) => ({ name, error: "download failed" }));
    notifyHuntCollect(asNotifier(r.dispatch), "c1", { ...job, skippedArtifacts }, {});
    expect(r.sent[0].title).toBe("Import failed: velociraptor: Best Practice");
    expect(r.sent[0].lines).toContain("Reason: no artifact could be read");
  });

  it("names a failed settle, and what its recovery did, as a failed item", () => {
    const r = recorder();
    notifyHuntCollect(
      asNotifier(r.dispatch),
      "c1",
      { ...job, settleWarning: "grading failed; rows were recovered" },
      { counts: { added: 3, highCritical: 0 }, error: "grading failed" },
    );
    expect(r.sent[0].title).toBe("Import finished, 1 failed: velociraptor: Best Practice");
    expect(r.sent[0].lines).toContain(
      "Failed: forensic timeline settle — grading failed; rows were recovered",
    );
  });

  it("names a collect that failed as a whole by its hunt id", () => {
    const r = recorder();
    notifyHuntFailed(r.dispatch, "c1", "H.EXAMPLE", "boom");
    expect(r.sent[0].title).toBe("Import failed: velociraptor: hunt H.EXAMPLE");
  });

  it("lists every kind of gap", () => {
    expect(
      artifactGaps({
        failed: [{ name: "A", error: "e" }],
        truncated: [{ name: "B" }],
        unread: [{ name: "C" }],
      }),
    ).toEqual([
      { name: "A", reason: "e" },
      { name: "B", reason: "cut short at the row cap" },
      { name: "C", reason: "not read in full (source list unknown)" },
    ]);
  });
});

describe("drop folder sweep", () => {
  it("sends nothing for a sweep of screenshots only", () => {
    const r = recorder();
    notifyDropSweep(r.dispatch, "c1", { imported: ["shot.png", "b.JPG"], failed: [] });
    expect(r.sent).toHaveLength(0);
  });

  it("counts evidence files, not screenshots, and lists failures", () => {
    const r = recorder();
    notifyDropSweep(r.dispatch, "c1", {
      imported: ["a.evtx", "shot.png"],
      failed: [{ relpath: "bad.json", reason: "unknown format" }] as never,
    });
    expect(r.sent[0].title).toBe("Import finished, 1 failed: drop folder (2 files)");
    expect(r.sent[0].lines).toContain("Event counts are not available for this import");
  });

  it("reads a sweep where every file failed as failed", () => {
    const r = recorder();
    notifyDropSweep(r.dispatch, "c1", {
      imported: [],
      failed: [{ relpath: "bad.json", reason: "x" }] as never,
    });
    expect(r.sent[0].title).toBe("Import failed: drop folder (1 file)");
  });

  it("reports a sweep-level failure", () => {
    const r = recorder();
    notifyDropSweepFailed(r.dispatch, "c1", new Error("disk"));
    expect(r.sent[0].title).toBe("Import failed: drop folder");
  });
});

describe("cloud collection and SIEM search", () => {
  it("names missing windows and quarantined files as failed items", () => {
    expect(
      collectionGaps({
        missing: [{ source: "audit", reason: "throttled" }],
        quarantined: [{ file: "p1.json", reason: "malformed" }],
      }).failed,
    ).toEqual([
      { name: "audit window", reason: "throttled" },
      { name: "p1.json", reason: "quarantined (malformed)" },
    ]);
    expect(collectionGaps({ missing: [], quarantined: [] })).toEqual({});
  });

  it("reads a SIEM search that found nothing as a known zero, not unknown", () => {
    const r = recorder();
    notifySiemSearch(
      { dispatchNotify: r.dispatch, serverLogger: logger },
      { caseId: "c1", title: "logons" },
      {
        truncated: false,
      },
    );
    expect(r.sent[0].lines).toContain("Forensic timeline: +0 events (0 High/Critical)");
  });

  it("reports a cut-short search and a failed one", () => {
    const r = recorder();
    const ctx = { dispatchNotify: r.dispatch, serverLogger: logger };
    notifySiemSearch(
      ctx,
      { caseId: "c1", title: "q" },
      { truncated: true, counts: { added: 1, highCritical: 0 } },
    );
    notifySiemSearch(ctx, { caseId: "c1", title: "q" }, { truncated: false, failed: "timed out" });
    expect(r.sent[0].title).toBe("Import finished, 1 failed: CrowdStrike NG-SIEM search: q");
    expect(r.sent[1].title).toBe("Import failed: CrowdStrike NG-SIEM search: q");
  });
});
