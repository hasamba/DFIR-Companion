// #3008 — a SO-CRATES submission (one file, or every entry of one archive) sends ONE "Import
// finished" / "Import failed" message when its last job settles. Synthetic data only.
import { describe, expect, it } from "vitest";
import type { NotificationEvent } from "../../src/analysis/notifications.js";
import type { SocratesJob } from "../../src/integrations/socrates/socratesJobStore.js";
import { createSocratesSubmissionTracker } from "../../src/composition/socratesImportNotify.js";

function recorder() {
  const sent: NotificationEvent[] = [];
  return { sent, dispatch: (e: NotificationEvent) => void sent.push(e) };
}

const job = (jobId: string, over: Partial<SocratesJob> = {}): SocratesJob => ({
  jobId,
  md5: `md5-${jobId}`,
  sourceName: "sample.zip",
  status: "processing",
  startedAt: "2026-01-01T00:00:00.000Z",
  submissionId: "sub-1",
  ...over,
});
const imported = (j: SocratesJob): SocratesJob => ({ ...j, status: "imported" });
const failed = (j: SocratesJob, error: string): SocratesJob => ({ ...j, status: "error", error });

describe("SO-CRATES submission messages (#3008)", () => {
  it("a single file sends one Import finished message with its counts", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    const a = job("a", { sourceName: "one.pcap" });
    t.open("c1", "sub-1", "one.pcap");
    t.add("c1", a);
    t.seal("c1", "sub-1");
    expect(r.sent).toHaveLength(0); // still running
    t.settle("c1", imported(a), { added: 4, highCritical: 1 });
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0].title).toBe("Import finished: SO-CRATES: one.pcap");
    expect(r.sent[0].lines).toContain("Forensic timeline: +4 events (1 High/Critical)");
    expect(r.sent[0].lines.some((l) => l.startsWith("Files:"))).toBe(false);
  });

  it("an archive with several entries sends one message for the whole submission", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    const entries = ["a", "b", "c"].map((id) => job(id, { zipEntry: `sample.zip!${id}.evtx` }));
    t.open("c1", "sub-1", "sample.zip");
    for (const e of entries) t.add("c1", e);
    t.seal("c1", "sub-1");
    t.settle("c1", imported(entries[0]), { added: 2, highCritical: 0 });
    t.settle("c1", imported(entries[1]), { added: 3, highCritical: 2, superAdded: 1 });
    expect(r.sent).toHaveLength(0);
    t.settle("c1", imported(entries[2]), { added: 1, highCritical: 1 });
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0].title).toBe("Import finished: SO-CRATES: sample.zip");
    expect(r.sent[0].lines).toContain("Files: 3");
    expect(r.sent[0].lines).toContain("Forensic timeline: +6 events (3 High/Critical)");
    // Only one entry knew its super-timeline rows, so no total is claimed for them.
    expect(r.sent[0].lines.some((l) => l.startsWith("Super-timeline"))).toBe(false);
  });

  it("an entry that finishes before the next one is launched does not close the submission", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    const a = job("a");
    const b = job("b");
    t.open("c1", "sub-1", "sample.zip");
    t.add("c1", a);
    t.settle("c1", imported(a), { added: 1, highCritical: 0 });
    expect(r.sent).toHaveLength(0);
    t.add("c1", b);
    t.seal("c1", "sub-1");
    t.settle("c1", imported(b), { added: 1, highCritical: 0 });
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0].lines).toContain("Files: 2");
  });

  it("a partial failure reads finished, N failed, with the failed entry named", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    const a = job("a", { zipEntry: "sample.zip!a.evtx" });
    const b = job("b", { zipEntry: "sample.zip!b.evtx" });
    t.open("c1", "sub-1", "sample.zip");
    t.add("c1", a);
    t.add("c1", b);
    t.seal("c1", "sub-1");
    t.settle("c1", imported(a), { added: 5, highCritical: 0 });
    t.settle("c1", failed(b, "analysis timed out"));
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0].title).toBe("Import finished, 1 failed: SO-CRATES: sample.zip");
    expect(r.sent[0].lines).toContain("Forensic timeline: +5 events (0 High/Critical)");
    expect(r.sent[0].lines).toContain("Failed: sample.zip!b.evtx — analysis timed out");
  });

  it("every entry failing sends one Import failed message", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    const a = job("a", { sourceName: "one.pcap" });
    t.open("c1", "sub-1", "one.pcap");
    t.add("c1", a);
    t.seal("c1", "sub-1");
    t.settle("c1", failed(a, "SO-CRATES reported an analysis failure"));
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0].title).toBe("Import failed: SO-CRATES: one.pcap");
    expect(r.sent[0].lines).toContain("Reason: SO-CRATES reported an analysis failure");
  });

  it("counts that are unknown read 'not available', never zero", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    const a = job("a");
    const b = job("b");
    t.open("c1", "sub-1", "sample.zip");
    t.add("c1", a);
    t.add("c1", b);
    t.seal("c1", "sub-1");
    t.settle("c1", imported(a), { added: 2, highCritical: 0 });
    t.settle("c1", imported(b)); // this entry's counts are unknown
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0].lines).toContain("Event counts are not available for this import");
    expect(r.sent[0].lines.some((l) => l.startsWith("Forensic timeline"))).toBe(false);
  });

  it("never sends twice: a second settle of the same job, or of a reported submission, is ignored", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    const a = job("a");
    t.open("c1", "sub-1", "sample.zip");
    t.add("c1", a);
    t.seal("c1", "sub-1");
    t.settle("c1", imported(a), { added: 1, highCritical: 0 });
    t.settle("c1", imported(a), { added: 1, highCritical: 0 });
    t.settle("c1", failed(a, "late"));
    t.seal("c1", "sub-1");
    expect(r.sent).toHaveLength(1);
  });

  it("an upload loop that stopped partway still reports what was launched, naming the rest", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    const a = job("a");
    t.open("c1", "sub-1", "sample.zip");
    t.add("c1", a);
    t.seal("c1", "sub-1", { name: "entries not submitted", reason: "upload refused" });
    t.settle("c1", imported(a), { added: 1, highCritical: 0 });
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0].title).toBe("Import finished, 1 failed: SO-CRATES: sample.zip");
    expect(r.sent[0].lines).toContain("Failed: entries not submitted — upload refused");
  });

  it("a submission that launched nothing sends nothing (its submitter reports the failure)", () => {
    const r = recorder();
    const t = createSocratesSubmissionTracker(r.dispatch);
    t.open("c1", "sub-1", "sample.zip");
    t.seal("c1", "sub-1", { name: "entries not submitted", reason: "upload refused" });
    expect(r.sent).toHaveLength(0);
  });

  describe("startup recovery", () => {
    it("two interrupted entries of one archive send one Import failed message", () => {
      const r = recorder();
      const t = createSocratesSubmissionTracker(r.dispatch);
      const a = job("a", { status: "importing", zipEntry: "sample.zip!a" });
      const b = job("b", { status: "importing", zipEntry: "sample.zip!b" });
      t.adopt("c1", [a, b]);
      t.settle("c1", failed(a, "interrupted"));
      expect(r.sent).toHaveLength(0);
      t.settle("c1", failed(b, "interrupted"));
      expect(r.sent).toHaveLength(1);
      expect(r.sent[0].title).toBe("Import failed: SO-CRATES: sample.zip");
      expect(r.sent[0].lines).toContain("Failed: sample.zip!a — interrupted");
    });

    it("a resumed entry and an interrupted one send one message when the resumed one ends", () => {
      const r = recorder();
      const t = createSocratesSubmissionTracker(r.dispatch);
      const a = job("a", { status: "processing" });
      const b = job("b", { status: "importing" });
      t.adopt("c1", [a, b]);
      t.settle("c1", failed(b, "interrupted"));
      expect(r.sent).toHaveLength(0);
      t.settle("c1", imported(a), { added: 1, highCritical: 0 });
      expect(r.sent).toHaveLength(1);
      expect(r.sent[0].title).toBe("Import finished, 1 failed: SO-CRATES: sample.zip");
    });

    it("an entry that finished before the restart is part of the message, with counts unknown", () => {
      const r = recorder();
      const t = createSocratesSubmissionTracker(r.dispatch);
      const a = imported(job("a"));
      const b = job("b", { status: "processing" });
      t.adopt("c1", [a, b]);
      t.settle("c1", imported(b), { added: 3, highCritical: 0 });
      expect(r.sent).toHaveLength(1);
      expect(r.sent[0].lines).toContain("Files: 2");
      expect(r.sent[0].lines).toContain("Event counts are not available for this import");
    });

    it("a finished submission and one this process already drives are not adopted", () => {
      const r = recorder();
      const t = createSocratesSubmissionTracker(r.dispatch);
      const live = job("live", { submissionId: "sub-live" });
      t.open("c1", "sub-live", "sample.zip");
      t.add("c1", live);
      t.adopt("c1", [imported(job("old", { submissionId: "sub-old" })), live]);
      t.settle("c1", imported(job("old", { submissionId: "sub-old" })));
      expect(r.sent).toHaveLength(0); // the old submission was already reported
      t.settle("c1", imported(live), { added: 1, highCritical: 0 });
      expect(r.sent).toHaveLength(0); // still open: its submitter has not sealed it
      t.seal("c1", "sub-live");
      expect(r.sent).toHaveLength(1);
    });

    it("a job written before #3008 (no submission id) is its own submission", () => {
      const r = recorder();
      const t = createSocratesSubmissionTracker(r.dispatch);
      const a = job("a", { submissionId: undefined, status: "importing" });
      const b = job("b", { submissionId: undefined, status: "importing" });
      t.adopt("c1", [a, b]);
      t.settle("c1", failed(a, "interrupted"));
      t.settle("c1", failed(b, "interrupted"));
      expect(r.sent).toHaveLength(2);
    });
  });
});
