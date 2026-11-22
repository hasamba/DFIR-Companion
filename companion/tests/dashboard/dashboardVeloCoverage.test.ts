import { describe, expect, it } from "vitest";
import type { VeloCoverageApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-velo-coverage.js — the per-artifact accounting line under a collected hunt.
//
// Three outcomes have to stay distinguishable, or "+3 events" next to a 40-artifact bundle reads as
// "only one artifact worked": an artifact that FAILED to collect, one that returned NOTHING, and one
// that returned rows but was CUT SHORT at the row cap. The third is the dangerous one — it looks
// exactly like success, which is how a THOR scan's 40 warnings went missing behind a green job.
const cov = loadDashboardModule<VeloCoverageApi>("dashboard-velo-coverage.js", ["dashboard-escape.js"]);

const imported = (extra: Record<string, unknown> = {}) => ({
  status: "imported",
  artifacts: ["A.one", "A.two", "A.three"],
  ...extra,
});

describe("veloCoverageHtml", () => {
  it("counts artifacts that returned results, had nothing, and failed", () => {
    const html = cov.veloCoverageHtml(
      imported({ emptyArtifacts: ["A.two"], skippedArtifacts: [{ name: "A.three", error: "too big" }] }),
    );
    expect(html).toContain("1/3 artifact(s) returned results");
    expect(html).toContain("1 had no findings");
    expect(html).toContain("1 failed to collect");
    expect(html).toContain("A.three: too big");
  });

  it("calls out an artifact cut short at the row cap, and names the knob that lifts it", () => {
    const html = cov.veloCoverageHtml(
      imported({ truncatedArtifacts: [{ name: "Generic.Scanner.ThorZIP", kept: 1000, total: 1001 }] }),
    );
    expect(html).toContain("cut short");
    expect(html).toContain("Generic.Scanner.ThorZIP");
    expect(html).toContain("1000");
    expect(html).toContain("DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS");
  });

  // #1982 — the shared super-timeline cap names every artifact it cut, with kept/total rows.
  it("names each artifact the shared super-timeline cap cut, and the knob that lifts it", () => {
    const html = cov.veloCoverageHtml(
      imported({
        superTimelineOnly: true,
        superCappedArtifacts: [
          { name: "Windows.NTFS.MFT", kept: 46000, total: 100000, rows: 90000, cap: 100000 },
          { name: "<b>Usn</b>", kept: 0, total: 5, rows: 5, cap: 100000 },
        ],
      }),
    );
    expect(html).toContain("Windows.NTFS.MFT");
    expect(html).toContain("46000 of 100000 mapped events");
    expect(html).toContain("from 90000 rows");
    expect(html).toContain("0 of 5 mapped events");
    expect(html).toContain("&lt;b&gt;Usn&lt;/b&gt;");
    expect(html).not.toContain("<b>Usn</b>");
    expect(html).toContain("DFIR_SUPERTIMELINE_MAX");
    expect(cov.veloCoverageHtml(imported())).not.toContain("DFIR_SUPERTIMELINE_MAX");
  });

  // #1950 — the cap keeps the first rows in read order, so the line names the time span they cover.
  it("names the kept time span of a cut-short artifact, escaped, when the job stored one", () => {
    const t = { name: "Windows.Forensics.Usn", kept: 1000, total: 1001 };
    const span = { earliest: "2026-09-29T00:00:00Z", latest: "2026-09-29T19:00:00Z" };
    const card = cov.veloCoverageHtml(imported({ truncatedArtifacts: [{ ...t, ...span }] }));
    expect(card).toContain("dated 2026-09-29T00:00:00Z to 2026-09-29T19:00:00Z");
    const gaps = cov.veloReadGapsHtml({ truncated: [{ ...t, earliest: "<i>x</i>", latest: "y" }] }, "Again.");
    expect(gaps).toContain("&lt;i&gt;x&lt;/i&gt;");
    expect(gaps).not.toContain("<i>x</i>");
    expect(cov.veloCoverageHtml(imported({ truncatedArtifacts: [t] }))).not.toContain("dated");
  });

  // #1969 — the cheap fix for a cut-short read is a time scope, so an unscoped hunt is told to use one.
  it("tells an unscoped hunt that was cut short to collect again with a time scope", () => {
    const t = { name: "Windows.Forensics.Usn", kept: 1000, total: 1001 };
    const html = cov.veloCoverageHtml(imported({ truncatedArtifacts: [t] }));
    expect(html).toContain("collect again with a time scope set to the incident window");
    const scoped = cov.veloCoverageHtml(
      imported({ truncatedArtifacts: [t], timeScope: { start: "2026-09-20T00:00:00Z" } }),
    );
    expect(scoped).not.toContain("with a time scope");
    expect(scoped).toContain("DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS");
  });

  it("says a cut-short artifact kept the rows inside the incident window when it was re-read there", () => {
    const t = {
      name: "Windows.Forensics.Usn",
      kept: 40,
      total: 40,
      windowStart: "2026-09-20T00:00:00.000Z",
      windowFull: true,
    };
    const html = cov.veloCoverageHtml(imported({ truncatedArtifacts: [t] }));
    expect(html).toContain("kept all 40 rows inside the incident window 2026-09-20T00:00:00.000Z to now");
    const part = cov.veloCoverageHtml(imported({ truncatedArtifacts: [{ ...t, windowFull: false }] }));
    expect(part).toContain("kept the first 40 rows inside the incident window");
  });

  // #1983 — no incident window: the cut-short read was re-read newest-first by the artifact's own time.
  it("says a cut-short artifact kept the newest rows, by the artifact's own time", () => {
    const t = { name: "Windows.NTFS.MFT", kept: 40, total: 41, order: "newest" };
    const html = cov.veloCoverageHtml(imported({ truncatedArtifacts: [t] }));
    expect(html).toContain("kept the newest 40 rows by file creation time ($FN, else $SI)");
    expect(html).toContain("newest across all hosts");
    expect(html).toContain("undated rows sorted last");
    expect(html).toContain("older rows were not kept");
    const usn = cov.veloCoverageHtml(
      imported({ truncatedArtifacts: [{ ...t, name: "Windows.Forensics.Usn" }] }),
    );
    expect(usn).toContain("kept the newest 40 records by change time");
    const evtx = { ...t, name: "Windows.EventLogs.Evtx", orderPartial: true };
    const ev = cov.veloCoverageHtml(imported({ truncatedArtifacts: [evtx] }));
    expect(ev).toContain("kept the newest 40 events by event time");
    expect(ev).toContain("named sources were not read");
  });

  // The bug this module was extracted to fix: the old inline version only rendered for a bundle of
  // MORE than one artifact, so a single-artifact THOR hunt that was cut short showed a green job and
  // no warning at all.
  it("warns on a SINGLE-artifact hunt that was cut short", () => {
    const html = cov.veloCoverageHtml({
      status: "imported",
      artifacts: ["Generic.Scanner.ThorZIP"],
      truncatedArtifacts: [{ name: "Generic.Scanner.ThorZIP", kept: 1000, total: 1001 }],
    });
    expect(html).toContain("cut short");
    expect(html).toContain("DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS");
  });

  // #1635 — the artifact catalog lookup failed, so rows kept under named sources were never read.
  it("warns on a SINGLE-artifact hunt whose named sources were not read", () => {
    const html = cov.veloCoverageHtml({
      status: "imported",
      artifacts: ["Windows.System.TaskScheduler"],
      unreadArtifacts: [{ name: "Windows.System.TaskScheduler", rows: 0 }],
    });
    expect(html).toContain("0/1 artifact(s) returned results");
    expect(html).toContain("1 not read");
    expect(html).toContain("Windows.System.TaskScheduler");
    expect(html).toContain("Collect again");
  });

  it("counts a partly read artifact as returning results, and still names it", () => {
    const html = cov.veloCoverageHtml(imported({ unreadArtifacts: [{ name: "A.one", rows: 3 }] }));
    expect(html).toContain("3/3 artifact(s) returned results");
    expect(html).toContain("1 not read");
    expect(html).toContain("A.one");
  });

  it("stays quiet for a clean single-artifact hunt, and for a job still running", () => {
    expect(cov.veloCoverageHtml({ status: "imported", artifacts: ["A.one"] })).toBe("");
    expect(cov.veloCoverageHtml({ status: "running", artifacts: ["A.one", "A.two"] })).toBe("");
  });

  it("escapes artifact names and errors", () => {
    const html = cov.veloCoverageHtml(
      imported({ skippedArtifacts: [{ name: "<img src=x>", error: "<script>" }] }),
    );
    expect(html).not.toContain("<img src=x>");
    expect(html).toContain("&lt;img src=x&gt;");
  });

  // #2835 — an artifact that was downloaded but not imported is not a failed fetch. The record says
  // which it is; a record with no mark (a fetch failure, or a job stored before the mark) is a failure.
  const HELD_WHY =
    "held over the hunt artifact size limit (60.0 MB from one PC (limit 50 MB per PC)) — saved in " +
    "_held/H.1/A.two.json; Import anyway or Skip in the dashboard";
  const held = { name: "A.two", error: HELD_WHY, notImported: "held" };
  const stopped = [
    { name: "A.two", error: "Import refused to protect the server.", notImported: "stopped" },
    { name: "A.three", error: "not imported: the collect stopped when A.two failed", notImported: "stopped" },
  ];

  it("lists a held artifact as read but not imported, never as failed to collect", () => {
    const html = cov.veloCoverageHtml(imported({ skippedArtifacts: [held] }));
    expect(html).toContain("2/3 artifact(s) returned results");
    expect(html).toContain("1 read but not imported");
    expect(html).toContain("READ, NOT IMPORTED");
    expect(html).toContain("A.two: held over the hunt artifact size limit");
    expect(html).not.toContain("failed to collect");
  });

  it("shows the block for a collect that stopped partway, with the cut-short warning for what imported", () => {
    const html = cov.veloCoverageHtml({
      status: "error",
      artifacts: ["A.one", "A.two", "A.three"],
      skippedArtifacts: stopped,
      truncatedArtifacts: [{ name: "A.one", kept: 1000, total: 1001 }],
    });
    expect(html).toContain("1/3 artifact(s) returned results");
    expect(html).toContain("2 read but not imported");
    expect(html).toContain("READ, NOT IMPORTED");
    expect(html).toContain("A.two: Import refused to protect the server.");
    expect(html).toContain("A.three: not imported: the collect stopped when A.two failed");
    expect(html).toContain("INCOMPLETE");
    expect(html).not.toContain("failed to collect");
  });

  // #2842 — a collect that failed before it recorded its own results leaves an earlier collect's
  // lists on the job. The block stays, under a line that says whose results they are.
  describe("lists left by an earlier collect (#2842)", () => {
    const LABEL =
      "FROM AN EARLIER COLLECT &mdash; the last collect failed before it recorded its own results.";
    const failedAgain = (extra: Record<string, unknown> = {}) => ({
      status: "error",
      artifacts: ["A.one", "A.two", "A.three"],
      skippedArtifacts: stopped,
      ...extra,
    });

    it("leads the block with the earlier-collect line and keeps every list", () => {
      const html = cov.veloCoverageHtml(failedAgain({ earlierCoverage: true }));
      expect(html.indexOf(LABEL)).toBeGreaterThan(-1);
      expect(html.indexOf(LABEL)).toBeLessThan(html.indexOf("artifact(s) returned results"));
      expect(html).toContain("1/3 artifact(s) returned results");
      expect(html).toContain("READ, NOT IMPORTED");
      expect(html).toContain("A.two: Import refused to protect the server.");
      expect(html).toContain("A.three: not imported: the collect stopped when A.two failed");
    });

    it("does not print it for a collect's own results", () => {
      expect(cov.veloCoverageHtml(failedAgain())).not.toContain("FROM AN EARLIER COLLECT");
    });

    it("leads a held artifact's line with it too", () => {
      const html = cov.veloCoverageHtml(failedAgain({ skippedArtifacts: [held], earlierCoverage: true }));
      expect(html.indexOf(LABEL)).toBe(html.indexOf(">") + 1); // first, in its own line
      expect(html).toContain("A.two: held over the hunt artifact size limit");
    });

    it("never prints alone: a failed collect with nothing to show stays empty", () => {
      const cutOnly = { truncatedArtifacts: [{ name: "A.one", kept: 1000, total: 1001 }] };
      expect(
        cov.veloCoverageHtml(failedAgain({ skippedArtifacts: undefined, ...cutOnly, earlierCoverage: true })),
      ).toBe("");
    });
  });

  it("keeps a failed fetch and a not-imported artifact under their own counts and lists", () => {
    const html = cov.veloCoverageHtml(
      imported({ skippedArtifacts: [{ name: "A.three", error: "too big" }, held] }),
    );
    expect(html).toContain("1/3 artifact(s) returned results");
    expect(html).toContain("1 failed to collect");
    expect(html).toContain("1 read but not imported");
    const [before, after] = html.split("READ, NOT IMPORTED");
    expect(before).toContain("A.three: too big");
    expect(before).not.toContain("A.two: held");
    expect(after).toContain("A.two: held");
    expect(after).not.toContain("A.three: too big");
  });

  it("stays quiet for a collect that failed with nothing marked as read", () => {
    const failedFetch = [{ name: "A.three", error: "too big" }];
    const job = { status: "error", artifacts: ["A.one", "A.two", "A.three"], skippedArtifacts: failedFetch };
    expect(cov.veloCoverageHtml(job)).toBe("");
    expect(cov.veloCoverageHtml({ ...job, truncatedArtifacts: [{ name: "A.one", kept: 1, total: 2 }] })).toBe(
      "",
    );
  });

  // The held list is saved before any import starts, so a collect that then imports NOTHING is an
  // "error" job with a held record: say where that artifact is, and claim nothing about the rest.
  it("names only the held artifact when the collect failed with nothing imported", () => {
    const html = cov.veloCoverageHtml({
      status: "error",
      artifacts: ["A.one", "A.two", "A.three"],
      skippedArtifacts: [held, { name: "A.three", error: "too big" }],
      emptyArtifacts: ["A.one"],
      truncatedArtifacts: [{ name: "A.one", kept: 1000, total: 1001 }],
      unreadArtifacts: [{ name: "A.one", rows: 3 }],
    });
    expect(html).toContain("READ, NOT IMPORTED");
    expect(html).toContain("A.two: held over the hunt artifact size limit");
    expect(html).not.toContain("returned results");
    expect(html).not.toContain("read but not imported");
    expect(html).not.toContain("INCOMPLETE");
    expect(html).not.toContain("NOT READ &mdash;");
    expect(html).not.toContain("had no findings");
    expect(html).not.toContain("too big");
  });

  it("says so when a one-artifact hunt's only artifact is held", () => {
    const html = cov.veloCoverageHtml({ status: "imported", artifacts: ["A.two"], skippedArtifacts: [held] });
    expect(html).toContain("0/1 artifact(s) returned results");
    expect(html).toContain("1 read but not imported");
    expect(html).toContain("READ, NOT IMPORTED");
  });

  it("stays quiet while a collect that holds an artifact is still running", () => {
    const job = { artifacts: ["A.one", "A.two", "A.three"], skippedArtifacts: [held, ...stopped] };
    expect(cov.veloCoverageHtml({ ...job, status: "collecting" })).toBe("");
    expect(cov.veloCoverageHtml({ ...job, status: "running" })).toBe("");
  });

  // #2841 — the server records "cut short" when it READS an artifact, before it decides to hold it or
  // stops the collect. A not-imported artifact has no rows in the case, so it must not sit under
  // INCOMPLETE ("kept N rows") as well: it is listed once, and its line says the read was partial.
  const ALSO_PARTIAL = " (this read was also incomplete: not every row was read)";
  const cutTwo = { name: "A.two", kept: 100000, total: 250000 };

  it("lists a held artifact that was also cut short once, under READ, NOT IMPORTED", () => {
    const html = cov.veloCoverageHtml(imported({ skippedArtifacts: [held], truncatedArtifacts: [cutTwo] }));
    expect(html).toContain("2/3 artifact(s) returned results");
    expect(html).toContain("1 read but not imported");
    expect(html).not.toContain("INCOMPLETE");
    expect(html).not.toContain("cut short at the row cap");
    expect(html).not.toContain("100000");
    expect(html).not.toContain("kept");
    expect(html).toContain(`Import anyway or Skip in the dashboard${ALSO_PARTIAL}`);
    expect(html.split("A.two: ")).toHaveLength(2);
  });

  it("keeps only the imported artifact under INCOMPLETE when a collect stopped partway", () => {
    const html = cov.veloCoverageHtml({
      status: "error",
      artifacts: ["A.one", "A.three", "A.two"],
      skippedArtifacts: stopped,
      truncatedArtifacts: [
        { name: "A.three", kept: 100000, total: 250000 },
        { name: "A.one", kept: 5, total: 9 },
      ],
    });
    expect(html).toContain("1/3 artifact(s) returned results");
    expect(html).toContain("1 cut short at the row cap");
    expect(html).toContain("2 read but not imported");
    const [before, after] = html.split("READ, NOT IMPORTED");
    expect(before).toContain("INCOMPLETE");
    expect(before).toContain("A.one (kept 5 rows, there were more)");
    expect(before).not.toContain("A.three");
    expect(after).toContain(`A.three: not imported: the collect stopped when A.two failed${ALSO_PARTIAL}`);
    expect(after).toContain("A.two: Import refused to protect the server.<br>");
    expect(html).not.toContain("100000");
  });

  it("drops a windowed or newest-first cut record of a held artifact from INCOMPLETE too", () => {
    for (const shape of [
      { windowStart: "2026-01-01T00:00:00Z", windowEnd: "2026-01-02T00:00:00Z", windowFull: true },
      { windowStart: "2026-01-01T00:00:00Z" },
      { order: "newest", orderPartial: true },
    ]) {
      const html = cov.veloCoverageHtml(
        imported({ skippedArtifacts: [held], truncatedArtifacts: [{ ...cutTwo, ...shape }] }),
      );
      expect(html).not.toContain("INCOMPLETE");
      expect(html).not.toContain("cut short at the row cap");
      expect(html).not.toContain("incident window");
      expect(html).not.toContain("kept");
      expect(html).toContain(ALSO_PARTIAL);
    }
  });

  it("adds the note only to the not-imported artifact that was cut short", () => {
    const html = cov.veloCoverageHtml({
      status: "error",
      artifacts: ["A.one", "A.two", "A.three"],
      skippedArtifacts: stopped,
      truncatedArtifacts: [{ name: "A.three", kept: 7, total: 9 }],
    });
    expect(html.split(ALSO_PARTIAL)).toHaveLength(2);
    expect(html).toContain("A.two: Import refused to protect the server.<br>");
    expect(cov.veloCoverageHtml(imported({ skippedArtifacts: [held] }))).not.toContain("also incomplete");
  });

  // Cannot come from the server (a failed fetch is never read, so never cut short) — it pins that only
  // a MARKED record takes an artifact out of INCOMPLETE.
  it("leaves a cut-short artifact under INCOMPLETE when a same-named record is an unmarked failure", () => {
    const html = cov.veloCoverageHtml(
      imported({ skippedArtifacts: [{ name: "A.two", error: "too big" }], truncatedArtifacts: [cutTwo] }),
    );
    expect(html).toContain("INCOMPLETE");
    expect(html).toContain("A.two (kept 100000 rows, there were more)");
    expect(html).toContain("1 cut short at the row cap");
    expect(html).toContain("A.two: too big");
    expect(html).not.toContain("also incomplete");
  });

  it("matches names exactly: a held artifact does not hide a differently-cased cut record", () => {
    const html = cov.veloCoverageHtml(
      imported({ skippedArtifacts: [held], truncatedArtifacts: [{ ...cutTwo, name: "a.two" }] }),
    );
    expect(html).toContain("a.two (kept 100000 rows, there were more)");
    expect(html).not.toContain("also incomplete");
  });

  // NOT READ claims nothing about the case and still matters after Import anyway, so it stays.
  it("still lists a held artifact under NOT READ when its source list could not be read", () => {
    const html = cov.veloCoverageHtml(
      imported({
        skippedArtifacts: [held],
        truncatedArtifacts: [cutTwo],
        unreadArtifacts: [{ name: "A.two", rows: 100000 }],
      }),
    );
    expect(html).toContain("1 not read in full");
    expect(html).toContain("NOT READ &mdash; A.two");
    expect(html).not.toContain("INCOMPLETE");
    expect(html).toContain(ALSO_PARTIAL);
  });

  it("carries the note when the collect failed with nothing imported", () => {
    const html = cov.veloCoverageHtml({
      status: "error",
      artifacts: ["A.one", "A.two", "A.three"],
      skippedArtifacts: [held],
      truncatedArtifacts: [cutTwo],
    });
    expect(html).toContain(`Import anyway or Skip in the dashboard${ALSO_PARTIAL}`);
    expect(html).not.toContain("INCOMPLETE");
    expect(html).not.toContain("returned results");
  });

  it("escapes a not-imported artifact's name on the line that carries the note", () => {
    const name = "<img src=x onerror=1>";
    const skippedArtifacts = [{ name, error: "<script>alert(1)</script>", notImported: "held" }];
    for (const status of ["imported", "error"]) {
      const html = cov.veloCoverageHtml({
        status,
        artifacts: ["A.one", name],
        skippedArtifacts,
        truncatedArtifacts: [{ name, kept: 9, total: 10 }],
      });
      expect(html).toContain(
        `&lt;img src=x onerror=1&gt;: &lt;script&gt;alert(1)&lt;/script&gt;${ALSO_PARTIAL}`,
      );
      expect(html).not.toContain("INCOMPLETE");
      expect(html).not.toContain("<img");
      expect(html).not.toContain("<script>");
    }
  });

  it("escapes a not-imported artifact's name and reason", () => {
    const bad = { name: "<img src=x onerror=1>", error: "<script>alert(1)</script>" };
    for (const job of [
      imported({ skippedArtifacts: [{ ...bad, notImported: "held" }] }),
      {
        status: "error",
        artifacts: ["A.one", "A.two"],
        skippedArtifacts: [{ ...bad, notImported: "stopped" }],
      },
      { status: "error", artifacts: ["A.one", "A.two"], skippedArtifacts: [{ ...bad, notImported: "held" }] },
    ]) {
      const html = cov.veloCoverageHtml(job);
      expect(html).toContain("READ, NOT IMPORTED");
      expect(html).toContain("&lt;img src=x onerror=1&gt;: &lt;script&gt;alert(1)&lt;/script&gt;");
      expect(html).not.toContain("<img");
      expect(html).not.toContain("<script>");
    }
  });
});

// The launch-time half of the same module. SKIPPED artifacts were dropped from the run; UNHELD tools
// dropped nothing — the server just has no file for them yet. Conflating the two would tell an
// analyst a sweep is smaller than it is, or that a run is fine when one unreachable tool will kill it.
describe("veloLaunchNotesHtml", () => {
  it("is empty when nothing was skipped and every tool is on the server", () => {
    expect(cov.veloLaunchNotesHtml({})).toBe("");
    expect(cov.veloLaunchNotesHtml({ unknownArtifacts: [], unheldTools: [] })).toBe("");
  });

  it("names skipped artifacts, both the unknown ones and the ones missing a tool", () => {
    const html = cov.veloLaunchNotesHtml({
      unknownArtifacts: ["Windows.Bogus.Typo"],
      unavailableArtifacts: [{ artifact: "Generic.Scanner.ThorZIP", reason: "no download URL" }],
    });
    expect(html).toContain("skipped 2 artifact(s)");
    expect(html).toContain("Windows.Bogus.Typo");
    expect(html).toContain("Generic.Scanner.ThorZIP: no download URL");
    expect(html).not.toContain("tool(s) were not on this server yet");
  });

  it("warns about tools the server has not fetched WITHOUT calling them skipped", () => {
    const html = cov.veloLaunchNotesHtml({
      unheldTools: [{ tool: "FileYaraWindows", url: "https://example.invalid/y.gz", artifacts: ["A.one"] }],
    });
    expect(html).toContain("1 tool(s) were not on this server yet");
    expect(html).toContain("FileYaraWindows");
    expect(html).toContain("the run will not start");
    expect(html).not.toContain("skipped");
  });

  it("reports both at once, and escapes what the server sent back", () => {
    const html = cov.veloLaunchNotesHtml({
      unknownArtifacts: ["<img src=x>"],
      unheldTools: [{ tool: "<script>", url: "", artifacts: [] }],
    });
    expect(html).toContain("skipped 1 artifact(s)");
    expect(html).toContain("1 tool(s) were not on this server yet");
    expect(html).not.toContain("<img src=x>");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;img src=x&gt;");
  });
});

// The in-flight half of the same module (#770). "collecting" was the ONE status renderVeloJobs had
// no text for, and it is also the one that lasts minutes — so a routine collect, part of it queued
// behind another import, presented as a yellow badge over an empty line and read as a hang.
describe("veloCollectingDetail", () => {
  it("says nothing for a job that is not collecting", () => {
    expect(cov.veloCollectingDetail({ status: "running" })).toBe("");
    expect(cov.veloCollectingDetail({ status: "imported", collectPhase: "importing" })).toBe("");
    expect(cov.veloCollectingDetail(null)).toBe("");
  });

  it("distinguishes waiting for another import from doing the work", () => {
    const queued = cov.veloCollectingDetail({
      status: "collecting",
      collectPhase: "queued",
      collectRows: 171,
    });
    expect(queued).toContain("171 row(s)");
    expect(queued).toContain("waiting for another import");

    const importing = cov.veloCollectingDetail({
      status: "collecting",
      collectPhase: "importing",
      collectRows: 171,
    });
    expect(importing).toContain("importing 171 row(s)");
    expect(importing).not.toContain("waiting");
  });

  it("names Velociraptor while the rows are still being read", () => {
    expect(cov.veloCollectingDetail({ status: "collecting", collectPhase: "fetching" })).toContain(
      "fetching results from Velociraptor",
    );
  });

  // A job written before this field existed, or stranded by a server that died mid-collect. The
  // fallback must still say SOMETHING — an empty line here is the whole bug.
  it("falls back to the first thing a collect does when the phase is missing", () => {
    const html = cov.veloCollectingDetail({ status: "collecting" });
    expect(html).not.toBe("");
    expect(html).toContain("fetching");
  });

  // THE TRAP. A stored "collecting" outlives the process that wrote it, so the phase alone is not
  // permission to describe live work — a server killed mid-collect leaves the job saying "importing"
  // forever. Trading an empty line for a confident lie would be the worse bug.
  it("stops claiming live work once the server says the collect is not running", () => {
    const stranded = cov.veloCollectingDetail({
      status: "collecting",
      collectPhase: "importing",
      collectRows: 171,
      collectActive: false,
    });
    expect(stranded).not.toContain("importing 171");
    expect(stranded).toContain("no longer running");
    expect(stranded).toContain("Collect now");
  });

  // "the server did not say" is what an older payload looks like, and it must not read as "stopped".
  it("keeps describing the phase when liveness is simply absent", () => {
    expect(cov.veloCollectingDetail({ status: "collecting", collectPhase: "importing" })).toContain(
      "importing",
    );
  });

  // A row count is the one number here, and "0 row(s)" is a real answer — a hunt whose artifacts all
  // came back empty. It must not be mistaken for "not known yet".
  it("reports a zero row count, and stays vague when there is no count at all", () => {
    expect(
      cov.veloCollectingDetail({ status: "collecting", collectPhase: "importing", collectRows: 0 }),
    ).toContain("0 row(s)");
    expect(cov.veloCollectingDetail({ status: "collecting", collectPhase: "importing" })).toContain(
      "importing results",
    );
  });
});

// The other half of the same mistake: a stranded collect that cannot be collected again is a hunt no
// analyst can recover from the card, because the status never leaves "collecting" on its own.
describe("veloCanCollect", () => {
  it("offers the button in every status that is not a live collect", () => {
    expect(cov.veloCanCollect({ status: "running" })).toBe(true);
    expect(cov.veloCanCollect({ status: "imported" })).toBe(true);
    expect(cov.veloCanCollect({ status: "error" })).toBe(true);
  });

  it("withholds it from a collect that is really running", () => {
    expect(cov.veloCanCollect({ status: "collecting", collectActive: true })).toBe(false);
    // Liveness absent = the server did not say. Withhold, exactly as before this field existed.
    expect(cov.veloCanCollect({ status: "collecting" })).toBe(false);
  });

  it("offers it to a STRANDED collect, which is the only way back", () => {
    expect(cov.veloCanCollect({ status: "collecting", collectActive: false })).toBe(true);
  });

  it("withholds it where a collect can never help", () => {
    expect(cov.veloCanCollect({ status: "deleted" })).toBe(false);
    expect(cov.veloCanCollect({ status: "unreachable" })).toBe(false);
    expect(cov.veloCanCollect(null)).toBe(false);
  });
});

// #1645 — the external import and the Hunting Profile's live view read hunts too, without a collect.
// They must say "not read in full" the way a collect's hunt card does, with their own next step.
describe("veloReadGapsHtml", () => {
  it("is empty when every read was complete", () => {
    expect(cov.veloReadGapsHtml({}, "Import again.")).toBe("");
    expect(cov.veloReadGapsHtml({ unread: [], truncated: [], failed: [] }, "Import again.")).toBe("");
  });

  it("says NOT READ with the hunt card's own wording and the surface's next step", () => {
    const card = cov.veloCoverageHtml({
      status: "imported",
      artifacts: ["Windows.System.TaskScheduler"],
      unreadArtifacts: [{ name: "Windows.System.TaskScheduler", rows: 0 }],
    });
    const ext = cov.veloReadGapsHtml(
      { unread: [{ name: "Windows.System.TaskScheduler", rows: 0 }] },
      "Import again once the server answers.",
    );
    expect(ext).toContain("NOT READ");
    expect(ext).toContain("No rows here does not mean nothing was found.");
    expect(ext).toContain("Import again once the server answers.");
    expect(ext).not.toContain("Collect again");
    expect(card).toContain(ext.replace("Import again once the server answers.", "Collect again."));
  });

  it("names a read cut short and a read that failed, escaped", () => {
    const html = cov.veloReadGapsHtml(
      {
        truncated: [{ name: "Generic.Scanner.ThorZIP", kept: 1000, total: 1001 }],
        failed: [{ name: "<b>X</b>", error: "timeout" }],
      },
      "Import again.",
    );
    expect(html).toContain("INCOMPLETE");
    expect(html).toContain("Generic.Scanner.ThorZIP (kept 1000 rows");
    expect(html).toContain("FAILED TO READ");
    expect(html).toContain("&lt;b&gt;X&lt;/b&gt;: timeout");
    expect(html).not.toContain("<b>X</b>");
  });
});
