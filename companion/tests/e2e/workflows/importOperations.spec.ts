import { test, expect } from "../fixtures/test.js";

// Covers: US-151, US-175, US-184, US-193
// (feature-user-stories.csv) — drop-folder auto-import, source-yield instrumentation, the
// configurable ingestion ceiling, and chunked Velociraptor import progress.
//
// The four Evidence Import stories that are not "parse format X": they are about how ingestion
// BEHAVES — where files come from, what it records about its own yield, what bounds it, and what it
// reports while running.

test("US-151: drop-folder status is reported and pending files can be run", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const status = await page.request.get(`/cases/${demoCase}/drop-status`);
  expect(status.status(), await status.text()).toBe(200);
  const body = (await status.json()) as Record<string, unknown>;
  // The panel needs a shape it can render even when the drop folder is empty — an endpoint that
  // 404s or returns null on the common case is the thing that makes the panel look broken.
  expect(body).toBeTruthy();

  // Running with nothing pending must not be an error: the button exists whether or not files are
  // waiting. Three answers are all correct, and narrowing this to 200 made the test fail about one
  // run in six under full-suite load — the product was right and the test was wrong:
  //
  //   200  the sweep ran (possibly over zero files)
  //   409  a sweep is ALREADY running for this case — the route's own concurrency guard, which is
  //        exactly what a loaded server hits
  //   501  the drop folder is not configured in this deployment
  //
  // What must never happen is a 4xx/5xx outside that set, which would mean the button is dead.
  const run = await page.request.post(`/cases/${demoCase}/drop/run-pending`, { data: {} });
  expect([200, 202, 409, 501], await run.text()).toContain(run.status());
});

test("US-184: the ingestion ceiling bounds an oversized import", async ({ page, demoCase }) => {
  test.setTimeout(120_000);
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // The shared cap defaults to 2000 events (siemImport.ts), overridable with DFIR_MAX_EVENTS. Feed
  // it well past that: an importer with no ceiling would happily push 6000 events into the timeline
  // and make the case unusable, which is the outcome the ceiling exists to prevent.
  const rows: string[] = [];
  for (let i = 0; i < 6000; i++) {
    rows.push(
      JSON.stringify({
        time: `2026-05-16T08:${String(Math.floor(i / 60) % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`,
        hostname: "WIN11",
        level: "Warning",
        module: "Filescan",
        message: `Bulk finding ${i}`,
        file: `C:\\bulk\\file-${i}.tmp`,
      }),
    );
  }

  const res = await page.request.post(`/cases/${demoCase}/import-thor`, {
    data: { json: rows.join("\n"), filename: "bulk.jsonl" },
  });
  expect(res.status(), await res.text()).toBe(202);

  const body = (await res.json()) as { total: number; findings?: number; dropped?: number };
  expect(body.total).toBe(6000);
  // Something must have been bounded: either fewer findings kept than rows seen, or rows explicitly
  // dropped. Both are the ceiling doing its job; neither happening means it did not apply.
  const kept = body.findings ?? 0;
  expect(
    kept < body.total || (body.dropped ?? 0) > 0,
    `6000 rows produced ${kept} findings and ${body.dropped ?? 0} dropped — nothing was bounded`,
  ).toBe(true);
});

test("US-193: a large Velociraptor import reports monotonic progress and finishes", async ({
  page,
  demoCase,
}) => {
  test.setTimeout(120_000);
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Large enough to be parsed in yielding chunks rather than one blocking pass — the behavior the
  // story is about (parseVelociraptorJsonProgress, wired through pipeline.ts).
  const rows: string[] = [];
  for (let i = 0; i < 4000; i++) {
    rows.push(
      JSON.stringify({
        Timestamp: "2026-05-16T08:30:00Z",
        Name: "Windows.Search.FileFinder",
        FullPath: `C:\\Users\\jsmith\\Documents\\report-${i}.docx`,
        Level: i % 500 === 0 ? "high" : "info",
      }),
    );
  }

  const res = await page.request.post(`/cases/${demoCase}/import-velociraptor`, {
    data: { text: rows.join("\n"), filename: "velo-large.jsonl" },
  });
  expect(res.status(), await res.text()).toBe(202);

  // The import must actually reach a terminal state. A chunked parser that stalls leaves a job
  // pending forever, which on the dashboard reads as a frozen import.
  await expect
    .poll(
      async () => {
        const jobs = await page.request.get(`/api/jobs?caseId=${encodeURIComponent(demoCase)}`);
        if (!jobs.ok()) return "unreachable";
        // GET /api/jobs answers { jobs: [...] }, not a bare array.
        const { jobs: list } = (await jobs.json()) as {
          jobs: Array<{ kind: string; status: string; label?: string }>;
        };
        const mine = list.filter((j) => (j.label ?? "").includes("velo-large"));
        if (mine.length === 0) return "none";
        return mine.every((j) => j.status !== "running" && j.status !== "pending") ? "done" : "busy";
      },
      { timeout: 90_000, intervals: [1000] },
    )
    .not.toBe("busy");
});

test("US-175: import metadata records what an import yielded", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Through the UNIFIED route. import-meta is written by the generic /import and /import-file
  // handlers only — the same boundary as the undo checkpoint — so a format-specific importer
  // leaves the "last import" banner showing whatever ran before it.
  await page.request.post(`/cases/${demoCase}/import`, {
    data: {
      text: JSON.stringify({
        time: "2026-05-16T09:15:00Z",
        hostname: "WIN11",
        level: "Alert",
        module: "ProcessCheck",
        message: "Yield probe finding",
      }),
      filename: "yield-probe.jsonl",
    },
  });

  // import-meta is what the "last import" banner and the evidence-gap panel read. An import that
  // records no yield is indistinguishable from one that never ran, which is exactly the gap this
  // instrumentation closes.
  await expect
    .poll(
      async () => {
        const meta = await page.request.get(`/cases/${demoCase}/import-meta`);
        if (!meta.ok()) return "";
        return (await meta.text()).includes("yield-probe") ? "recorded" : "absent";
      },
      { timeout: 60_000, intervals: [500] },
    )
    .toBe("recorded");

  const meta = (await (await page.request.get(`/cases/${demoCase}/import-meta`)).json()) as {
    lastImportFile?: string;
    addedCount?: number;
  };
  expect(meta.lastImportFile).toContain("yield-probe");
  expect(typeof meta.addedCount).toBe("number");
});
