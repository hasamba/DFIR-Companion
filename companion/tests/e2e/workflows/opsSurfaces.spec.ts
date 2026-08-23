import { test, expect } from "../fixtures/test.js";

// Covers: US-254, US-261, US-266, US-291, US-312, US-313, US-337, US-338, US-341
// (feature-user-stories.csv) — the operational surfaces an analyst leans on mid-case: the
// analysis-run manifest, playbook matching, hypothesis tracking, the collection plan's override
// round-trip, clock-skew recompute, hunt-execution cancel, cockpit card actions, and the
// diagnostics/support-bundle view.
//
// Everything here is deterministic on the seeded case — no live model (the stub answers
// synthesis), no external service, no timing dependence. Shapes were probed against a running
// harness before being pinned, not assumed from the source.
//
// Deliberately NOT here:
//   - US-340 (release pack download): the release workflow starts at workflow/submit, which
//     answers 409 "peer review requires team authentication" — and this harness runs team auth
//     off by design. The reachable refusals are asserted below without claiming the story.
//   - US-339 (hunt-execution cancel): the story is cancelling an execution IN PROGRESS, and this
//     harness has no hunt backend to keep one in progress — the stubbed work finishes before a
//     cancel could land. The boundary below (cancel-after-end refuses honestly) is asserted
//     without claiming the story.
//   - US-258 (clock-skew DETECTION): needs ≥3 correlated cross-host anchor events with a real
//     offset, which means engineering a skewed multi-host fixture; the detector itself is
//     unit-covered. What is pinned here is US-338, the recompute route, whose groupsExamined
//     proves it re-measured the timeline.

test("US-254: every stub synthesis leaves a reproducible run manifest", async ({ page, demoCase }) => {
  const synth = await page.request.post(`/cases/${demoCase}/synthesize`, { data: {} });
  expect(synth.status(), await synth.text()).toBe(200);

  const res = await page.request.get(`/cases/${demoCase}/analysis-runs`);
  expect(res.status(), await res.text()).toBe(200);
  const runs = (await res.json()) as Array<{
    id: string;
    kind: string;
    status: string;
    configuration?: { promptHash?: string; provider?: string; model?: string };
  }>;
  expect(runs.length, "the synthesis just requested must be on the ledger").toBeGreaterThan(0);

  const synthesis = runs.find((r) => r.kind === "synthesis" && r.status === "completed");
  expect(synthesis, "a completed synthesis run is recorded").toBeTruthy();
  // The manifest's whole point is reproducibility: without the prompt hash and the exact
  // provider/model there is nothing to diff a later run against.
  expect(synthesis?.configuration?.promptHash ?? "").toMatch(/^[0-9a-f]{64}$/);
  expect(synthesis?.configuration?.provider).toBe("openai");
  expect(synthesis?.configuration?.model).toBe("stub-model");

  // "…so a past run can be REPLAYED later" is half the story, so it is driven too: replaying the
  // manifest is accepted and the new run is chained to its parent — the link a later diff needs.
  const replayed = await page.request.post(
    `/cases/${demoCase}/analysis-runs/${(synthesis as { id: string }).id}/replay`,
    { data: {} },
  );
  expect(replayed.status(), await replayed.text()).toBe(200);
  const receipt = (await replayed.json()) as { accepted: boolean; parentRunId: string };
  expect(receipt.accepted).toBe(true);
  expect(receipt.parentRunId).toBe((synthesis as { id: string }).id);
});

test("US-261: the seeded case's techniques rank against named ransomware playbooks, offline", async ({
  page,
  demoCase,
}) => {
  const res = await page.request.get(`/cases/${demoCase}/playbook-match`);
  expect(res.status(), await res.text()).toBe(200);
  const { matches } = (await res.json()) as {
    matches: Array<{ name: string; score?: number; reference?: string }>;
  };
  // The seeded case ships Cobalt Strike + LSASS + lateral-movement techniques precisely so that
  // known intrusion playbooks match. Zero matches would mean the matcher lost the seeded case,
  // which is the regression this test exists to catch.
  expect(matches.length, "the seeded techniques must match at least one known playbook").toBeGreaterThan(0);
  const names = matches.map((m) => m.name);
  // Conti is the canonical seeded match (probed, not assumed). Pinning one name catches the
  // matcher returning *something* while the ranking logic is broken.
  expect(names, `got: ${names.join(", ")}`).toContain("Conti");
  // Each match must carry a public reference — the analyst is expected to hand this to an IR
  // lead, and an unreferenced claim about a named actor is not usable in a report.
  for (const m of matches) expect(m.reference ?? "", `${m.name} reference`).toMatch(/^https:\/\//);
});

test("US-266: a hypothesis keeps its identity and status through a re-synthesis", async ({
  page,
  demoCase,
}) => {
  const created = await page.request.post(`/cases/${demoCase}/hypotheses`, {
    data: { title: "Initial access was phishing", status: "open" },
  });
  expect(created.status(), await created.text()).toBe(201);
  const hypothesis = (await created.json()) as { id: string; status: string };
  expect(hypothesis.id).toBeTruthy();

  const advanced = await page.request.patch(`/cases/${demoCase}/hypotheses/${hypothesis.id}`, {
    data: { status: "supported" },
  });
  expect(advanced.status(), await advanced.text()).toBe(200);

  // THE CLAIM: "survives re-synthesis". A synthesis replaces findings and techniques wholesale;
  // if it also replaced the hypothesis ledger, the analyst's investigative state would silently
  // reset every time the AI ran.
  const synth = await page.request.post(`/cases/${demoCase}/synthesize`, { data: {} });
  expect(synth.status(), await synth.text()).toBe(200);

  const after = await page.request.get(`/cases/${demoCase}/hypotheses`);
  expect(after.status()).toBe(200);
  const list = (await after.json()) as Array<{ id: string; status: string; title: string }>;
  const survivor = list.find((h) => h.id === hypothesis.id);
  expect(survivor, "the hypothesis vanished across a synthesis").toBeTruthy();
  expect(survivor?.status, "the analyst's verdict was reset").toBe("supported");
});

test("US-337: a collection-plan override is set, then cleared back to the automatic state", async ({
  page,
  demoCase,
}) => {
  // The plan derives from the case's incident type; a case without one has no plan at all, so the
  // type is set first — through the same route the dashboard uses.
  const typed = await page.request.post(`/cases/${demoCase}/incident-type`, {
    data: { typeId: "ransomware" },
  });
  expect(typed.status(), await typed.text()).toBe(200);

  const planOf = async (): Promise<Array<{ id: string; state: string; reason: string }>> => {
    const res = await page.request.get(`/cases/${demoCase}/collection-plan`);
    expect(res.status(), await res.text()).toBe(200);
    const body = (await res.json()) as {
      plan: { steps: Array<{ id: string; state: string; reason: string }> };
    };
    return body.plan?.steps ?? [];
  };

  const before = await planOf();
  expect(before.length, "the ransomware plan must have steps").toBeGreaterThan(0);
  // The EDR step is auto-satisfied by the seeded evidence, which is what makes DELETE meaningful:
  // clearing the override must RETURN to that derived state, not to a blank.
  const edr = before.find((s) => s.id === "edr");
  expect(edr, "the ransomware plan carries an edr step").toBeTruthy();
  const automaticState = (edr as { state: string }).state;

  const overridden = await page.request.put(`/cases/${demoCase}/collection-plan/edr`, {
    data: { state: "na", reason: "no EDR was deployed at this site" },
  });
  expect(overridden.status(), await overridden.text()).toBe(200);
  const mid = (await planOf()).find((s) => s.id === "edr");
  // Overrides are stored marked ("override-na"), so the UI can tell an analyst's call apart from
  // a derived state — asserting bare "na" here was wrong in a way that mattered.
  expect(mid?.state).toBe("override-na");
  expect(mid?.reason).toContain("no EDR");

  const cleared = await page.request.delete(`/cases/${demoCase}/collection-plan/edr`);
  expect(cleared.status(), await cleared.text()).toBe(200);
  const after = (await planOf()).find((s) => s.id === "edr");
  // Back to automatic — the state the evidence derives, not "na" and not a reset blank.
  expect(after?.state, "DELETE must restore the derived state").toBe(automaticState);
  expect(after?.reason ?? "").toBe("");

  // An unknown step refuses rather than storing an orphan override.
  const ghost = await page.request.put(`/cases/${demoCase}/collection-plan/no-such-step`, {
    data: { state: "na" },
  });
  expect(ghost.status()).toBe(404);
});

test("US-338: clock-skew recompute re-measures the current timeline", async ({ page, demoCase }) => {
  const res = await page.request.post(`/cases/${demoCase}/clock-skew/recompute`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { results: unknown[]; groupsExamined?: number; detectedAt: string };
  // groupsExamined is what separates "it ran over the case" from "it answered a cached shape".
  expect(body.groupsExamined ?? 0, "recompute must actually examine the timeline").toBeGreaterThan(0);
  expect(Date.parse(body.detectedAt), "recompute stamps when it measured").not.toBeNaN();
  // The seeded case is single-clock-consistent, so the CORRECT answer is no skew. A result here
  // would be a false positive against known-good data.
  expect(body.results, "consistent seeded clocks must not report skew").toHaveLength(0);
});

test("US-339 boundary: cancelling a hunt execution that is not running refuses rather than pretending", async ({
  page,
  demoCase,
}) => {
  // Real executions need a live hunt backend; what every dashboard build relies on is the other
  // half of the contract — a cancel click landing after the execution ended must say so, not
  // answer 202 and leave the analyst believing they stopped something.
  const res = await page.request.post(`/cases/${demoCase}/hunt-query/executions/never-ran/cancel`);
  expect(res.status(), await res.text()).toBe(404);
  expect(((await res.json()) as { error?: string }).error ?? "").toContain("active execution");
});

test("US-341: a cockpit lead card pins, and the decision is attributed", async ({ page, demoCase }) => {
  const cockpit = await page.request.get(`/cases/${demoCase}/cockpit`);
  expect(cockpit.status(), await cockpit.text()).toBe(200);
  const body = (await cockpit.json()) as {
    investigator: string;
    sections: Record<string, Array<{ id: string; kind: string }>>;
  };
  // The seeded case's confirmed Cobalt Strike finding surfaces as a lead card deterministically —
  // that exact card is the pin target, so the test fails if the cockpit stops deriving leads.
  const lead = (body.sections.leads ?? []).find((c) => c.id === "lead:finding:f001");
  expect(lead, "the seeded case's f001 lead card is missing from the cockpit").toBeTruthy();

  const pinned = await page.request.patch(`/cases/${demoCase}/cockpit/cards/lead:finding:f001`, {
    data: { action: "pin" },
  });
  expect(pinned.status(), await pinned.text()).toBe(200);
  const decision = (await pinned.json()) as { decision: { pinned: boolean; updatedBy: string } };
  expect(decision.decision.pinned).toBe(true);
  // Attribution is the forensic half: a pin nobody signed is a decision nobody owns.
  expect(decision.decision.updatedBy).toBe(body.investigator);

  // The guard rails the dashboard depends on: an unknown action and an unknown card both refuse.
  const badAction = await page.request.patch(`/cases/${demoCase}/cockpit/cards/lead:finding:f001`, {
    data: { action: "explode" },
  });
  expect(badAction.status()).toBe(400);
  const badCard = await page.request.patch(`/cases/${demoCase}/cockpit/cards/no:such:card`, {
    data: { action: "pin" },
  });
  expect(badCard.status()).toBe(404);
});

test("US-340 boundary: release packs refuse cleanly — unknown pack, unknown release, auth-gated workflow", async ({
  page,
  demoCase,
}) => {
  // NOT a claim on US-340 (see the header): the signed-release happy path is team-auth-gated and
  // covered by the Supertest suites. These are the refusals the dashboard must survive.
  const badPack = await page.request.get(`/cases/${demoCase}/report-releases/any/packs/exe`);
  expect(badPack.status(), await badPack.text()).toBe(400);

  const ghostRelease = await page.request.get(`/cases/${demoCase}/report-releases/ghost/packs/ioc`);
  expect(ghostRelease.status(), await ghostRelease.text()).toBe(404);

  const submit = await page.request.post(`/cases/${demoCase}/report-versions/v1/workflow/submit`, {
    data: { reviewerId: "nobody" },
  });
  expect(submit.status(), await submit.text()).toBe(409);
  expect(((await submit.json()) as { error?: string }).error ?? "").toContain("team authentication");
});

test("US-291 / US-312 / US-313: diagnostics carries import counters, capacity samples and the support bundle", async ({
  page,
  demoCase,
}) => {
  const readDiag = async (): Promise<{
    report: {
      operational: {
        sampleCount: number;
        imports: { runs: number; rowsRead: number };
        capacity: { databaseBytes: number; diskFreeBytes: number };
      };
    };
    supportFilename: string;
    supportPreview: string;
  }> => {
    const res = await page.request.get(`/diagnostics`);
    expect(res.status(), await res.text()).toBe(200);
    return (await res.json()) as never;
  };

  const before = await readDiag();

  // US-291: the counter is global and monotone, so "my import raised it" holds under parallel
  // workers — others can only raise it further.
  const runsBefore = before.report.operational.imports.runs;
  const rowsBefore = before.report.operational.imports.rowsRead;
  const imported = await page.request.post(`/cases/${demoCase}/import`, {
    data: {
      filename: "ops-probe.jsonl",
      text: JSON.stringify({
        time: "2026-06-01T10:00:00Z",
        hostname: "OPS-PROBE",
        level: "Warning",
        module: "Filescan",
        message: "ops diagnostics probe",
        file: "C:\\Temp\\ops-probe.ps1",
        reason_1: "YARA rule SUSP_PS1",
      }),
    },
  });
  expect(imported.status(), await imported.text()).toBe(202);

  await expect
    .poll(async () => (await readDiag()).report.operational.imports.runs, { timeout: 15_000 })
    .toBeGreaterThan(runsBefore);
  // "…recorded with row counts": the one-line file must add exactly its row count's worth. Only a
  // lower bound is claimable under parallel workers, but rowsRead unchanged would mean the counter
  // counts runs and not rows.
  expect((await readDiag()).report.operational.imports.rowsRead).toBeGreaterThan(rowsBefore);
  // NOT asserted: the story's "including empty/failed ones". Observed against the live harness: a
  // file no importer recognises falls back to the AI log path, and with analysis skipped that
  // attempt did NOT move any counter. The story text is stronger than the behavior; recorded here
  // the way US-286 records its own story-vs-code divergence, rather than pinned as either side.

  // US-312: capacity is sampled from boot, so real numbers must already be here — zero samples
  // would mean the sampler never started, which is exactly the silent failure the story names.
  const after = await readDiag();
  expect(after.report.operational.sampleCount).toBeGreaterThan(0);
  expect(after.report.operational.capacity.databaseBytes).toBeGreaterThan(0);
  expect(after.report.operational.capacity.diskFreeBytes).toBeGreaterThan(0);

  // US-313: the support bundle is offered as a file the analyst downloads and attaches to a bug
  // report — the preview must parse as JSON and carry the version, or the bundle is dead weight.
  expect(after.supportFilename).toMatch(/^dfir-companion-support-\d{4}-\d{2}-\d{2}\.json$/);
  const bundle = JSON.parse(after.supportPreview) as {
    application?: { version?: string };
    system?: { disk?: unknown; ai?: unknown };
  };
  expect(bundle.application?.version, "the bundle must name the version being reported").toBeTruthy();
  expect(bundle.system?.disk, "the bundle must carry disk state").toBeTruthy();
  expect(bundle.system?.ai, "the bundle must carry the AI error breakdown").toBeTruthy();
});

test("update-check defaults to off and discloses that nothing was checked", async ({ page }) => {
  // NOT a claim on US-314: the notice itself needs a GitHub round-trip this suite must never
  // make. What IS pinned is the OPSEC default the story promises — no phone-home unless the
  // analyst opts in, and an honest "never checked" state rather than a fabricated verdict.
  const res = await page.request.get(`/update-check`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { enabled: boolean; checkedAt: string | null; latest: string | null };
  expect(body.enabled, "update checking must be opt-in").toBe(false);
  expect(body.checkedAt, "nothing may have been checked without opt-in").toBeNull();
  expect(body.latest).toBeNull();
});
