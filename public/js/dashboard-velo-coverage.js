// Per-artifact accounting for a collected Velociraptor hunt (#385 file-size ledger: extracted from
// dashboard-velo-triage.js rather than grown inside it).
//
// Without this line, "+3 events" next to a 40-artifact bundle reads as "only one artifact worked",
// with no way to tell why the rest are missing. Three outcomes must stay distinguishable:
//
//   failed     — the fetch errored (oversized/timeout). Loud already.
//   empty      — fetched cleanly, nothing to report. Not a problem.
//   CUT SHORT  — returned rows AND hit the row cap, so an unknown number of findings were never read.
//
// The third is the one worth the screen space, because it is the one that looks exactly like success.
// A THOR scan opens with ~1000 lines of startup chatter before it reports anything, so the old
// 1000-row cap ended a real scan mid-run: 40 warnings never left the server and the job went green.
// It is also why this renders for a SINGLE-artifact hunt, which the multi-artifact coverage line
// deliberately skips — a one-artifact THOR hunt is exactly the case that showed no warning at all.

/* exported veloCoverageHtml */
function veloCoverageHtml(job) {
  const cut = job.truncatedArtifacts || [];
  const failed = job.skippedArtifacts || [];
  const empty = job.emptyArtifacts || [];
  const total = (job.artifacts || []).length;
  if (job.status !== "imported" || (total <= 1 && !cut.length)) return "";

  const box = (body, color) =>
    `<div data-safe-style="font-size:12px;color:${color};margin-top:2px">${body}</div>`;
  const tint = (text, color) => `<span data-safe-style="color:${color}">${text}</span>`;

  const bits = [`${total - failed.length - empty.length}/${total} artifact(s) returned results`];
  if (cut.length) bits.push(tint(`${cut.length} cut short at the row cap`, "var(--sev-high)"));
  if (empty.length) bits.push(`${empty.length} had no findings`);
  if (failed.length) bits.push(tint(`${failed.length} failed to collect`, "#ff9f43"));

  let html = box(bits.join(" &middot; "), "var(--text-muted)");
  if (cut.length) {
    const names = cut
      .map((t) => `${esc(t.name)} (kept ${esc(String(t.kept))} rows, there were more)`)
      .join("<br>");
    html += box(
      `&#9888; INCOMPLETE &mdash; ${names}<br>Findings past the cap were never read. Raise ` +
        `DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS and collect again.`,
      "var(--sev-high)",
    );
  }
  if (failed.length) {
    html += box(
      failed.map((s) => `${esc(s.name)}: ${esc(s.error)}`).join("<br>"),
      "#ff9f43",
    );
  }
  return html;
}

// What the run-bundle route left behind, said at launch (#385 file-size ledger: extracted from
// dashboard-velo-triage.js rather than grown inside it).
//
// Two different things, and conflating them would be wrong. SKIPPED artifacts were dropped — this
// server does not have them, or cannot download their tool — and the hunt runs without them. UNHELD
// tools cost nothing yet: the server simply has no file for them, and fetches each while it compiles
// the hunt. Harmless with egress and fatal without it, because ONE it cannot reach loses the entire
// run — so the analyst is told which they are while the hunt is still young.

/* exported veloLaunchNotesHtml */
function veloLaunchNotesHtml(j) {
  const list = (v) => (Array.isArray(v) ? v : []);
  const tint = (items, sev) => `<span data-safe-style="color:var(--sev-${sev})">${esc(items.join(", "))}</span>`;
  const skipped = list(j.unknownArtifacts).concat(
    list(j.unavailableArtifacts).map((u) => `${u.artifact}: ${u.reason}`),
  );
  const unheld = list(j.unheldTools).map((u) => u.tool);
  const notes = [];
  if (skipped.length)
    notes.push(
      `skipped ${skipped.length} artifact(s), not on this server or missing their tool: ` +
        tint(skipped, "high"),
    );
  if (unheld.length)
    notes.push(
      `${unheld.length} tool(s) were not on this server yet — Velociraptor fetches them while it ` +
        "starts the hunt, and if it cannot reach one the run will not start: " +
        tint(unheld, "medium"),
    );
  return notes.length ? `launched ✓ — ${notes.join("; ")}` : "";
}

// What a hunt card says while its collect is in flight (#770).
//
// "collecting" is the one status renderVeloJobs had no text for, and it is also the one that lasts:
// the badge appeared, the countdown disappeared (it only renders while "running"), the Collect-now
// button was withheld, and the analyst got a yellow word and an empty line for the minutes a collect
// takes on a large case. A wait nobody can see progress in is indistinguishable from a hang, and one
// was reported as exactly that — a routine six-minute collect, 75 seconds of it queued behind another
// import, read as a frozen companion.
//
// The phase comes off the job, and the phase alone is NOT permission to describe live work. A stored
// "collecting" outlives the process that wrote it: kill the server mid-collect and the job says
// "collecting", phase and all, forever. So the server stamps `collectActive` from its in-flight map
// (the only authority — see composition/veloHunts.ts) and a stranded job is told apart from a busy one
// here. Getting this wrong would trade an empty line for a confident lie, which is worse.
//
// `collectActive` is checked as an explicit `false`: absent means the server did not say, which is
// what an older payload looks like, and "did not say" must not read as "stopped".

/* exported veloCollectingDetail */
function veloCollectingDetail(job) {
  if (!job || job.status !== "collecting") return "";
  const n = Number(job.collectRows);
  const rows = Number.isFinite(n) && n >= 0 ? `${n} row(s)` : "results";
  if (job.collectActive === false)
    return "this collect is no longer running — the companion restarted, or it stopped part-way. Press Collect now to run it again.";
  if (job.collectPhase === "queued")
    return `${rows} fetched — waiting for another import on this case to finish before they can be written`;
  if (job.collectPhase === "importing") return `importing ${rows}…`;
  return "fetching results from Velociraptor…";
}

// Is this hunt's Collect button offered, and does pressing it do anything?
//
// Withholding it during a collect is right; withholding it from a STRANDED collect is how a hunt
// becomes unrecoverable from the UI — the status never leaves "collecting" on its own, so the one
// action that would fix it was the one the card refused to show (#770).

/* exported veloCanCollect */
function veloCanCollect(job) {
  if (!job) return false;
  if (job.status === "collecting") return job.collectActive === false;
  return job.status === "running" || job.status === "imported" || job.status === "error";
}
