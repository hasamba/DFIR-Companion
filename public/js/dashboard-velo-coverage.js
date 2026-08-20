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
