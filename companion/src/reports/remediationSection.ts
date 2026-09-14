import type { InvestigationState } from "../analysis/stateTypes.js";
import { cellMd } from "./mdText.js";

/**
 * "Remediation checks" section (#930 item 9 — #969): per boundary, the analyst's recorded
 * residual-risk status with the receipt it names — the facts they read when they recorded it:
 * which host spellings were covered, how many rows of each telemetry family the case held in the
 * window and whether that family counts as covered, how many rows named the artifact and what
 * each was (activity, a scanner's claim, a presence record, a listing of an older object), and
 * whether the read was truncated, the window still open, or the stores moved since. Never a
 * verify that was not recorded, never a verdict the machine made: a "checked — not observed" is
 * the analyst's sentence, and the coverage beside it says how much it rests on.
 */
export function remediationChecksSection(state: InvestigationState, lines: string[]): void {
  lines.push("## Remediation checks", "");
  const boundaries = state.remediationBoundaries ?? [];
  if (boundaries.length === 0) {
    lines.push("No remediation boundary has been declared for this case.", "");
    return;
  }
  lines.push(
    "Each boundary is an analyst statement that an artifact was remediated on a host at a time. The status is the analyst's; the check it names lists what the case held for that host inside the watch window and how much of it there was. Absence of rows is a coverage fact, not evidence that the foothold is gone.",
    "",
  );
  for (const b of boundaries) {
    lines.push(`### ${cellMd(b.artifact.kind)} \`${cellMd(b.artifact.value)}\` on ${cellMd(b.host)}`, "");
    lines.push(
      `- Remediated at ${cellMd(b.remediatedAt)}; watch window ${b.windowHours} h${b.note ? `; note: ${cellMd(b.note)}` : ""}`,
    );
    const receipt = b.receipts.find((r) => r.id === b.statusReceiptId);
    const stale = receipt?.stale
      ? ` — recorded against older data (receipt ${cellMd(receipt.id)}, ${cellMd(receipt.at)})`
      : "";
    lines.push(
      `- Status: **${cellMd(b.status)}**${b.statusSetAt ? ` (${cellMd(b.statusSetAt)})` : ""}${b.statusNote ? ` — ${cellMd(b.statusNote)}` : ""}${b.statusOverrideNote ? ` — override: ${cellMd(b.statusOverrideNote)}` : ""}${stale}`,
    );
    if (receipt) {
      const flags = [
        receipt.truncated ? "read truncated" : "",
        receipt.window.open ? "window still open" : "",
        receipt.coverageGapped ? "a relevant family not covered" : "",
        receipt.inconsistent ? "stores changed during the read" : "",
        receipt.retentionNote ? "super-timeline at its retention cap" : "",
      ].filter(Boolean);
      lines.push(
        `- Check ${cellMd(receipt.id)} at ${cellMd(receipt.at)}: host spellings ${receipt.spellings.map((s) => `\`${cellMd(s)}\``).join(", ") || "(none held by the case)"}; window ${cellMd(receipt.window.from)} → ${cellMd(receipt.window.to)}; ${receipt.hitTotal} row(s) named the artifact${
          Object.keys(receipt.hitsByClass).length
            ? ` (${Object.entries(receipt.hitsByClass)
                .map(([k, v]) => `${v} ${cellMd(k)}`)
                .join(", ")})`
            : ""
        }; ${receipt.undated} undated row(s) skipped${flags.length ? `; ${flags.join("; ")}` : ""}`,
      );
      lines.push("", "| Telemetry family | Relevant | Rows in window | Coverage |", "|---|---|---|---|");
      for (const f of receipt.families)
        lines.push(
          `| ${cellMd(f.family)} | ${f.relevant ? "yes" : "no"} | ${f.rowsInWindow} | ${cellMd(f.state)} |`,
        );
      lines.push("");
    } else if (b.status !== "unreviewed") {
      lines.push("- The receipt this status names is no longer on the boundary.");
    }
    if (b.evidence.length) {
      lines.push("", "| Attached evidence | Time | Description |", "|---|---|---|");
      for (const id of b.evidence.slice(0, 50)) {
        const e = state.forensicTimeline.find((x) => x.id === id);
        lines.push(
          `| ${cellMd(id)} | ${cellMd(e?.timestamp ?? "")} | ${cellMd(e?.description ?? "(not in the forensic timeline)")} |`,
        );
      }
      if (b.evidence.length > 50) lines.push(`| … | | +${b.evidence.length - 50} more |`);
    }
    lines.push("");
  }
}
