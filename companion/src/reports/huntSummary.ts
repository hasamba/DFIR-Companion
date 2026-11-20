import type { InvestigationState } from "../analysis/stateTypes.js";
import { coverageSentence } from "../analysis/huntFraming.js";
import {
  huntVerdict,
  VERDICT_TEXT,
  type HuntReportData,
  type HuntReportItem,
} from "../analysis/huntReport.js";
import { cellMd } from "./mdText.js";

/**
 * "Threat hunt summary" section (#2670): scope and coverage, the verdict QUALIFIED by coverage, the
 * graded hunt items with their hosts, what still waits for the client's answer, and the comparison
 * with the last comparable hunt. Every adversary- or client-supplied string goes through cellMd.
 */
const HOSTS_SHOWN = 50;

const KIND_TITLE: Record<HuntReportItem["kind"], string> = {
  policy: "Policy violations (not allowed by the client)",
  new: "New since the last comparable hunt",
  rare: "Rare across the hosts that answered",
  download: "Flagged downloads",
};

export function huntSummarySection(
  hunt: HuntReportData | undefined,
  state: InvestigationState,
  lines: string[],
): void {
  lines.push("## Threat hunt summary", "");
  if (!hunt) {
    lines.push("This case is not a threat hunt, or its hunt records are not part of this rendering.", "");
    return;
  }
  scope(hunt, lines);
  const verdict = huntVerdict(state, hunt.items);
  lines.push(
    "### Verdict",
    "",
    `**${VERDICT_TEXT[verdict]}**, within coverage. ${coverageSentence(hunt.coverage)}`,
    "",
  );
  items(hunt.items, lines);
  pending(hunt, lines);
  comparison(hunt, lines);
}

function scope(hunt: HuntReportData, lines: string[]): void {
  lines.push("### Scope", "");
  if (hunt.clientName) lines.push(`- Client: ${cellMd(hunt.clientName)}`);
  if (hunt.baselineVersion !== undefined)
    lines.push(`- Graded against baseline version ${hunt.baselineVersion}`);
  lines.push(`- ${coverageSentence(hunt.coverage)}`, "");
  if (hunt.hunts.length) {
    const times = hunt.hunts.map((h) => h.launchedAt).sort();
    lines.push(`Time window: ${cellMd(times[0] ?? "")} to ${cellMd(times[times.length - 1] ?? "")}`, "");
    lines.push("| Hunt | Bundle | Launched | Status |", "|---|---|---|---|");
    for (const h of hunt.hunts)
      lines.push(
        `| ${cellMd(h.huntId)} | ${cellMd(h.bundleName)} | ${cellMd(h.launchedAt)} | ${cellMd(h.status)} |`,
      );
    lines.push("");
  } else {
    lines.push(
      "No Companion-launched hunt is recorded for this case; uploaded hunt exports carry no coverage.",
      "",
    );
  }
  if (hunt.coverage.known && hunt.coverage.answeredHosts.length) {
    const shown = hunt.coverage.answeredHosts
      .slice(0, HOSTS_SHOWN)
      .map((h) => cellMd(h.hostname || h.clientId));
    const more = hunt.coverage.answeredHosts.length - shown.length;
    lines.push(`Hosts that answered: ${shown.join(", ")}${more > 0 ? ` (+${more} more)` : ""}`, "");
  }
}

function items(list: readonly HuntReportItem[], lines: string[]): void {
  lines.push("### Policy violations, new and rare items", "");
  if (!list.length) {
    lines.push("No hunt item was graded on this case.", "");
    return;
  }
  for (const kind of ["policy", "new", "rare", "download"] as const) {
    const of = list.filter((i) => i.kind === kind);
    if (!of.length) continue;
    lines.push(`#### ${KIND_TITLE[kind]}`, "", "| Item | Severity | Hosts | Why |", "|---|---|---|---|");
    for (const i of of) {
      const hosts = i.hosts.map(cellMd).join(", ") + (i.moreHosts > 0 ? ` (+${i.moreHosts} more)` : "");
      lines.push(`| ${cellMd(i.label)} | ${i.severity} | ${i.hostCount}: ${hosts} | ${cellMd(i.reason)} |`);
    }
    lines.push("");
  }
}

function pending(hunt: HuntReportData, lines: string[]): void {
  lines.push("### Waiting for client confirmation", "");
  if (!hunt.pending.length) {
    lines.push("Nothing is waiting for the client's answer.", "");
    return;
  }
  lines.push(
    "Seeing a program never approves it. These items stay listed until the client answers.",
    "",
    "| Item | Hosts | First seen | Unconfirmed for |",
    "|---|---|---|---|",
  );
  for (const p of hunt.pending)
    lines.push(
      `| ${cellMd(p.label)} | ${p.hostCount} | ${cellMd(p.firstSeen)} | ${p.huntsUnconfirmed} hunt(s) |`,
    );
  lines.push("");
}

function comparison(hunt: HuntReportData, lines: string[]): void {
  lines.push("### Comparison with the last comparable hunt", "");
  const c = hunt.comparison;
  if (!c) {
    lines.push(
      "Nothing to compare yet: there is no earlier comparable hunt for this client that you can open.",
      "",
    );
    return;
  }
  lines.push(
    `Compared with case ${cellMd(c.previousCaseId)} (${cellMd(c.previousAt)}): ${c.newItems} item(s) are new and ${c.goneItems} item(s) were not seen this time (absence is only claimed where both hunts covered the host cleanly).`,
    "",
  );
}
export type { HuntReportData } from "../analysis/huntReport.js";
