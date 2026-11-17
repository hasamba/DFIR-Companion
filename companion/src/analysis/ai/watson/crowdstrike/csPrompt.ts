import type { SiemLimits } from "../../../siemSearch.js";
import type { WatsonChat } from "../types.js";

// The CROWDSTRIKE NG-SIEM block of Watson's prompt (#2666). It is added only when the server has the
// Next-Gen SIEM search client set up, so Watson never hears about a tool it cannot use.

export type WatsonCsPrompt = Pick<SiemLimits, "maxWindowDays" | "maxRows" | "repository">;

/** Searches listed as already run, newest last. */
const RAN_MAX = 10;
const TITLE_CHARS = 120;

const line = (s: string): string => s.replace(/\s+/g, " ").trim().slice(0, TITLE_CHARS);

export function csRulesText(cs: WatsonCsPrompt, chat: WatsonChat): string {
  const ran = chat.proposals
    .flatMap((p) => (p.kind === "cs_search" && p.status === "applied" ? [p] : []))
    .slice(-RAN_MAX)
    .map((p) => `- ${line(p.title)} (${p.start} to ${p.end})`);
  return [
    "CROWDSTRIKE NG-SIEM",
    "You may ask to run a CQL search on this case's CrowdStrike Falcon Next-Gen SIEM: set 'request' to",
    '{ "kind": "crowdstrike_search", "title": "...", "query": "CQL", "start": "ISO 8601", "end": "ISO 8601", "why": "..." }.',
    "It becomes a card. The search runs only when the analyst approves it (in Auto mode, when the analyst's message",
    "came from the Watson panel). The rows are imported into the case as evidence and graded like any import. Rules:",
    `- One search covers at most ${cs.maxWindowDays} days and imports at most ${cs.maxRows} rows. A wider range is refused.`,
    "  Give both start and end, inside the incident window; with neither, the last days up to now are searched.",
    `- The repository is ${line(cs.repository)}. Write LogScale / Next-Gen SIEM CQL, never legacy FQL or SPL.`,
    "- Filter on ONE event type when you can: `#event_simpleName=ProcessRollup2 | <filters> | table([@timestamp,",
    "  ComputerName, ...], limit=1000)`. table() returns 200 rows unless you set limit=. Rows of groupBy() or count()",
    "  are not events: they are kept as evidence only and never reach the timeline.",
    "- Never repeat a search that already ran with the same query and range.",
    `Searches already run on this case:\n${ran.join("\n") || "(none)"}`,
  ].join("\n");
}
