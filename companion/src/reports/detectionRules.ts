// "Detection rules" for the reports (#2204): which Sigma rule release and settings graded the
// imported events. Read from the structured provenance token the import-time engine stamps on every
// event it graded (`sigma:<release>:<content>:<statuses>:<min level>:<disabled>[:<exclusions>]` in
// the canonical producer's ruleVersions) — a grammar the Companion writes itself, never prose parsed
// back. Tokens written before #2218 have no exclusions part and still read. A token may end in one
// `<origin>=<release>=<statuses>` part per extra rule source (#2499, Suzaku).
// Only forensic-timeline events are read, matching what the report itself covers.

import type { ForensicEvent } from "../analysis/stateTypes.js";
import { escapeHtml } from "./escapeHtml.js";

export interface SigmaGradingRef {
  release: string;
  contentSha: string;
  statuses: string[];
  minLevel: string;
  disabledHash: string;
  /** The analyst's exclusions (#2218). Absent on events graded before exclusions existed. */
  exclusionsHash?: string;
  /** Extra rule sources beside SigmaHQ (#2499), e.g. { name: "suzaku", release, statuses }. */
  origins?: { name: string; release: string; statuses: string[]; minLevel?: string }[];
}

const ORIGIN_PART = /^([A-Za-z0-9._-]+)=([A-Za-z0-9._-]+)=([A-Za-z0-9._+-]+)(?:=([a-z]+))?$/;
/** Display names of the extra sources the Companion ships; an unknown one shows as written. */
const ORIGIN_NAMES: Record<string, string> = { suzaku: "Suzaku" };

const TOKEN =
  /^sigma:([A-Za-z0-9._-]+):([0-9a-f]{12}):([A-Za-z0-9._+-]+):([a-z]+):([0-9a-f]{8}|none)(?::([0-9a-f]{8}|none))?((?::[A-Za-z0-9._-]+=[A-Za-z0-9._-]+=[A-Za-z0-9._+-]+(?:=[a-z]+)?)*)$/;

function parseOrigins(tail: string | undefined): SigmaGradingRef["origins"] {
  const parts = (tail ?? "").split(":").filter(Boolean);
  const out = parts.flatMap((p) => {
    const m = ORIGIN_PART.exec(p);
    return m
      ? [
          {
            name: ORIGIN_NAMES[m[1]] ?? m[1],
            release: m[2],
            statuses: m[3].split("+").filter(Boolean),
            ...(m[4] ? { minLevel: m[4] } : {}),
          },
        ]
      : [];
  });
  return out.length ? out : undefined;
}

/** Every distinct grading recorded on the events, first-seen order. */
export function sigmaGradingsInCase(events: readonly ForensicEvent[]): SigmaGradingRef[] {
  const seen = new Map<string, SigmaGradingRef>();
  for (const e of events) {
    for (const v of e.canonical?.producer?.ruleVersions ?? []) {
      if (seen.has(v)) continue;
      const m = TOKEN.exec(v);
      if (!m) continue;
      seen.set(v, {
        release: m[1],
        contentSha: m[2],
        statuses: m[3].split("+").filter(Boolean),
        minLevel: m[4],
        disabledHash: m[5],
        ...(m[6] ? { exclusionsHash: m[6] } : {}),
        ...(m[7] ? { origins: parseOrigins(m[7]) } : {}),
      });
    }
  }
  return [...seen.values()];
}

const md = (g: SigmaGradingRef): string =>
  `SigmaHQ \`${g.release}\` (content \`${g.contentSha}\`) — statuses ${g.statuses.join(", ")}; ` +
  `raises severity at ${g.minLevel} and above; disabled list \`${g.disabledHash}\`` +
  (g.exclusionsHash ? `; exclusions \`${g.exclusionsHash}\`` : "") +
  (g.origins ?? [])
    .map(
      (o) =>
        `; ${o.name} \`${o.release}\` — statuses ${o.statuses.join(", ")}` +
        (o.minLevel ? `; raises severity at ${o.minLevel} and above` : ""),
    )
    .join("");

/** A Markdown sub-section, or nothing when no imported event was graded by Sigma. */
export function detectionRulesMarkdown(events: readonly ForensicEvent[], lines: string[]): void {
  const gradings = sigmaGradingsInCase(events);
  if (gradings.length === 0) return;
  lines.push("### Detection rules", "");
  lines.push(
    "Imported cloud events were graded at import with Sigma rules (DRL 1.1). Each graded event names its rules, author and link.",
    "",
  );
  for (const g of gradings) lines.push(`- ${md(g)}`);
  lines.push("");
}

/** One line for the interactive report's header, or "". */
export function detectionRulesHtml(events: readonly ForensicEvent[]): string {
  const gradings = sigmaGradingsInCase(events);
  if (gradings.length === 0) return "";
  const items = gradings.map(
    (g) =>
      `SigmaHQ ${escapeHtml(g.release)} (content ${escapeHtml(g.contentSha)}), statuses ${escapeHtml(g.statuses.join(", "))}, raises at ${escapeHtml(g.minLevel)}+, disabled list ${escapeHtml(g.disabledHash)}` +
      (g.exclusionsHash ? `, exclusions ${escapeHtml(g.exclusionsHash)}` : "") +
      (g.origins ?? [])
        .map(
          (o) =>
            `; ${escapeHtml(o.name)} ${escapeHtml(o.release)}, statuses ${escapeHtml(o.statuses.join(", "))}` +
            (o.minLevel ? `, raises at ${escapeHtml(o.minLevel)}+` : ""),
        )
        .join(""),
  );
  return `<p class="meta">Detection rules: ${items.join(" · ")}</p>`;
}
