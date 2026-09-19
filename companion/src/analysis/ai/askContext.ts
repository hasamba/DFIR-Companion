// The analyst-decision blocks the Ask prompt carries (#1411). ask() used to see the case's evidence
// (timeline, findings, IOCs, questions) but none of the investigator's OWN work, all of which lives
// in per-case side files: hypotheses, host-scope decisions, dwell windows, hunt outcomes, tags and
// comments, the notebook. Without them the model can name a host the analyst cleared, re-propose a
// hunt that came back empty, or answer "was data exfiltrated?" without seeing the hypothesis opened
// on exactly that.
//
// ASK_PROMPT itself is NOT changed (CI's #378 change gate hashes every prompt constant), so each
// block's legend line carries the instruction the model needs — the `PRIOR HUNTS (… do NOT
// re-propose …)` pattern from huntOutcomes.renderPriorHuntsBlock.
//
// PURE — no I/O, no clock. Every renderer returns "" when there is nothing to add (zero tokens on a
// fresh case), else a legend + bullets ending in a blank line so the blocks concatenate cleanly.

import type { Hypothesis } from "../hypothesis.js";
import type { HostScopeDecision } from "../hostScopeStore.js";
import type { DwellWindow } from "../dwellWindow.js";
import type { Tag } from "../tags.js";
import type { Comment } from "../comments.js";
import type { NotebookEntry } from "../notebookStore.js";
import type { AskTurn } from "../askHistory.js";
import { STARRED_LABEL } from "../superTimeline.js";

export const ASK_HYPOTHESES_MAX = 20;
export const ASK_HOST_SCOPE_MAX = 40;
export const ASK_DWELL_MAX = 20;
export const ASK_MARKS_MAX = 50; // one line per marked entity, not per tag
export const ASK_NOTEBOOK_MAX = 40;
const NOTE_MAX = 160; // chars of free text carried per hypothesis note / exhaustion reason

// Host statuses that carry information for an answer. "unknown" is the absence of a decision.
const HOST_SCOPE_KEEP: ReadonlySet<HostScopeDecision["to"]> = new Set([
  "cleared",
  "out-of-scope",
  "confirmed",
  "suspected",
]);

const oneLine = (s: string, max = NOTE_MAX): string => s.replace(/\s+/g, " ").trim().slice(0, max);

const cap = (limit: number): number => Math.max(1, Math.floor(limit));

export function renderAskHypothesesBlock(
  hypotheses: readonly Hypothesis[],
  limit = ASK_HYPOTHESES_MAX,
): string {
  const list = (hypotheses ?? []).slice(0, cap(limit));
  if (!list.length) return "";
  const lines = list.map((h) => {
    const status = h.exhausted && h.status !== "refuted" ? "exhausted" : h.status;
    const detail =
      status === "exhausted"
        ? oneLine(h.exhaustedReason ?? "")
        : status === "refuted"
          ? oneLine(h.notes ?? "")
          : h.expectedOutcome
            ? `decided by: ${oneLine(h.expectedOutcome)}`
            : "";
    const sup = h.relatedEventIds?.length ?? 0;
    const con = h.contradictingEventIds?.length ?? 0;
    const counts =
      sup || con ? ` (${sup} supporting, ${con} contradicting event${con === 1 ? "" : "s"})` : "";
    return `- [${status}] ${h.title}${detail ? ` — ${detail}` : ""}${counts}`;
  });
  return (
    "ANALYST HYPOTHESES (the investigator's own theories and their current status — answer AGAINST these; " +
    "a refuted or exhausted theory must NOT be re-asserted; if the evidence contradicts a status, say so " +
    `explicitly):\n${lines.join("\n")}\n\n`
  );
}

// Latest decision per host wins (a host can be suspected, then cleared). Hosts whose latest decision
// is "unknown" are dropped: the analyst withdrew the earlier call, so there is nothing to assert.
export function renderHostScopeBlock(
  decisions: readonly HostScopeDecision[],
  limit = ASK_HOST_SCOPE_MAX,
): string {
  const latest = new Map<string, HostScopeDecision>();
  for (const d of decisions ?? []) {
    const prev = latest.get(d.host);
    if (!prev || d.at >= prev.at) latest.set(d.host, d);
  }
  const rows = [...latest.values()].filter((d) => HOST_SCOPE_KEEP.has(d.to)).slice(0, cap(limit));
  if (!rows.length) return "";
  const lines = rows.map((d) => {
    const reason = oneLine(d.reason ?? "");
    const who = `${d.analyst || "analyst"}, ${d.at.slice(0, 10)}`;
    return `- ${d.host}: ${d.to}${reason ? ` — ${reason}` : ""} (${who})`;
  });
  return (
    "ANALYST HOST-SCOPE DECISIONS (signed by the investigator — a cleared or out-of-scope host must NOT be " +
    "named as compromised; a confirmed host is established; if the evidence contradicts a decision, flag " +
    `the contradiction explicitly instead of overriding it):\n${lines.join("\n")}\n\n`
  );
}

export function renderDwellWindowsBlock(windows: readonly DwellWindow[], limit = ASK_DWELL_MAX): string {
  const list = (windows ?? []).slice(0, cap(limit));
  if (!list.length) return "";
  const lines = list.map((w) => `- ${oneLine(w.label)}: ${w.start} → ${w.end}`);
  return (
    "ANALYST DWELL WINDOWS (attacker-presence windows the investigator defined — prefer these for " +
    `'when did they get in / leave' questions, and say if the evidence extends beyond them):\n${lines.join("\n")}\n\n`
  );
}

interface MarkedTarget {
  targetType: string;
  targetId: string;
  tags: string[];
  comments: Comment[];
  newest: string;
  starred: boolean;
}

// One line per marked entity: its tags, then its comments. Starred entities lead (the star is the
// analyst's strongest "this matters" signal), then newest activity first.
export function renderAnalystMarksBlock(
  tags: readonly Tag[],
  comments: readonly Comment[],
  limit = ASK_MARKS_MAX,
): string {
  const targets = new Map<string, MarkedTarget>();
  const target = (t: { targetType: string; targetId: string }, at: string): MarkedTarget => {
    const key = `${t.targetType}\u0000${t.targetId}`;
    let m = targets.get(key);
    if (!m) {
      m = {
        targetType: t.targetType,
        targetId: t.targetId,
        tags: [],
        comments: [],
        newest: at,
        starred: false,
      };
      targets.set(key, m);
    }
    if (at > m.newest) m.newest = at;
    return m;
  };
  for (const t of tags ?? []) {
    const m = target(t, t.createdAt);
    m.tags.push(t.label);
    if (t.label === STARRED_LABEL) m.starred = true;
  }
  for (const c of comments ?? []) target(c, c.createdAt).comments.push(c);
  if (!targets.size) return "";

  const rows = [...targets.values()]
    .sort((a, b) => Number(b.starred) - Number(a.starred) || b.newest.localeCompare(a.newest))
    .slice(0, cap(limit));
  const lines = rows.map((m) => {
    const labels = [...new Set(m.tags)].sort(
      (a, b) => Number(b === STARRED_LABEL) - Number(a === STARRED_LABEL),
    );
    const parts: string[] = [];
    if (labels.length) parts.push(`tags: ${labels.join(", ")}`);
    for (const c of m.comments) parts.push(`"${oneLine(c.text, 300)}" (${c.author || "analyst"})`);
    return `- [${m.targetType} ${m.targetId}] ${parts.join(" · ")}`;
  });
  return (
    "ANALYST MARKS (what the investigator starred, tagged or commented on — weight these as the analyst's " +
    `own judgement and cite the marked event ids when they bear on the question):\n${lines.join("\n")}\n\n`
  );
}

export function renderAskNotebookBlock(entries: readonly NotebookEntry[], limit = ASK_NOTEBOOK_MAX): string {
  const list = [...(entries ?? [])]
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, cap(limit));
  if (!list.length) return "";
  const lines = list.map((e) => `[${e.type.toUpperCase()}] ${oneLine(e.text, 400)}`);
  return `ANALYST NOTEBOOK (investigator notes, newest first — context, not evidence):\n${lines.join("\n")}\n\n`;
}

export function renderAskHistoryBlock(turns: readonly AskTurn[]): string {
  if (!turns?.length) return "";
  const lines = turns.map((t) => `Q: ${t.question}\nA: ${t.answer || "(no answer)"}`);
  return (
    "PRIOR Q&A IN THIS SESSION (the question below may be a follow-up to these — resolve 'it', 'that host' " +
    `and similar against them; do not repeat an earlier answer verbatim):\n${lines.join("\n")}\n\n`
  );
}
