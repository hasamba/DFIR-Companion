// WHEN a threat-intel assertion applies (#933 item 19). A provider's hit establishes that the
// provider asserted a verdict at `fetchedAt`, plus the dated facts it reported — each of its own
// kind. A VirusTotal scan date is when the verdict was MEASURED; a submission date is when a file
// or URL reached VirusTotal, not when it came to exist; an AbuseIPDB window bounds what its report
// count means. None of them is an observation of the indicator at the time of the case, so the
// words here compare each fact with the case time and stop: "measured N days after the case
// time" — never "was malicious then", never "still", never "covers".
//
// The case time is the earliest DATED extraction event in the IOC's provenance chain, with its
// basis: an authoritative `extractedFrom` link, an approximate value match (the words say so), or
// none — in which case the IOC's `firstSeen` is named for what it is, the import time.

import type { IOC, IocEnrichment } from "./stateTypes.js";
import type { IocProvenanceChain } from "./iocProvenanceChain.js";

export type CaseTime =
  | { basis: "authoritative" | "approximate"; from: string; to?: string }
  | { basis: "none"; importedAt: string };

const DAY_MS = 86_400_000;
const CLAUSE_MAX = 160;
const TAG_MAX = 400;

const parse = (iso: string): number => Date.parse(iso);
const dateOnly = (iso: string): boolean => /^\d{4}-\d{2}-\d{2}$/.test(iso.trim());
const day = (iso: string): string => {
  const t = parse(iso);
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : iso;
};
const utcDayIndex = (iso: string): number => Math.floor(parse(iso) / DAY_MS);

/** The case's own time for this indicator: the dated extraction events, with their basis. */
export function caseTime(ioc: Pick<IOC, "firstSeen">, chain: IocProvenanceChain | undefined): CaseTime {
  // The chain's bounds cover every matching event, before its display cap; fall back to the
  // capped list only for a chain built before the bounds existed.
  const dated = (chain?.extraction ?? []).filter((e) => Number.isFinite(parse(e.timestamp)));
  const from = chain?.extractionEarliest ?? dated.map((e) => e.timestamp).sort()[0];
  if (!from) return { basis: "none", importedAt: ioc.firstSeen };
  const ends = dated.map((e) =>
    e.endTimestamp && Number.isFinite(parse(e.endTimestamp)) ? e.endTimestamp : e.timestamp,
  );
  const to = chain?.extractionLatest ?? ends.sort().at(-1);
  return {
    basis: chain?.extractionAuthoritative ? "authoritative" : "approximate",
    from,
    ...(to && to !== from ? { to } : {}),
  };
}

function caseLabel(c: CaseTime & { basis: "authoritative" | "approximate" }): string {
  const span = c.to ? `${day(c.from)} → ${day(c.to)}` : day(c.from);
  return c.basis === "approximate"
    ? `the approximately matching event at ${span}`
    : `the case time (${span})`;
}

/**
 * "N days after the case time (S)" — calendar days from the NEAREST bound of the case time: a fact
 * inside an interval case time is "within" it. Under a day is said as such; a date-only fact next
 * to an instant under a day apart is not comparable (its precision cannot say which came first).
 */
function relation(factIso: string, c: CaseTime & { basis: "authoritative" | "approximate" }): string {
  const label = caseLabel(c);
  const f = parse(factIso);
  const from = parse(c.from);
  const to = c.to ? parse(c.to) : from;
  if (!Number.isFinite(f) || !Number.isFinite(from) || !Number.isFinite(to))
    return `not comparable with ${label}`;
  const factDay = utcDayIndex(factIso);
  if (c.to && f >= from && f <= to) return `within ${label}`;
  const bound = f < from ? c.from : (c.to ?? c.from);
  const boundMs = f < from ? from : to;
  const days = factDay - utcDayIndex(bound);
  if (days === 0) return `on the same day as ${label}`;
  if (Math.abs(f - boundMs) < DAY_MS) {
    return dateOnly(factIso)
      ? `not comparable with ${label} (a date without a time, less than a day apart)`
      : `less than one day from ${label}`;
  }
  const n = Math.abs(days).toLocaleString("en-US");
  return `${n} days ${days > 0 ? "after" : "before"} ${label}`;
}

/** Two intervals: the case time is before, after, inside, or overlapping the window. */
function windowRelation(
  from: string,
  to: string,
  c: CaseTime & { basis: "authoritative" | "approximate" },
): string {
  const s0 = parse(c.from);
  const s1 = c.to ? parse(c.to) : s0;
  const a = parse(from);
  const b = parse(to);
  const where = s1 < a ? "before" : s0 > b ? "after" : s0 >= a && s1 <= b ? "inside" : "overlapping";
  return `${caseLabel(c)} is ${where} that window`;
}

export interface TemporalReading {
  words: string;
  /** True when at least one dated fact from the provider exists. */
  dated: boolean;
}

/** The provider's dated facts against the case time, each of its own kind. Pure. */
export function intelTemporal(hit: IocEnrichment, c: CaseTime, now: string): TemporalReading {
  const t = hit.temporal ?? {};
  const dated = Boolean(
    t.verdictMeasuredAt || t.firstSubmittedAt || t.recordUpdatedAt || t.lastReportAt || t.queryWindow,
  );
  const cmp = (iso: string): string => (c.basis === "none" ? "" : ` — ${relation(iso, c)}`);
  const noCase =
    c.basis === "none"
      ? `no dated case time to compare (the indicator was imported on ${day(c.importedAt)})`
      : "";
  const parts: string[] = [];

  if (t.queryWindow) {
    // An absent count is not zero: the provider did not report one.
    const count = typeof t.reportCount === "number" ? t.reportCount : undefined;
    const counted =
      count === undefined
        ? "reports not counted by the provider"
        : `${count.toLocaleString("en-US")} reports counted`;
    let w = `${counted} over the window ${day(t.queryWindow.from)} → ${day(t.queryWindow.to)}`;
    if (c.basis !== "none") w += `; ${windowRelation(t.queryWindow.from, t.queryWindow.to, c)}`;
    if (t.lastReportAt) w += `; latest report ${day(t.lastReportAt)}${cmp(t.lastReportAt)}`;
    if (count === 0) w += "; no reports in that window says nothing about earlier dates";
    parts.push(w);
  }
  if (t.verdictMeasuredAt)
    parts.push(
      `verdict measured by the latest scan on ${day(t.verdictMeasuredAt)}${cmp(t.verdictMeasuredAt)}`,
    );
  if (t.firstSubmittedAt) {
    parts.push(
      `first submitted to VirusTotal on ${day(t.firstSubmittedAt)}${cmp(t.firstSubmittedAt)} (a submission date, not when the file or URL came to exist)`,
    );
  }
  if (t.recordUpdatedAt)
    parts.push(`VirusTotal record last updated ${day(t.recordUpdatedAt)} (not an observation)`);

  if (!dated) {
    const lookup = `the provider reports no dates; the lookup ran on ${day(hit.fetchedAt || now)}`;
    return {
      words: c.basis === "none" ? `${lookup}; ${noCase}` : `${lookup}${cmp(hit.fetchedAt || now)}`,
      dated,
    };
  }
  return { words: noCase ? `${parts.join("; ")}; ${noCase}` : parts.join("; "), dated };
}

// A provider name is provider-written text beside the tag's own brackets. The same three rules
// recordIdentity.ts applies (brackets to parentheses, control characters out, a 32+ hex run shown
// by its ends) — restated here because this domain may not import the ingest layer.
const shown = (s: string, max: number): string => {
  const t = s
    .replace(/\[/g, "(")
    .replace(/\]/g, ")")
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/[a-f0-9]{32,}/gi, (m) => `${m.slice(0, 8)}…${m.slice(-4)}`);
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
};

/**
 * The one bounded tag the synthesis line carries: every provider with a malicious or suspicious
 * verdict, one clause each, clauses and the whole tag capped, the cut said as "(+N more)".
 */
export function intelTimeTag(hits: readonly IocEnrichment[], c: CaseTime, now: string): string {
  const bad = hits.filter((h) => h.verdict === "malicious" || h.verdict === "suspicious");
  if (!bad.length) return "";
  const clauses = bad.map((h) => shown(`${h.source} — ${intelTemporal(h, c, now).words}`, CLAUSE_MAX));
  const head = "[intel time: ";
  let body = "";
  let kept = 0;
  for (const cl of clauses) {
    const next = body ? `${body}; ${cl}` : cl;
    const more = clauses.length - kept - 1;
    const tail = more > 0 ? ` (+${more} more)]` : "]";
    if (head.length + next.length + tail.length > TAG_MAX) break;
    body = next;
    kept += 1;
  }
  if (!kept) return `${head}${shown(clauses[0], TAG_MAX - head.length - 20)} (+${clauses.length - 1} more)]`;
  const more = clauses.length - kept;
  return `${head}${body}${more > 0 ? ` (+${more} more)` : ""}]`;
}
