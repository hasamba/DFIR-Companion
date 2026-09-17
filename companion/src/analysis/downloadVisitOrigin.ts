// Mark → browser visit: a download mark's own URL or referrer, matched against a Velociraptor
// browser-history "Visited" row for the same URL, dated BEFORE the mark's own anchor — the
// browser-origin half of #985. Split out of downloadExecution.ts (the file-size ledger, #384)
// rather than grown in place.
//
// A visit within ORDER_TOLERANCE_MS of the anchor, after it, or with no readable time on either
// side establishes no order and is never noted as having "preceded" the mark: asserting a
// sequence the evidence doesn't show would corroborate a drive-by story the evidence actually
// contradicts (#985 code review). It establishes that the browser reached that URL before the
// file appeared, never that the visit CAUSED the download (T1189 needs an analyst's own read, not
// an automated one) — no technique is added, and a mark is raised no higher than Medium, below
// what real execution evidence earns.

import { splitDerivedNotes } from "./derivedNote.js";
import {
  type TimelineEventShape,
  ORDER_TOLERANCE_MS,
  neutral,
  excerpt,
  ms,
  hostOf,
  veloAction,
} from "./downloadCorroborationShared.js";

export const BROWSER_VISIT_MARKER = "[downloaded from a visited page:";
export const REFERRER_VISIT_MARKER = "[referrer page visited:";
export const VISIT_PRECEDES_MARK_MARKER = "[preceded a download mark:";

/** Records indexed per URL bucket; the rest are counted, never read. */
const BUCKET_MAX = 64;
/** Marks named on one corroborating visit row; the rest are counted. */
const MARKS_PER_VISIT_MAX = 4;

/** The mark's own download URL / referrer, embedded in its description by ntfsStreams.ts's
 * `markWords()` (`downloaded from <zone> (<url>[, referrer <referrer>])`). "" when the record
 * carried neither. */
const MARK_URL =
  /downloaded from (?:the [A-Za-z ]+ zone|zone \S+) \((https?:\/\/[^,)]+)(?:, referrer (https?:\/\/[^)]+))?\)/i;
function markUrls(e: TimelineEventShape): { url: string; referrer: string } {
  const m = MARK_URL.exec(splitDerivedNotes(e.description).base);
  return { url: m?.[1]?.trim() ?? "", referrer: m?.[2]?.trim() ?? "" };
}

/** A Velociraptor browser-history "Visited" row's URL. `veloAction` already gates on `sources`
 * naming Velociraptor, so a non-Velociraptor row with a lookalike description cannot spoof this. */
function veloVisitUrl(e: TimelineEventShape): string {
  if (!/^Visited/i.test(veloAction(e))) return "";
  const m = /https?:\/\/\S+/i.exec(e.description ?? "");
  return m ? m[0].replace(/[.,;]+$/, "") : "";
}

/** Scheme and host fold together (case is not a real difference there), an explicit default port
 * is dropped (`:443` on https, `:80` on http — a mark can carry MOTW's verbatim HostUrl while a
 * browser history URL is canonicalized, so this is a real mismatch a mark/visit pair can otherwise
 * hit), and a bare origin's trailing slash is not a distinct page. The path/query stay
 * case-sensitive — a real distinguishing part of a URL. Percent-escape hex case and IDN/punycode
 * host spellings are NOT folded — a residual, safe-direction gap (a real match can be missed;
 * nothing is ever matched that shouldn't be) rather than fixed here (#985 code review). */
function normalizeUrl(u: string): string {
  const m = /^(https?):\/\/([^/]+)(\/.*)?$/i.exec(u.trim());
  if (!m) return u.trim();
  const scheme = m[1].toLowerCase();
  let host = m[2].toLowerCase();
  if (scheme === "https") host = host.replace(/:443$/, "");
  else host = host.replace(/:80$/, "");
  const path = (m[3] ?? "").replace(/\/+$/, "");
  return `${scheme}://${host}${path}`;
}

interface Visit<T> {
  event: T;
  host: string;
  hostNote?: string;
}

/** The visit rows matching a URL, filtered by the same host rule as the mark → execution join:
 * two NAMED hosts must agree; an unnamed record attaches only when the eligible set names at
 * most one host. */
function matchVisits<T extends TimelineEventShape>(
  markHost: string,
  url: string,
  visitByUrl: Map<string, { event: T; host: string }[]>,
): Visit<T>[] {
  const candidates = visitByUrl.get(normalizeUrl(url)) ?? [];
  if (!candidates.length) return [];
  const namedHosts = new Set([markHost, ...candidates.map((c) => c.host)].filter(Boolean));
  const out: Visit<T>[] = [];
  for (const c of candidates) {
    if (markHost && c.host) {
      if (markHost === c.host) out.push(c);
      continue;
    }
    if (namedHosts.size > 1) continue;
    out.push({
      ...c,
      hostNote:
        namedHosts.size === 1
          ? `host not named on one record — attributed to the case's one named host, ${neutral([...namedHosts][0]).slice(0, 80)}`
          : "host not named on either record",
    });
  }
  return out;
}

/** Whether a visit is dated BEFORE the mark's own anchor, beyond ORDER_TOLERANCE_MS — the same
 * order check the mark → execution join uses (flipped: a visit must come before the download, an
 * execution after it). */
function precedesAnchor<T extends TimelineEventShape>(v: Visit<T>, anchor: number | null): boolean {
  const visited = ms(v.event.timestamp);
  return visited !== null && anchor !== null && anchor - visited > ORDER_TOLERANCE_MS;
}

function visitWords<T extends TimelineEventShape>(v: Visit<T>): string {
  const when = v.event.timestamp ? neutral(v.event.timestamp).slice(0, 40) : "no time";
  const hostNote = v.hostNote ? ` (${v.hostNote})` : "";
  return `${excerpt(v.event.description ?? "")} — ${when}${hostNote}`;
}

/** One label's note: the first eligible visit, named; the rest counted. Callers pass only visits
 * that already passed `precedesAnchor`. */
function joinVisits<T extends TimelineEventShape>(matches: Visit<T>[], label: string): string {
  const more = matches.length > 1 ? `; +${matches.length - 1} more` : "";
  return `${label}: ${visitWords(matches[0])}${more}`;
}

export interface BrowserVisitCorroboration<T> {
  /** Per mark: the note naming the visit(s) to its own download URL. */
  ownVisitNotes: Map<T, string>;
  /** Per mark: the note naming the visit(s) to its referrer page. */
  referrerVisitNotes: Map<T, string>;
  /** Per visit row: the mark(s) it precedes. */
  precededNotes: Map<T, { marks: string[]; more: number }>;
}

/**
 * Match every download mark's URL/referrer against the browser visits that precede it. `marks` is
 * the caller's own list of classified mark records (event + resolved host) — this module has no
 * knowledge of how a mark was classified, only of what it says.
 */
export function browserVisitCorroboration<T extends TimelineEventShape>(
  events: readonly T[],
  marks: readonly { event: T; host: string }[],
): BrowserVisitCorroboration<T> {
  const visitByUrl = new Map<string, { event: T; host: string }[]>();
  for (const e of events) {
    const url = veloVisitUrl(e);
    if (!url) continue;
    const key = normalizeUrl(url);
    const list = visitByUrl.get(key) ?? visitByUrl.set(key, []).get(key)!;
    if (list.length < BUCKET_MAX) list.push({ event: e, host: hostOf(e) });
  }
  const ownVisitNotes = new Map<T, string>();
  const referrerVisitNotes = new Map<T, string>();
  const precededNotes = new Map<T, { marks: string[]; more: number }>();
  if (visitByUrl.size) {
    for (const r of marks) {
      const { url, referrer } = markUrls(r.event);
      if (!url && !referrer) continue;
      const anchor = ms(r.event.timestamp);
      const sameAsUrl = url && referrer && normalizeUrl(referrer) === normalizeUrl(url);
      const own = (url ? matchVisits(r.host, url, visitByUrl) : []).filter((v) => precedesAnchor(v, anchor));
      const ref = (referrer && !sameAsUrl ? matchVisits(r.host, referrer, visitByUrl) : []).filter((v) =>
        precedesAnchor(v, anchor),
      );
      if (own.length) ownVisitNotes.set(r.event, joinVisits(own, "visited the download URL"));
      if (ref.length) referrerVisitNotes.set(r.event, joinVisits(ref, "visited the referrer page"));
      for (const v of [...own, ...ref]) {
        const c =
          precededNotes.get(v.event) ?? precededNotes.set(v.event, { marks: [], more: 0 }).get(v.event)!;
        if (c.marks.length < MARKS_PER_VISIT_MAX)
          c.marks.push(
            `${excerpt(r.event.path ?? "")}${r.host ? ` on ${neutral(r.host).slice(0, 80)}` : ""}`,
          );
        else c.more += 1;
      }
    }
  }
  return { ownVisitNotes, referrerVisitNotes, precededNotes };
}
