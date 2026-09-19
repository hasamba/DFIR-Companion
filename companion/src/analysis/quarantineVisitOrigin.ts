// The quarantine record's origin page and download URL against the browser visits that precede
// it (#1037 link 3) — the macOS half of what downloadVisitOrigin.ts (#985) does for a Windows
// mark. Same join, same posture: a visit is matched by URL equality alone (scheme/host folded,
// path exact — never a host, a basename or a time), only a visit dated BEFORE the record beyond
// the tolerance is noted, and the note says the browser reached the page before the download
// event was logged — never that the visit caused the download (T1189 is the analyst's own read;
// no technique is added). Two named hosts must agree; an unnamed side attaches only when the
// pair names one host, and the note says so.
//
// Both rows are Info, so both are raised to Medium when joined: the record so it sits in the
// forensic timeline beside the visit that explains it, the visit so the next merge can still find
// it. The same cross-import limitation #985 accepts applies — a visit demoted before the dump
// arrives is out of reach; the manual says which order to import in. The IOC provenance view
// shows both records for the URL regardless (both importers mint the `url` indicator).

import type { QuarantineBlock } from "./canonicalQuarantine.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import { hostOf, neutral, type TimelineEventShape } from "./downloadCorroborationShared.js";
import { browserVisitCorroboration } from "./downloadVisitOrigin.js";
import type { Severity } from "./stateTypes.js";

export const ORIGIN_VISITED_MARKER = "[origin page visited:";
export const DATA_URL_VISITED_MARKER = "[download URL visited:";
export const PRECEDED_QUARANTINE_MARKER = "[preceded a quarantine record:";
const NOTE_MAX = 600;
const RAISED: Severity = "Medium";
const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

export interface QuarantineVisitEventShape extends TimelineEventShape {
  canonical?: TimelineEventShape["canonical"] & { quarantine?: QuarantineBlock };
}

const OWN = [ORIGIN_VISITED_MARKER, DATA_URL_VISITED_MARKER, PRECEDED_QUARANTINE_MARKER].map((m) =>
  m.slice(1, -1),
);
const OWN_RE = new RegExp(
  `\\s*\\[(?:${OWN.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")}):[\\s\\S]{0,1200}?\\]`,
  "gu",
);

function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  return [base, notes.replace(OWN_RE, "").trim()].filter(Boolean).join(" ");
}
const clip = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);
const raise = (current: Severity | undefined): Severity =>
  RANK[current ?? "Info"] < RANK[RAISED] ? RAISED : (current ?? "Info");

const dbBlock = (e: QuarantineVisitEventShape): QuarantineBlock | undefined => {
  const q = e.canonical?.quarantine;
  return q && !q.folded && (q.dataUrl || q.originUrl) ? q : undefined;
};
const dbHost = (q: QuarantineBlock): string =>
  q.host && "name" in q.host ? q.host.name.trim().toLowerCase() : "";

export function linkQuarantineVisitOrigin<T extends QuarantineVisitEventShape>(events: readonly T[]): T[] {
  const stripped = events.map((e) => {
    const description = withoutOwnNotes(e.description);
    return description === (e.description ?? "") ? e : { ...e, description };
  });
  const marks = stripped.flatMap((e) => {
    const q = dbBlock(e);
    return q ? [{ event: e, host: dbHost(q) || hostOf(e) }] : [];
  });
  if (!marks.length) return stripped;
  // The record's own URLs: the download as "url", the origin page as "referrer" — the same two
  // slots the Windows mark fills, so the same visit matcher and order check apply unchanged.
  const { ownVisitNotes, referrerVisitNotes, precededNotes } = browserVisitCorroboration(stripped, marks, {
    urlsOf: (e) => {
      const q = dbBlock(e)!;
      return { url: q.dataUrl ?? "", referrer: q.originUrl ?? "" };
    },
    labelOf: (e) => {
      const q = dbBlock(e)!;
      return neutral(q.dataUrl ?? q.originUrl ?? "").slice(0, 160);
    },
  });
  return stripped.map((e) => {
    let description = e.description ?? "";
    let severity = e.severity;
    const own = ownVisitNotes.get(e);
    if (own) {
      description = appendDerivedNote(
        description,
        DATA_URL_VISITED_MARKER,
        clip(own.replace(/^visited the download URL/, "visited the download URL")),
      );
      severity = raise(severity);
    }
    const ref = referrerVisitNotes.get(e);
    if (ref) {
      description = appendDerivedNote(
        description,
        ORIGIN_VISITED_MARKER,
        clip(ref.replace(/^visited the referrer page/, "visited the origin page")),
      );
      severity = raise(severity);
    }
    const preceded = precededNotes.get(e);
    if (preceded) {
      const words = [...preceded.marks, ...(preceded.more ? [`+${preceded.more} more`] : [])].join("; ");
      description = appendDerivedNote(
        description,
        PRECEDED_QUARANTINE_MARKER,
        clip(words || "a quarantine record"),
      );
      severity = raise(severity);
    }
    if (description === (e.description ?? "") && severity === e.severity) return e;
    return { ...e, description, ...(severity !== undefined ? { severity } : {}) };
  });
}
