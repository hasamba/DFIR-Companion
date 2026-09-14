import type { ForensicEvent, IOC } from "./stateTypes.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import { actionableAssertions } from "./intelViews.js";

// The infection window on a mobile extraction (#932 item 18 — #988): the earliest SIGN of
// compromise on one subject device, and the rows of that device placed before or after it.
//
// WHAT A SIGN IS. An app-inventory row (the origin registry's `record: app-inventory` — an
// installed app the extraction lists) whose SHA-256 or package name is a case IOC with an
// ACTIONABLE malicious assertion (intelViews.ts: live now, not expired, revoked or legacy). Only
// that: a malicious URL a notification carried, a synced history row, a cached link — content
// the device HOLDS — never opens a window, because content held is not compromise of the device.
//
// WHAT A WINDOW IS PARTITIONED BY. The subject device the analyst named at import (`asset` on the
// rows). A device name a row carries (an iCloud tab's "Device Name") is an association, not the
// subject, and is never used here. Rows with no subject device get no window, and the fact is
// said in the note count, not hidden.
//
// WHAT THE NOTES SAY. Before the earliest sign: "before the earliest sign of compromise". After
// it: "after the earliest sign — malware present on the device is a POSSIBLE alternative source
// of this record; its capabilities are not read" (no capability readings exist in the codebase).
// Never a conclusion either way; never a severity change. Uncertainty is stated: the sign's
// clock is the store's or the table's, not an install time; an undated sign gives no window.
//
// Recomputed on every merge: own notes stripped first, one evaluation time, at most one note per
// row — a revoked assertion takes its window away with it.

export const INFECTION_WINDOW_MARKER = "[infection window:";
const OWN_NOTE = /\s*\[infection window:[\s\S]{0,600}?\]/gu;
const NOTE_MAX = 500;

interface Sign {
  at: number;
  iso: string;
  what: string;
}

const ms = (iso: string | undefined): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

const isMobile = (e: ForensicEvent): boolean => !!e.canonical?.mobile;

/**
 * The malicious app-inventory signs per subject device — the earliest DATED one; a device with a
 * qualifying UNDATED inventory row gets no window at all, since that row may precede every dated
 * one. Only the block's typed package and digest are compared, never the rendered text.
 */
export function infectionSigns(
  events: readonly ForensicEvent[],
  iocs: readonly IOC[],
  at: string,
): Map<string, Sign> {
  const hashes = new Map<string, string>(); // lowercased sha256 → what
  const packages = new Map<string, string>(); // lowercased package → what
  for (const ioc of iocs) {
    const live = actionableAssertions(ioc, at).filter((a) => a.verdict === "malicious");
    if (!live.length) continue;
    const what = `${ioc.value} (${live[0].source}: malicious)`;
    if (ioc.type === "hash" && /^[0-9a-f]{64}$/i.test(ioc.value)) hashes.set(ioc.value.toLowerCase(), what);
    else if (ioc.type === "other" || ioc.type === "process" || ioc.type === "file")
      packages.set(ioc.value.toLowerCase(), what);
  }
  const signs = new Map<string, Sign>();
  if (!hashes.size && !packages.size) return signs;
  const undatedSign = new Set<string>();
  for (const e of events) {
    const m = e.canonical?.mobile;
    if (!m || m.facets.record !== "app-inventory" || !e.asset || !m.app) continue;
    const what =
      (m.app.sha256 ? hashes.get(m.app.sha256.toLowerCase()) : undefined) ??
      (m.app.package ? packages.get(m.app.package.toLowerCase()) : undefined);
    if (!what) continue;
    const t = ms(e.timestamp);
    if (t === null) {
      undatedSign.add(e.asset);
      continue;
    }
    const prev = signs.get(e.asset);
    if (!prev || t < prev.at) signs.set(e.asset, { at: t, iso: e.timestamp, what });
  }
  for (const asset of undatedSign) signs.delete(asset);
  return signs;
}

function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  return [base, notes.replace(OWN_NOTE, "").trim()].filter(Boolean).join(" ");
}

/**
 * Place every mobile row of a subject device before or after that device's earliest sign. Pure;
 * idempotent; only ever adds the note.
 */
export function markInfectionWindow(
  events: readonly ForensicEvent[],
  iocs: readonly IOC[],
  at: string = new Date().toISOString(),
): ForensicEvent[] {
  const signs = infectionSigns(events, iocs, at);
  return events.map((e) => {
    const base = withoutOwnNotes(e.description);
    if (!isMobile(e) || !e.asset) return base === (e.description ?? "") ? e : { ...e, description: base };
    const sign = signs.get(e.asset);
    const t = ms(e.timestamp);
    if (!sign || t === null) return base === (e.description ?? "") ? e : { ...e, description: base };
    const note =
      t < sign.at
        ? `before the earliest sign of compromise on ${e.asset} (${sign.what} listed at ${sign.iso}; an inventory row's clock is the store's or the table's, not an install time)`
        : `after the earliest sign of compromise on ${e.asset} (${sign.what} listed at ${sign.iso}) — malware present on the device is a POSSIBLE alternative source of this record; its capabilities are not read; presence alone neither attributes nor explains away this row`;
    const description = appendDerivedNote(base, INFECTION_WINDOW_MARKER, note.slice(0, NOTE_MAX));
    return description === e.description ? e : { ...e, description };
  });
}
