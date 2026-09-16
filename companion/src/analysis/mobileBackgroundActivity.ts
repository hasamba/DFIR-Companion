import type { ForensicEvent } from "./stateTypes.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";

// App-identity corroboration across independent iOS artifacts (#932 item 16): when the same app,
// on the same subject device, is named by two or more of knowledgeC App Usage, PowerLog
// Application Runtime, netusage App Data, TCC Application Permissions and Notification Duet, say
// so on the group's primary row. Presence only — never a byte total, a second count or a duration
// threshold. "Energy use is not execution of a particular malicious function," and a notification
// is a message received, not read; this pass never concludes anything, it only says which
// independent records also name the app.
//
// NOT THE INFECTION WINDOW (#988, mobileInfectionWindow.ts). That pass gates on a live malicious
// IOC match — a sign already known bad. This one is the opposite kind of tool: it helps an analyst
// FIND a candidate worth looking at, by showing that several independent artifacts agree an app
// exists and did something, with no verdict attached. Gating this pass on the same IOC signal would
// make it redundant with the infection window and defeat the item's own purpose.
//
// WHY ONE NOTE PER GROUP, NOT PER ROW. PowerLog alone can carry tens of thousands of rows per
// image; a note on every one of them would be noise, not evidence. One note lands on the group's
// EARLIEST row of its PRIMARY kind — power, then usage, then network, then permission, then
// notification, in that order over whichever kinds are actually present — so every corroborated
// group always has somewhere to put its note, even a `{permission, notification}` group from a
// partial collection with no PowerLog or netusage.
//
// Recomputed on every merge, like the infection window: own notes stripped first, one note per
// group, never a severity change.

export const APP_CORROBORATION_MARKER = "[app corroboration:";
const OWN_NOTE = /\s*\[app corroboration:[\s\S]{0,600}?\]/gu;
const NOTE_MAX = 500;
const NAME_MAX = 200;
const ASSET_MAX = 120;
const ACCESS_MAX = 60;
// A name inside the note: brackets to parentheses so the note's own bracket stays its end (same
// rule mobileOriginRegistry.ts's own tag uses, kept local here to avoid an ingest->timeline import
// the boundary check forbids — a one-line pure function, not worth a shared module for two callers).
const tagSafe = (v: string): string => v.replace(/\[/g, "(").replace(/\]/g, ")");

// Precedence order: the first of these present in a group is where its note lands.
const CORROBORATING_KINDS = ["power", "usage", "network", "permission", "notification"] as const;
type CorroboratingKind = (typeof CORROBORATING_KINDS)[number];

const KIND_LABEL: Record<CorroboratingKind, string> = {
  power: "power record",
  usage: "usage record",
  network: "network record",
  permission: "permission record",
  notification: "notification record",
};

function kindOf(record: string): CorroboratingKind | undefined {
  return (CORROBORATING_KINDS as readonly string[]).includes(record)
    ? (record as CorroboratingKind)
    : undefined;
}

interface GroupRow {
  event: ForensicEvent;
  kind: CorroboratingKind;
  access?: string;
}

interface Group {
  asset: string;
  /** The first-seen row's actual-case app package — display identity, never the lowercased join key. */
  display: string;
  rows: GroupRow[];
}

function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  return [base, notes.replace(OWN_NOTE, "").trim()].filter(Boolean).join(" ");
}

// Undated primary-kind rows sort after dated ones and keep file order among themselves (a stable
// sort against a shared Infinity value never reorders equal elements).
const ms = (iso: string | undefined): number => {
  if (!iso) return Number.POSITIVE_INFINITY;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : Number.POSITIVE_INFINITY;
};

/**
 * Group iOS mobile rows of one subject device by app identity, and note the group's primary row
 * with which OTHER independent artifacts also name that app — presence only, never a magnitude.
 * Pure; idempotent; only ever adds the note.
 */
export function markAppCorroboration(events: readonly ForensicEvent[]): ForensicEvent[] {
  const groups = new Map<string, Group>();
  for (const e of events) {
    const m = e.canonical?.mobile;
    if (!m || m.platform !== "ios" || !e.asset) continue;
    const pkg = m.app?.package?.trim();
    if (!pkg) continue;
    const kind = kindOf(m.facets.record);
    if (!kind) continue;
    const key = `${e.asset}\u0000${pkg.toLowerCase()}`;
    let g = groups.get(key);
    if (!g) {
      g = { asset: e.asset, display: pkg, rows: [] };
      groups.set(key, g);
    }
    const access = m.evidence.find((ev) => ev.facet === "access")?.value;
    g.rows.push({ event: e, kind, ...(access ? { access } : {}) });
  }

  const noteByEventId = new Map<string, string>();
  for (const g of groups.values()) {
    const kinds = new Set(g.rows.map((r) => r.kind));
    if (kinds.size < 2) continue; // one artifact alone is not corroboration
    const primaryKind = CORROBORATING_KINDS.find((k) => kinds.has(k))!;
    const primary = g.rows
      .filter((r) => r.kind === primaryKind)
      .sort((a, b) => ms(a.event.timestamp) - ms(b.event.timestamp))[0];

    // The TCC Access value rides in the OTHERS list only — when permission is the primary kind
    // itself, its Access value is not repeated here because it is already on that very row's own
    // `[origin: ...]` tag (mobileOriginRegistry.ts's own accessColumn handling), not lost.
    const accessValue = g.rows.find((r) => r.kind === "permission" && r.access)?.access;
    const others = CORROBORATING_KINDS.filter((k) => k !== primaryKind && kinds.has(k)).map((k) =>
      k === "permission" && accessValue
        ? `permission record (Access: ${tagSafe(accessValue.slice(0, ACCESS_MAX))})`
        : KIND_LABEL[k],
    );

    const guardrails: string[] = [];
    if (kinds.has("power") || kinds.has("usage"))
      guardrails.push("energy or usage presence does not establish which function ran");
    if (kinds.has("notification")) guardrails.push("a notification is a message received, not read");
    if (kinds.has("network"))
      guardrails.push("a network record is this app's own logged usage, not traffic attributed to it");

    const note =
      `${tagSafe(g.display.slice(0, NAME_MAX))} on ${tagSafe(g.asset.slice(0, ASSET_MAX))} also appears in: ` +
      `${others.join(", ")}${guardrails.length ? " — " + guardrails.join("; ") : ""}`;
    noteByEventId.set(primary.event.id, note.slice(0, NOTE_MAX));
  }

  return events.map((e) => {
    const base = withoutOwnNotes(e.description);
    const note = noteByEventId.get(e.id);
    if (!note) return base === (e.description ?? "") ? e : { ...e, description: base };
    const description = appendDerivedNote(base, APP_CORROBORATION_MARKER, note);
    return description === e.description ? e : { ...e, description };
  });
}
