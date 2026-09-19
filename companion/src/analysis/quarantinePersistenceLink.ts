// The quarantine-database record and the launchd job whose program carries the same event
// identifier, joined at merge time across uploads (#1037 link 2, the persistence-target path).
//
// A persistence collection (text under `==>` headers) and a quarantine-database dump (CSV / JSON)
// are never one upload, so link 1's within-upload join (quarantineJoin.ts) cannot reach this pair.
// They meet here, in a merge-time pass over the forensic timeline, like the Windows download-mark
// ↔ execution join (downloadExecution.ts, #985): the persistence finding gains the download facts
// the database record carries (the URL it does not), and the database row gains the program it
// marked and the job that runs it. The join is by the event identifier alone — never a basename, a
// URL segment, a path or a time — and every refused join says why on both sides.
//
// What the pair establishes: a download event was logged, and the file it marked is set to run
// by launchd. It does not establish that the file ran (no execution record is read here), that
// the file is malicious, or — when the database record names a host and the persistence
// collection names none, which is the usual case — that both records are from one host; the note
// says the host was not compared. The database row is raised to Medium so it survives the Info
// demote and reaches the forensic timeline beside the finding it explains — Medium at most, the
// cap the browser-visit join puts on a mark (downloadVisitOrigin.ts); the persistence row keeps
// the severity its own evidence earned (the grader already raises a download-flagged mark).
//
// Cross-import limitation, the same one #985 and #1092 document: an Info database row imported
// BEFORE the persistence collection is demoted to the super-timeline before this pass can see
// it. The manual says which order to import in, and a re-import of the database dump after the
// collection is the recovery. The notes are recomputed from the current evidence on every merge.

import type { QuarantineAttributeBlock, QuarantineBlock } from "./canonicalQuarantine.js";
import { neutral } from "./downloadCorroborationShared.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import {
  flagTags,
  quarantineAgentAgreement,
  quarantineFlagFacts,
  quarantineTimeAgreement,
  timeWords,
} from "./quarantineAgreement.js";
import type { Severity } from "./stateTypes.js";

export const DOWNLOAD_EVENT_MARKER = "[download record:";
export const PERSISTED_MARKER = "[persisted as:";
/** Distinct database identifiers indexed per pass; a target past the bound says so. */
export const LINK_IDS_MAX = 8_192;
const TARGETS_PER_ID_MAX = 256;
const TARGETS_SHOWN_MAX = 3;
const SHOWN_MAX = 120;
const RAISED: Severity = "Medium";
const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

export interface QuarantineLinkEventShape {
  id?: string;
  description?: string;
  severity?: Severity;
  timestamp?: string;
  canonical?: { quarantine?: QuarantineBlock; quarantineAttribute?: QuarantineAttributeBlock };
}

const OWN_NOTE_NAMES = [DOWNLOAD_EVENT_MARKER, PERSISTED_MARKER].map((m) => m.slice(1, -1));
const OWN_NOTES_RE = new RegExp(
  `\\s*\\[(?:${OWN_NOTE_NAMES.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")}):[\\s\\S]{0,1200}?\\]`,
  "gu",
);

function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  const kept = notes.replace(OWN_NOTES_RE, "");
  return [base, kept.trim()].filter(Boolean).join(" ");
}

const show = (v: string | undefined): string => {
  const t = neutral(v ?? "");
  return t.length > SHOWN_MAX ? `${t.slice(0, SHOWN_MAX - 1)}…` : t;
};

// ───────────────────────────── the database side ─────────────────────────────

interface DbGroup<T> {
  rows: T[];
  /** Distinct fact sets among the rows — more than one is #1009's disagreement, and joins nothing. */
  variants: Set<string>;
}

const dbBlock = <T extends QuarantineLinkEventShape>(e: T): QuarantineBlock | undefined => {
  const q = e.canonical?.quarantine;
  return q && !q.folded && q.eventId ? q : undefined;
};

const factsKey = (q: QuarantineBlock): string =>
  [q.kind, q.typeRaw, q.agent, q.bundleId, q.dataUrl, q.originUrl, q.senderName, q.senderAddress]
    .map((v) => v ?? "")
    .join("\u0000");

/** Database rows by identifier — earliest records first, and at most LINK_IDS_MAX identifiers. */
function indexDatabase<T extends QuarantineLinkEventShape>(
  events: readonly T[],
): { groups: Map<string, DbGroup<T>>; overflow: boolean } {
  const rows = events
    .filter((e) => dbBlock(e) !== undefined)
    .sort(
      (a, b) =>
        (a.timestamp ?? "").localeCompare(b.timestamp ?? "") ||
        dbBlock(a)!.eventId!.localeCompare(dbBlock(b)!.eventId!),
    );
  const groups = new Map<string, DbGroup<T>>();
  let overflow = false;
  for (const e of rows) {
    const q = dbBlock(e)!;
    const id = q.eventId!.toLowerCase();
    let g = groups.get(id);
    if (!g) {
      if (groups.size >= LINK_IDS_MAX) {
        overflow = true;
        continue;
      }
      g = { rows: [], variants: new Set() };
      groups.set(id, g);
    }
    g.rows.push(e);
    g.variants.add(factsKey(q));
  }
  return { groups, overflow };
}

// ───────────────────────────── the persistence side ─────────────────────────────

interface Target<T> {
  event: T;
  block: QuarantineAttributeBlock;
  id: string;
}

function targetsOf<T extends QuarantineLinkEventShape>(events: readonly T[]): Target<T>[] {
  const out: Target<T>[] = [];
  for (const event of events) {
    const block = event.canonical?.quarantineAttribute;
    if (
      block?.role !== "persistence-target" ||
      !block.mark ||
      !("eventId" in block.mark) ||
      !block.mark.eventId
    )
      continue;
    out.push({ event, block, id: block.mark.eventId.toLowerCase() });
  }
  return out;
}

const dbHost = (q: QuarantineBlock): { name?: string; ambiguous: boolean } =>
  !q.host || "state" in q.host
    ? { ambiguous: q.host?.state === "2 values in this record" }
    : { name: q.host.name, ambiguous: false };

const agentWords = (q: QuarantineBlock): string =>
  [q.agent, q.bundleId ? `(${q.bundleId})` : ""].filter(Boolean).join(" ");

/** The words the persistence row gets for one database group — a joined pair's facts, or why not. */
function downloadNote<T extends QuarantineLinkEventShape>(
  t: Target<T>,
  g: DbGroup<T>,
): { note: string; joined: boolean } {
  if (g.variants.size > 1)
    return { note: "database records with this identifier disagree — not joined", joined: false };
  const q = dbBlock(g.rows[0])!;
  const host = dbHost(q);
  if (host.ambiguous) return { note: "the database record names two hosts — not joined", joined: false };
  const mark = t.block.mark as Extract<QuarantineAttributeBlock["mark"], { eventId?: string }>;
  const parts = [
    `data url ${show(q.dataUrl) || "not in this record"}`,
    `origin ${show(q.originUrl) || "not in this record"}`,
    `agent ${show(agentWords(q)) || "not in this record"}`,
  ];
  const tags = [`${parts.join("; ")} — the database record with this event identifier`];
  const agent = quarantineAgentAgreement(mark.agent, q);
  if (agent === "agrees") tags.push("agent agrees");
  else if (agent === "differs")
    tags.push(`agent differs: attribute ${show(mark.agent)}; database ${show(agentWords(q))}`);
  tags.push(timeWords(quarantineTimeAgreement(mark.time, g.rows[0].timestamp ?? "", q.timeEncoding)));
  tags.push(...flagTags(quarantineFlagFacts(mark)));
  tags.push(
    host.name
      ? `host not compared — the persistence collection names no host; the database record names ${show(host.name)}`
      : "host not compared — the persistence collection names no host",
  );
  return { note: tags.join("; "), joined: true };
}

/** The words the database row gets for the targets that carry its identifier. */
function persistedNote<T extends QuarantineLinkEventShape>(
  targets: readonly Target<T>[],
  disagree: boolean,
): string {
  if (disagree)
    return "a launchd job's program carries this event identifier, but the database records with it disagree — not joined";
  const shown = targets.slice(0, TARGETS_SHOWN_MAX).map((t) => {
    const label = t.block.persistence?.label ? ` (${show(t.block.persistence.label)})` : "";
    return `${show(t.block.path)}${label}`;
  });
  const more = targets.length - shown.length;
  if (targets.length === 1) {
    const t = targets[0];
    const job = t.block.persistence?.label
      ? `launchd job ${show(t.block.persistence.label)}`
      : "a launchd job";
    const artifact = t.block.persistence?.artifact ? ` (${show(t.block.persistence.artifact)})` : "";
    return `${show(t.block.path)} — the program of ${job}${artifact}; its quarantine attribute carries this event identifier — set to run by launchd; whether it ran is not established by these records`;
  }
  return `${targets.length} launchd programs — ${shown.join(", ")}${more > 0 ? ` and ${more} more` : ""} — the same identifier on several files: a copy, or an archive's extracted members; the records do not say which — set to run by launchd; whether any ran is not established by these records`;
}

// ───────────────────────────── the pass ─────────────────────────────

export function linkQuarantinePersistence<T extends QuarantineLinkEventShape>(events: readonly T[]): T[] {
  const targets = targetsOf(events);
  const stripped = (e: T): T => {
    const description = withoutOwnNotes(e.description);
    return description === (e.description ?? "") ? e : { ...e, description };
  };
  if (!targets.length) return events.map(stripped);

  const { groups, overflow } = indexDatabase(events);
  const targetNotes = new Map<T, string>();
  const byId = new Map<string, Target<T>[]>();
  const joinedIds = new Set<string>();
  for (const t of targets) {
    const g = groups.get(t.id);
    if (!g) {
      if (overflow)
        targetNotes.set(t.event, `not compared — more than ${LINK_IDS_MAX} database identifiers in the case`);
      continue;
    }
    const list = byId.get(t.id) ?? [];
    if (list.length < TARGETS_PER_ID_MAX) list.push(t);
    byId.set(t.id, list);
    const { note, joined } = downloadNote(t, g);
    targetNotes.set(t.event, note);
    if (joined) joinedIds.add(t.id);
  }

  return events.map((raw) => {
    const e = stripped(raw);
    const targetNote = targetNotes.get(raw);
    if (targetNote !== undefined)
      return { ...e, description: appendDerivedNote(e.description, DOWNLOAD_EVENT_MARKER, targetNote) };
    const q = dbBlock(raw);
    if (!q) return e;
    const id = q.eventId!.toLowerCase();
    const list = byId.get(id);
    if (!list?.length) return e;
    const g = groups.get(id)!;
    const disagree = g.variants.size > 1 || dbHost(q).ambiguous;
    const description = appendDerivedNote(e.description, PERSISTED_MARKER, persistedNote(list, disagree));
    const severity = joinedIds.has(id) && RANK[e.severity ?? "Info"] < RANK[RAISED] ? RAISED : e.severity;
    return { ...e, description, ...(severity !== undefined ? { severity } : {}) };
  });
}
