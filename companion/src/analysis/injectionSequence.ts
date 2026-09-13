// Injection and hollowing sequences, joined by process GUID (#932 item 9, second half — #987).
//
// processAccess.ts (#986) made each Sysmon 10 / 8 / 25 record say what it establishes on its own;
// the SEQUENCE — a write-capable handle, then a remote thread from the same source into the same
// target; a process created, its image replaced, then reached into — is a join across records that
// meets here, at merge time, like the download-mark corroboration (#985).
//
// What the pass establishes: that two records name the same source and target process by GUID
// (a pid + host fallback for feeds without GUIDs, worded as such), in what order by the sensor's
// own clock, and which parts of the shape it saw. It does not establish that memory was written
// (Sysmon never records the write — the note says so), that the code was hostile, or that time
// proximity links two processes: nothing joins on an image name or on closeness in time alone.
// The structured facts it reads are the envelope's — `event.action` (the rights, the thread
// start, the tamper type, the source's path-anchored trust) and the subject / object identities —
// never the prose; a row that predates those fields says so.

import type { Severity } from "./stateTypes.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import { shortHost } from "./correlate.js";

/** The markers this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const INJECTION_SEQUENCE_MARKER = "[injection sequence:";
export const HOLLOWING_SEQUENCE_MARKER = "[hollowing sequence:";

/** A remote thread this long after a write-capable handle is inside the injection window. */
export const INJECTION_WINDOW_MS = 10 * 60 * 1000;
/** GUID-less rows join by pid only inside this window on one host. */
export const PID_FALLBACK_WINDOW_MS = 60 * 60 * 1000;
/** Rows read per index bucket, by event time; the rest are counted. */
export const BUCKET_MAX = 64;
const SEQUENCES_NAMED_MAX = 4;
const EXCERPT_MAX = 120;
const NOTE_MAX = 900;

interface Entity {
  kind?: string;
  id?: string;
  name?: string;
  pid?: number;
}

interface TimelineEventShape {
  id?: string;
  description?: string;
  asset?: string;
  severity?: Severity;
  mitreTechniques?: string[];
  timestamp?: string;
  processName?: string;
  pid?: number;
  canonical?: {
    event?: { category?: string; type?: string; action?: string };
    subject?: Entity;
    object?: Entity;
    process?: { id?: string; pid?: number; name?: string; parent?: { name?: string } };
  };
}

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ───────────────────────────── readings ─────────────────────────────

/** Brackets to parentheses, control characters and hash runs neutralised (recordIdentity.ts, restated for the timeline layer). */
const neutral = (t: string): string =>
  t
    .replace(/\[/g, "(")
    .replace(/\]/g, ")")
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/[a-f0-9]{32,}/gi, (m) => `${m.slice(0, 8)}…${m.slice(-4)}`)
    .trim();
const excerpt = (s: string): string => neutral(s).slice(0, EXCERPT_MAX);

const ms = (iso: string | undefined): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

function gapWords(gapMs: number): string {
  const s = Math.abs(gapMs) / 1000;
  if (s < 10) return `${Math.round(s * 10) / 10} s`;
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${Math.round(s / 3600)} h`;
}

/** A process identity as the record carries it: a GUID, or a pid with its host as the fallback. */
interface Identity {
  guid: string;
  pid?: number;
  name: string;
}

const identityOf = (e: Entity | undefined): Identity | null => {
  if (!e) return null;
  const id = (e.id ?? "").trim().toLowerCase();
  const guid = GUID.test(id) ? id : "";
  const pid = e.pid ?? (id.startsWith("pid:") ? Number(id.slice(4)) : undefined);
  return { guid, ...(pid !== undefined && Number.isFinite(pid) ? { pid } : {}), name: e.name ?? "" };
};

type Kind = "access" | "thread" | "tamper" | "start";

interface Rec<T> {
  event: T;
  kind: Kind;
  host: string;
  time: number | null;
  source: Identity | null;
  target: Identity;
  action: string;
  /** The per-record rule marked the source a path-anchored system image. */
  systemSource: boolean;
}

function classify<T extends TimelineEventShape>(e: T): Rec<T> | null {
  const ev = e.canonical?.event;
  if (ev?.category !== "process") return null;
  const action = ev.action ?? "";
  const host = shortHost(e.asset);
  const time = ms(e.timestamp);
  const systemSource = action.includes(";source=system-path");
  if (ev.type === "access" || ev.type === "remote_thread") {
    const source = identityOf(e.canonical?.subject);
    const target = identityOf(e.canonical?.object);
    if (!target) return null;
    return {
      event: e,
      kind: ev.type === "access" ? "access" : "thread",
      host,
      time,
      source,
      target,
      action,
      systemSource,
    };
  }
  if (ev.type === "tamper") {
    const target = identityOf(e.canonical?.object);
    if (!target) return null;
    return { event: e, kind: "tamper", host, time, source: null, target, action, systemSource: false };
  }
  if (ev.type === "start") {
    const p = e.canonical?.process;
    const guid = (p?.id ?? "").trim().toLowerCase();
    if (!GUID.test(guid) && p?.pid === undefined) return null;
    return {
      event: e,
      kind: "start",
      host,
      time,
      source: null,
      target: {
        guid: GUID.test(guid) ? guid : "",
        ...(p?.pid !== undefined ? { pid: p.pid } : {}),
        name: p?.name ?? "",
      },
      action,
      systemSource: false,
    };
  }
  return null;
}

// The structured rights: `access:<rights or state>`; absent on a row that predates the mapping.
type Rights =
  { state: "structured"; writeCapable: boolean; threadCapable: boolean; words: string } | { state: "legacy" };

function rightsOf(action: string): Rights {
  const m = /^access:([^;]*)/.exec(action);
  if (!m) return { state: "legacy" };
  const key = m[1];
  const rights = new Set(
    key
      .split(",")
      .map((r) => r.trim().toLowerCase())
      .filter(Boolean),
  );
  const all = rights.has("all_access");
  const writeCapable = all || (rights.has("vm_write") && rights.has("vm_operation"));
  const threadCapable = all || rights.has("create_thread");
  return { state: "structured", writeCapable, threadCapable, words: key.toUpperCase().replace(/,/g, "|") };
}

function startWords(action: string): string {
  const m = /^thread:(unbacked|module|absent)(?::([^;]*))?/.exec(action);
  if (!m) return "start not in the row's data — this row may predate the sequence mapping";
  if (m[1] === "unbacked") return `starting at ${excerpt(m[2] || "an address")} — outside any module`;
  if (m[1] === "module") return `starting at ${excerpt(m[2] || "a module")}`;
  return "start module not in the record";
}

const isReplaced = (action: string): boolean => /^tamper:.*image is replaced/.test(action);

// ───────────────────────────── identity keys ─────────────────────────────

/** Two identities name one process when both carry a GUID and it matches, or neither does and the pid does (on one host). */
function pairKeys(
  host: string,
  source: Identity | null,
  target: Identity,
): { key: string; byPid: boolean }[] {
  if (!source) return [];
  if (source.guid && target.guid) return [{ key: `g|${host}|${source.guid}|${target.guid}`, byPid: false }];
  if (!source.guid && !target.guid && source.pid !== undefined && target.pid !== undefined && host)
    return [{ key: `p|${host}|${source.pid}|${target.pid}`, byPid: true }];
  return [];
}

function targetKeys(host: string, target: Identity): { key: string; byPid: boolean }[] {
  if (target.guid) return [{ key: `g|${host}|${target.guid}`, byPid: false }];
  if (target.pid !== undefined && host) return [{ key: `p|${host}|${target.pid}`, byPid: true }];
  return [];
}

interface Bucket<T> {
  rows: Rec<T>[];
  beyond: number;
}

/** Buckets keep the first BUCKET_MAX rows by event time — the same rows in any upload order. */
function bucketed<T extends TimelineEventShape>(
  rows: Rec<T>[],
  keyOf: (r: Rec<T>) => string[],
): Map<string, Bucket<T>> {
  const sorted = [...rows].sort(
    (a, b) =>
      (a.time ?? Number.MAX_SAFE_INTEGER) - (b.time ?? Number.MAX_SAFE_INTEGER) ||
      (a.event.id ?? "").localeCompare(b.event.id ?? ""),
  );
  const out = new Map<string, Bucket<T>>();
  for (const r of sorted)
    for (const k of keyOf(r)) {
      const b = out.get(k) ?? out.set(k, { rows: [], beyond: 0 }).get(k)!;
      if (b.rows.length < BUCKET_MAX) b.rows.push(r);
      else b.beyond += 1;
    }
  return out;
}

// ───────────────────────────── notes ─────────────────────────────

interface Note {
  words: string[];
  more: number;
  raise: boolean;
  mitre: string[];
  beyond: number;
}

function noteFor<T>(notes: Map<T, Note>, e: T): Note {
  return notes.get(e) ?? notes.set(e, { words: [], more: 0, raise: false, mitre: [], beyond: 0 }).get(e)!;
}

function say<T>(notes: Map<T, Note>, e: T, words: string, raise: boolean, mitre: string[] = []): void {
  const n = noteFor(notes, e);
  if (n.words.length < SEQUENCES_NAMED_MAX) n.words.push(words);
  else n.more += 1;
  if (raise) n.raise = true;
  for (const m of mitre) if (!n.mitre.includes(m)) n.mitre.push(m);
}

const procWords = (i: Identity): string =>
  `${excerpt(i.name || "a process")}${i.guid ? ` (guid ${i.guid.slice(0, 8)}…)` : i.pid !== undefined ? ` (pid ${i.pid})` : ""}`;

const MARKERS = [INJECTION_SEQUENCE_MARKER, HOLLOWING_SEQUENCE_MARKER];
const NOTE_NAMES = MARKERS.map((m) => m.slice(1, -1));

function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  const kept = notes.replace(
    new RegExp(
      `\\s*\\[(?:${NOTE_NAMES.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")}):[\\s\\S]{0,1200}?\\]`,
      "gu",
    ),
    "",
  );
  return [base, kept.trim()].filter(Boolean).join(" ");
}

const clipNote = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);

// ───────────────────────────── the pass ─────────────────────────────

/**
 * Join every Sysmon 10 / 8 / 25 / 1 row into the injection and hollowing sequences the case
 * carries, by process GUID (or pid + host for GUID-less feeds, worded). Only ever raises; recomputes
 * its own notes from the current evidence on every merge.
 */
export function corroborateInjectionSequences<T extends TimelineEventShape>(events: readonly T[]): T[] {
  const recs = events.map(classify).filter((r): r is Rec<T> => r !== null);
  const anyThread = recs.some((r) => r.kind === "thread");
  const anyTamper = recs.some((r) => r.kind === "tamper" && isReplaced(r.action));
  if (!anyThread && !anyTamper)
    return events.map((e) => {
      const description = withoutOwnNotes(e.description);
      return description === (e.description ?? "") ? e : { ...e, description };
    });

  const injection = new Map<T, Note>();
  const hollowing = new Map<T, Note>();

  // Sequence A: a write- or thread-capable handle, then a remote thread from the same source
  // into the same target — the pair keyed on both endpoints.
  const accessByPair = bucketed(
    recs.filter((r) => r.kind === "access"),
    (r) => pairKeys(r.host, r.source, r.target).map((k) => k.key),
  );
  for (const thread of recs.filter((r) => r.kind === "thread")) {
    for (const { key, byPid } of pairKeys(thread.host, thread.source, thread.target)) {
      const bucket = accessByPair.get(key);
      if (!bucket) continue;
      const window = byPid ? Math.min(INJECTION_WINDOW_MS, PID_FALLBACK_WINDOW_MS) : INJECTION_WINDOW_MS;
      for (const access of bucket.rows) {
        const rights = rightsOf(access.action);
        const capable = rights.state === "structured" && (rights.writeCapable || rights.threadCapable);
        if (rights.state === "structured" && !capable) continue;
        const gap = thread.time !== null && access.time !== null ? thread.time - access.time : null;
        const order =
          gap === null
            ? "order not established (no readable time)"
            : gap < 0
              ? `not the sequence: the thread precedes the handle by ${gapWords(gap)}`
              : gap > window
                ? `not the sequence: the thread is ${gapWords(gap)} after the handle, outside the window`
                : `remote thread ${gapWords(gap)} later`;
        const inSequence = gap !== null && gap >= 0 && gap <= window;
        const shape =
          rights.state === "legacy"
            ? "handle (structured rights unavailable — this row may predate the sequence mapping)"
            : rights.writeCapable
              ? `write-capable handle ${rights.words}`
              : `thread-capable handle ${rights.words}`;
        const caveat = byPid ? "; by pid — PID reuse not excluded" : "";
        const benign = access.systemSource && thread.systemSource;
        const raise = inSequence && rights.state === "structured" && !benign;
        const label = inSequence
          ? rights.state === "structured"
            ? `injection-shaped: ${shape} from ${procWords(thread.source!)} into ${procWords(thread.target)}, then ${order} ${startWords(thread.action)} — access, then execution transfer; no memory write was recorded${benign ? "; source is a path-anchored system image — shape kept, grade not raised" : ""}`
            : `${shape} from ${procWords(thread.source!)} into ${procWords(thread.target)}, then ${order} ${startWords(thread.action)}`
          : `${shape} from ${procWords(thread.source!)} into ${procWords(thread.target)}; ${order}`;
        const mitre = raise ? ["T1055"] : [];
        say(injection, thread.event, `${label}${caveat}`, raise, mitre);
        say(injection, access.event, `${label}${caveat}`, raise, mitre);
      }
      if (bucket.beyond) noteFor(injection, thread.event).beyond += bucket.beyond;
    }
  }

  // Sequence B: a process created, its image replaced, then reached into — keyed on the target.
  const startsByTarget = bucketed(
    recs.filter((r) => r.kind === "start"),
    (r) => targetKeys(r.host, r.target).map((k) => k.key),
  );
  const intoByTarget = bucketed(
    recs.filter((r) => r.kind === "thread" || r.kind === "access"),
    (r) => targetKeys(r.host, r.target).map((k) => k.key),
  );
  for (const tamper of recs.filter((r) => r.kind === "tamper" && isReplaced(r.action))) {
    for (const { key, byPid } of targetKeys(tamper.host, tamper.target)) {
      const caveat = byPid ? "; by pid — PID reuse not excluded" : "";
      const starts = (startsByTarget.get(key)?.rows ?? []).filter(
        (s) =>
          s.time === null ||
          tamper.time === null ||
          (tamper.time >= s.time && (!byPid || tamper.time - s.time <= PID_FALLBACK_WINDOW_MS)),
      );
      const start = starts[starts.length - 1];
      const created = start
        ? `created ${start.time !== null ? new Date(start.time).toISOString() : "at a time not readable"}${start.event.canonical?.process?.parent?.name ? ` by ${excerpt(start.event.canonical.process.parent.name)}` : ""}`
        : "creation not in the case (or imported before this version)";
      const replaced =
        start && start.time !== null && tamper.time !== null
          ? `image replaced ${gapWords(tamper.time - start.time)} after creation`
          : "image replaced";
      const into = (intoByTarget.get(key)?.rows ?? []).filter(
        (r) =>
          r.time === null ||
          tamper.time === null ||
          (r.time >= tamper.time && r.time - tamper.time <= INJECTION_WINDOW_MS),
      );
      const reached = into.length
        ? `${into.length === 1 ? "a" : into.length} ${into[0].kind === "thread" ? "remote thread" : "handle"}${into.length > 1 ? "s / threads" : ""} into it ${into[0].time !== null && tamper.time !== null ? `${gapWords(into[0].time - tamper.time)} later` : ""}`.trim()
        : "no handle or thread into it seen";
      const words = `${procWords(tamper.target)}: ${created}; ${replaced}; ${reached}; suspended / resumed not in the records${caveat}`;
      say(hollowing, tamper.event, words, true, ["T1055.012"]);
      if (start)
        say(hollowing, start.event, `${replaced} — ${procWords(tamper.target)}${caveat}`, true, [
          "T1055.012",
        ]);
      for (const r of into)
        say(
          hollowing,
          r.event,
          `into a process whose image was replaced ${tamper.time !== null && r.time !== null ? gapWords(r.time - tamper.time) : ""} earlier — ${procWords(tamper.target)}${caveat}`.replace(
            "  ",
            " ",
          ),
          false,
        );
      const beyond = (startsByTarget.get(key)?.beyond ?? 0) + (intoByTarget.get(key)?.beyond ?? 0);
      if (beyond) noteFor(hollowing, tamper.event).beyond += beyond;
    }
  }

  const apply = (
    description: string,
    severity: Severity,
    marker: string,
    n: Note | undefined,
  ): { description: string; severity: Severity; mitre: string[] } => {
    if (!n) return { description, severity, mitre: [] };
    // The counts are never clipped away: the named sequences fill what the tail leaves.
    const tail = [
      ...(n.more ? [`+${n.more} more`] : []),
      ...(n.beyond ? [`${n.beyond} rows beyond the index were not evaluated`] : []),
    ];
    const named: string[] = [];
    let omitted = 0;
    for (const w of n.words) {
      const rest = n.words.length - named.length - 1 + n.more;
      const withMore = rest > 0 ? `; +${rest} more` : "";
      const length =
        [...named, w].join("; ").length + withMore.length + (n.beyond ? tail[tail.length - 1].length + 2 : 0);
      if (length > NOTE_MAX) {
        omitted = n.words.length - named.length;
        break;
      }
      named.push(w);
    }
    const more = n.more + omitted;
    const parts = [
      ...named,
      ...(more ? [`+${more} more`] : []),
      ...(n.beyond ? [`${n.beyond} rows beyond the index were not evaluated`] : []),
    ];
    return {
      description: appendDerivedNote(description, marker, clipNote(parts.join("; "))),
      severity: n.raise && RANK.High > RANK[severity] ? "High" : severity,
      mitre: n.raise ? n.mitre : [],
    };
  };
  return events.map((e) => {
    let description = withoutOwnNotes(e.description);
    let severity: Severity = e.severity ?? "Info";
    const mitre = [...(e.mitreTechniques ?? [])];
    for (const [marker, notes] of [
      [INJECTION_SEQUENCE_MARKER, injection],
      [HOLLOWING_SEQUENCE_MARKER, hollowing],
    ] as const) {
      const out = apply(description, severity, marker, notes.get(e));
      description = out.description;
      severity = out.severity;
      for (const m of out.mitre) if (!mitre.includes(m)) mitre.push(m);
    }
    const same =
      description === (e.description ?? "") &&
      severity === (e.severity ?? "Info") &&
      mitre.length === (e.mitreTechniques ?? []).length;
    return same ? e : { ...e, description, severity, mitreTechniques: mitre };
  });
}
