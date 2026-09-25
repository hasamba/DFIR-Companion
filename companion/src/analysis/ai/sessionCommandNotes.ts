import {
  canonicalAccounts,
  canonicalFile,
  canonicalProcess,
  upgradeForensicEvent,
} from "../canonicalEvent.js";
import { byEventTime } from "../forensicSort.js";
import {
  SEVERITY_RANK,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type SessionCommand,
} from "../stateTypes.js";

/**
 * Quiet commands that no finding names (#1594).
 *
 * Synthesis groups findings by theme — credential theft, defense evasion. A lone discovery or
 * staging command (`net view /all`, `tasklist /v`, `subst E: C:\e`, a dropped `!start.cmd`) fits no
 * theme, so no finding names it, and a later run can drop a command an earlier run named while its
 * row stays in the timeline. This deterministic backstop runs after grading and lists each such
 * command on the closest finding, as a structured note — never as evidence the finding claims.
 *
 * WHAT IS READ. Only `scopedEvents`: the in-window, false-positive-filtered FORENSIC timeline that
 * synthesis itself reasoned over. Never the super-timeline (CLAUDE.md §7).
 *
 * THE ATTACK SESSION — conservative on purpose:
 *   - An anchor is a finding of Medium severity or higher that is not dismissed and not a
 *     build-baseline finding, and that cites at least one scoped row carrying a host.
 *   - Per host, the anchors' cited row times are sorted and split wherever two consecutive times are
 *     more than SESSION_GAP_MS apart. Each cluster, widened by SESSION_PAD_MS on both sides, is one
 *     session. A host with no anchor has no session, so nothing on it is ever noted.
 *
 * A CANDIDATE is a scoped row graded Low or higher (the tagger's verdict, not Info) inside a session
 * on its own host that carries a process command line, or that records a script or binary file
 * being written. Distinct per host and command text; the earliest row wins.
 *
 * NAMED means some non-dismissed finding's title or description already carries the command: the
 * full command, or its core (program plus its next two arguments, after unwrapping `cmd /c` and
 * `powershell -command`); a file write is named by its file name. A finding that cites the row and
 * names its program also counts.
 *
 * Each unnamed candidate is noted on the closest anchor on the same host: nearest cited row in time,
 * then a shared account, then the higher severity, then the lower finding id.
 */

export const SESSION_PAD_MS = 15 * 60_000;
export const SESSION_GAP_MS = 2 * 60 * 60_000;
/** One noted command, capped: the note is a pointer to the row, not a copy of it. */
export const MAX_NOTE_TEXT = 300;

const SCRIPT_OR_BINARY = /\.(?:cmd|bat|ps1|psm1|vbs|vbe|js|jse|wsf|hta|exe|dll|scr|lnk|msi)$/i;
const FILE_WRITE_TYPES = new Set(["create", "write", "modify"]);
const MEDIUM_RANK = SEVERITY_RANK.Medium;

export interface SessionCommandOptions {
  /** The in-window, false-positive-filtered forensic timeline synthesis read. */
  scopedEvents: readonly ForensicEvent[];
  /** Canonical host for a raw asset spelling (the alias index synthesis resolved). */
  hostOf?: (raw: string) => string;
}

interface Anchor {
  finding: Finding;
  host: string;
  times: number[];
  accounts: Set<string>;
}

interface Candidate {
  event: ForensicEvent;
  host: string;
  time: number;
  kind: SessionCommand["kind"];
  text: string;
  program: string;
  fileName?: string;
  accounts: string[];
}

/** Recompute every finding's `sessionCommands` from the scoped forensic timeline. Pure. */
export function noteSessionCommands(
  state: InvestigationState,
  opts: SessionCommandOptions,
): InvestigationState {
  const hostOf = opts.hostOf ?? ((raw: string) => raw.trim().toLowerCase());
  const byId = new Map(opts.scopedEvents.map((e) => [e.id, e] as const));
  const anchors = buildAnchors(state, byId, hostOf);
  const sessions = buildSessions(anchors);
  const live = state.findings.filter((f) => f.status !== "dismissed");
  const texts = new Map(live.map((f) => [f.id, findingText(f)] as const));
  const cited = citedBy(state, live);
  const hostsOf = findingHosts(state, live, byId, hostOf);

  const notes = new Map<string, SessionCommand[]>();
  for (const c of candidates(opts.scopedEvents, sessions, hostOf)) {
    if (isNamed(c, texts, cited, hostsOf)) continue;
    const target = closestAnchor(c, anchors);
    if (!target) continue;
    const list = notes.get(target.finding.id) ?? [];
    list.push(toNote(c));
    notes.set(target.finding.id, list);
  }
  return {
    ...state,
    findings: state.findings.map((f) => {
      const note = notes.get(f.id);
      if (note) return { ...f, sessionCommands: note };
      if (!f.sessionCommands) return f;
      const { sessionCommands: _stale, ...rest } = f;
      return rest;
    }),
  };
}

/** Keep only entries whose row is in the (projected, filtered) timeline — scope and false positives. */
export function pruneSessionCommands(state: InvestigationState): InvestigationState {
  if (!state.findings.some((f) => f.sessionCommands?.length)) return state;
  const visible = new Set(state.forensicTimeline.map((e) => e.id));
  return {
    ...state,
    findings: state.findings.map((f) => {
      if (!f.sessionCommands) return f;
      const kept = f.sessionCommands.filter((s) => visible.has(s.eventId));
      if (kept.length === f.sessionCommands.length) return f;
      if (kept.length) return { ...f, sessionCommands: kept };
      const { sessionCommands: _gone, ...rest } = f;
      return rest;
    }),
  };
}

function timeOf(e: ForensicEvent): number {
  const t = Date.parse(e.timestamp);
  return Number.isFinite(t) ? t : NaN;
}

/** Finding id -> the ids of the scoped rows it cites (forward links and back-links). */
function citedIds(state: InvestigationState, f: Finding): Set<string> {
  const ids = new Set(f.relatedEventIds ?? []);
  for (const e of state.forensicTimeline) if (e.relatedFindingIds.includes(f.id)) ids.add(e.id);
  return ids;
}

function citedBy(state: InvestigationState, findings: readonly Finding[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const f of findings) {
    for (const id of citedIds(state, f)) {
      const set = out.get(id) ?? new Set<string>();
      set.add(f.id);
      out.set(id, set);
    }
  }
  return out;
}

function buildAnchors(
  state: InvestigationState,
  byId: ReadonlyMap<string, ForensicEvent>,
  hostOf: (raw: string) => string,
): Anchor[] {
  const anchors: Anchor[] = [];
  for (const f of state.findings) {
    if (f.status === "dismissed" || f.buildBaseline || SEVERITY_RANK[f.severity] > MEDIUM_RANK) continue;
    const perHost = new Map<string, Anchor>();
    for (const id of citedIds(state, f)) {
      const e = byId.get(id);
      const time = e ? timeOf(e) : NaN;
      if (!e?.asset?.trim() || Number.isNaN(time)) continue;
      const host = hostOf(e.asset);
      const anchor = perHost.get(host) ?? { finding: f, host, times: [], accounts: new Set<string>() };
      anchor.times.push(time);
      for (const a of canonicalAccounts(e)) anchor.accounts.add(a.toLowerCase());
      perHost.set(host, anchor);
    }
    anchors.push(...perHost.values());
  }
  return anchors;
}

/** Host -> [start, end] windows: anchor times split at gaps over SESSION_GAP_MS, then padded. */
function buildSessions(anchors: readonly Anchor[]): Map<string, [number, number][]> {
  const timesByHost = new Map<string, number[]>();
  for (const a of anchors) timesByHost.set(a.host, [...(timesByHost.get(a.host) ?? []), ...a.times]);
  const sessions = new Map<string, [number, number][]>();
  for (const [host, times] of timesByHost) sessions.set(host, splitSessions(times));
  return sessions;
}

/**
 * One host's anchor times as [start, end] session windows: split wherever two consecutive times are
 * more than SESSION_GAP_MS apart, and each cluster widened by SESSION_PAD_MS on both sides. Shared with
 * the synthesis prompt's command seats (#1622), so "attack session" has one shape. Empty in, empty out.
 */
export function splitSessions(times: readonly number[]): [number, number][] {
  const sorted = times.filter((t) => Number.isFinite(t)).sort((x, y) => x - y);
  if (!sorted.length) return [];
  const windows: [number, number][] = [];
  let start = sorted[0];
  let prev = sorted[0];
  for (const t of sorted.slice(1)) {
    if (t - prev > SESSION_GAP_MS) {
      windows.push([start - SESSION_PAD_MS, prev + SESSION_PAD_MS]);
      start = t;
    }
    prev = t;
  }
  windows.push([start - SESSION_PAD_MS, prev + SESSION_PAD_MS]);
  return windows;
}

function candidates(
  events: readonly ForensicEvent[],
  sessions: ReadonlyMap<string, [number, number][]>,
  hostOf: (raw: string) => string,
): Candidate[] {
  const seen = new Set<string>();
  const out: Candidate[] = [];
  for (const e of [...events].sort(byEventTime)) {
    if (e.severity === "Info" || !e.asset?.trim()) continue;
    const host = hostOf(e.asset);
    const time = timeOf(e);
    const windows = sessions.get(host);
    if (!windows || Number.isNaN(time) || !windows.some(([s, end]) => time >= s && time <= end)) continue;
    const described = describe(e);
    if (!described) continue;
    const key = `${host}\u0000${normalize(described.text)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ...described, event: e, host, time, accounts: canonicalAccounts(e) });
  }
  return out;
}

function oneLine(value: string): string {
  const flat = value
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return flat.length > MAX_NOTE_TEXT ? `${flat.slice(0, MAX_NOTE_TEXT - 1)}…` : flat;
}

function baseName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

type Described = Pick<Candidate, "kind" | "text" | "program" | "fileName">;

/** The row's command line, or its script/binary file write; undefined for anything else. */
function describe(e: ForensicEvent): Described | undefined {
  const proc = canonicalProcess(e);
  const commandLine = (proc?.commandLine ?? e.commandLine ?? "").trim();
  if (commandLine) {
    const text = oneLine(commandLine);
    // The real program, not a `cmd /c` wrapper: a finding that says "cmd" has not named `net view`.
    return { kind: "process", text, program: programOf(unwrap(tokenize(text))) };
  }
  if (!isFileWrite(e)) return undefined;
  const path = (canonicalFile(e)?.path ?? e.path ?? "").trim();
  if (!path || !SCRIPT_OR_BINARY.test(path)) return undefined;
  const writer = proc?.name ?? e.processName;
  const text = oneLine(`${writer ? baseName(writer) : "a process"} wrote ${path}`);
  return {
    kind: "file-write",
    text,
    program: writer ? stripExe(baseName(writer)) : "",
    fileName: baseName(path),
  };
}

function isFileWrite(e: ForensicEvent): boolean {
  if (e.action === "write") return true;
  const event = upgradeForensicEvent(e).canonical?.event;
  if (event?.category === "file" && FILE_WRITE_TYPES.has(event.type.toLowerCase())) return true;
  // Older rows carry no typed envelope; a Sysmon file-create names its event id in the description.
  return /\(EID 11\b/.test(e.description);
}

/** Lowercase, quotes and `.exe` dropped, punctuation that wraps a quote in prose made a space. */
function normalize(value: string): string {
  return value
    .toLowerCase()
    .replace(/["'`“”‘’]/g, "")
    .replace(/\.exe\b/g, "")
    .replace(/[(),;]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function findingText(f: Finding): string {
  // A sentence-ending period is prose, not part of the command it follows ("dropped !start.cmd.").
  return ` ${normalize(`${f.title} ${f.description}`).replace(/\.(?=\s|$)/g, " ")} `;
}

/** Windows-style split: a double-quoted run is one token. */
function tokenize(command: string): string[] {
  return (command.match(/"[^"]*"|\S+/g) ?? []).map((t) => t.replace(/"/g, ""));
}

function stripExe(name: string): string {
  return name.toLowerCase().replace(/\.exe$/, "");
}

function programOf(tokens: readonly string[]): string {
  return tokens.length ? stripExe(baseName(tokens[0])) : "";
}

/** Drop `cmd /c` / `cmd /k` and `powershell -command` wrappers so the core names the real command. */
function unwrap(tokens: string[]): string[] {
  const prog = programOf(tokens);
  const flag = tokens[1]?.toLowerCase();
  if (prog === "cmd" && (flag === "/c" || flag === "/k") && tokens.length > 2) return unwrap(tokens.slice(2));
  if ((prog === "powershell" || prog === "pwsh") && tokens.length > 2) {
    const i = tokens.findIndex((t, idx) => idx > 0 && /^-(?:c|command)$/i.test(t));
    if (i > 0 && tokens.length > i + 1) return unwrap(tokens.slice(i + 1));
  }
  return tokens;
}

function wordIn(text: string, word: string): boolean {
  return word.length > 0 && text.includes(` ${word} `);
}

/** Finding id -> the hosts of the scoped rows it cites. */
function findingHosts(
  state: InvestigationState,
  findings: readonly Finding[],
  byId: ReadonlyMap<string, ForensicEvent>,
  hostOf: (raw: string) => string,
): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const f of findings) {
    const hosts = new Set<string>();
    for (const id of citedIds(state, f)) {
      const asset = byId.get(id)?.asset?.trim();
      if (asset) hosts.add(hostOf(asset));
    }
    out.set(f.id, hosts);
  }
  return out;
}

/**
 * Only a finding about this row's host can name it: one that cites the row itself, or cites some row
 * on the same host. `net view /all` named for host B says nothing about the same command on host A.
 */
function isNamed(
  c: Candidate,
  texts: ReadonlyMap<string, string>,
  cited: ReadonlyMap<string, Set<string>>,
  hostsOf: ReadonlyMap<string, Set<string>>,
): boolean {
  const full = normalize(c.text);
  const core = coreOf(c);
  const citing = cited.get(c.event.id);
  for (const [id, text] of texts) {
    if (!citing?.has(id) && !hostsOf.get(id)?.has(c.host)) continue;
    if (text.includes(full)) return true;
    if (core && (core.includes(" ") || core.length >= 4) && wordIn(text, core)) return true;
    if (citing?.has(id) && wordIn(text, c.program)) return true;
  }
  return false;
}

/** Program plus its next two arguments; the file name for a file write. */
function coreOf(c: Candidate): string {
  if (c.kind === "file-write") return c.fileName ? normalize(c.fileName) : "";
  const tokens = unwrap(tokenize(c.text));
  if (!tokens.length) return "";
  return normalize([stripExe(baseName(tokens[0])), ...tokens.slice(1, 3)].join(" "));
}

function closestAnchor(c: Candidate, anchors: readonly Anchor[]): Anchor | undefined {
  const accounts = new Set(c.accounts.map((a) => a.toLowerCase()));
  const scored = anchors
    .filter((a) => a.host === c.host)
    .map((a) => ({
      a,
      distance: Math.min(...a.times.map((t) => Math.abs(t - c.time))),
      sharesAccount: [...a.accounts].some((x) => accounts.has(x)) ? 0 : 1,
    }));
  scored.sort(
    (x, y) =>
      x.distance - y.distance ||
      x.sharesAccount - y.sharesAccount ||
      SEVERITY_RANK[x.a.finding.severity] - SEVERITY_RANK[y.a.finding.severity] ||
      x.a.finding.id.localeCompare(y.a.finding.id),
  );
  return scored[0]?.a;
}

function toNote(c: Candidate): SessionCommand {
  return {
    eventId: c.event.id,
    timestamp: c.event.timestamp,
    host: c.host,
    kind: c.kind,
    text: c.text,
    ...(c.accounts.length ? { accounts: c.accounts } : {}),
  };
}
