import { isConsoleHistoryRow } from "./defenderTamperCap.js";
import type { ForensicEvent } from "./stateTypes.js";

/**
 * Entry candidates before the first script write (#1968).
 *
 * Two lab runs left the initial-access vector "unknown" although the entry row (a ClickFix paste, a
 * console-history download) sat in the forensic timeline. Nothing told synthesis which launches came
 * just before the attacker's first script landed on disk. This pure module computes that, per host,
 * from the forensic-timeline rows IN SYNTHESIS SCOPE and states it as one block:
 *   - the first script-file write (.ps1/.bat/.cmd/.vbs/.js/.hta …) on the host, and
 *   - the process launches in a short window before it, earliest first, capped, routine OS and
 *     collector launches skipped;
 *   - console-history lines that fetch a URL, labelled "time unknown": a PSReadLine line has no
 *     per-line time, so its row time is the history file's time and must never place it (#1941).
 *
 * CANDIDATES, not a verdict: the block says "weigh", never "conclude", and changes no severity.
 * Never the super-timeline (CLAUDE.md §7) — the caller passes the scoped forensic events only.
 */

export const ENTRY_CANDIDATES_BLOCK_HEADER =
  "ENTRY CANDIDATES (deterministic — the earliest process launches before the first script-file write on each host; candidates, not a verdict):";
/** Launches further back than this from the first script write are not listed. */
export const ENTRY_CANDIDATES_WINDOW_MS = 15 * 60_000;
/** At most this many launch lines per host; the rest are counted. */
export const ENTRY_CANDIDATES_MAX_LAUNCHES = 5;
/** At most this many console-history download lines per host. */
export const ENTRY_CANDIDATES_MAX_HISTORY = 3;
/** At most this many hosts are listed; the rest are counted. */
export const ENTRY_CANDIDATES_MAX_HOSTS = 5;

const HOST_CAP = 100;
const TEXT_CAP = 200;
const SCAN_CAP = 16_384;

const SCRIPT_FILE = /\.(?:ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|wsf)$/i;
const WRITE_TYPES = new Set(["create", "write", "modify", "observation", "rename"]);
const COLLECTOR_PATH = /[\\/]velociraptor[\\/]/i;
const HISTORY_FILE_MENTION = /consolehost_history\.txt/i;
const FETCH_VERB =
  /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget|start-bitstransfer|bitsadmin|certutil|downloadstring|downloadfile|downloaddata|net\.webclient)\b/i;
const URL = /\b(?:https?|ftp):\/\/\S/i;
/** Routine Windows and collector images: a launch of one of these is not an entry candidate. */
const ROUTINE_IMAGES = new Set([
  "svchost.exe",
  "conhost.exe",
  "wermgr.exe",
  "werfault.exe",
  "searchprotocolhost.exe",
  "searchfilterhost.exe",
  "searchindexer.exe",
  "runtimebroker.exe",
  "backgroundtaskhost.exe",
  "taskhostw.exe",
  "dllhost.exe",
  "smartscreen.exe",
  "compattelrunner.exe",
  "msmpeng.exe",
  "mpcmdrun.exe",
  "tiworker.exe",
  "trustedinstaller.exe",
  "sppsvc.exe",
  "wmiprvse.exe",
  "velociraptor.exe",
]);

const capped = (value: string | undefined): string =>
  !value ? "" : value.length > SCAN_CAP ? value.slice(0, SCAN_CAP) : value;

/** Adversary-controlled text: one line, no control characters, bounded. */
function flat(raw: string | undefined, cap: number): string {
  const printable = [...capped(raw)]
    .map((ch) => {
      const code = ch.charCodeAt(0);
      return code < 0x20 || code === 0x7f ? " " : ch;
    })
    .join("");
  const line = printable.replace(/\s+/g, " ").trim();
  return line.length > cap ? `${line.slice(0, cap)}…` : line;
}

const hostOf = (e: ForensicEvent): string => flat(e.asset, HOST_CAP) || "an unnamed host";

function timeOf(e: ForensicEvent): number | undefined {
  const t = Date.parse(e.timestamp);
  return Number.isFinite(t) ? t : undefined;
}

function isHistory(e: ForensicEvent): boolean {
  return isConsoleHistoryRow(e) || HISTORY_FILE_MENTION.test(`${capped(e.description)} ${capped(e.message)}`);
}

function isScriptWrite(e: ForensicEvent): boolean {
  const path = capped(e.path).trim();
  if (!SCRIPT_FILE.test(path) || COLLECTOR_PATH.test(path)) return false;
  const kind = e.canonical?.event;
  if (!kind) return !e.commandLine;
  return (kind.category === "file" && WRITE_TYPES.has(kind.type)) || e.action === "write";
}

function imageOf(e: ForensicEvent): string {
  const cmd = capped(e.commandLine).trim();
  const first = cmd.startsWith('"') ? cmd.slice(1).split('"')[0] : cmd.split(/\s+/)[0];
  const raw = e.processName || first || "";
  return (raw.split(/[\\/]/).pop() ?? "").toLowerCase();
}

function isLaunch(e: ForensicEvent): boolean {
  if (!capped(e.commandLine).trim() || isHistory(e)) return false;
  const kind = e.canonical?.event;
  if (kind && !(kind.category === "process" && kind.type === "start")) return false;
  if (COLLECTOR_PATH.test(capped(e.commandLine))) return false;
  return !ROUTINE_IMAGES.has(imageOf(e));
}

function isHistoryDownload(e: ForensicEvent): boolean {
  if (!isHistory(e)) return false;
  const text = `${capped(e.commandLine)} ${capped(e.message)} ${capped(e.description)}`;
  return FETCH_VERB.test(text) && URL.test(text);
}

interface Launch {
  ids: string[];
  at: number;
  timestamp: string;
  text: string;
}

interface HostCandidates {
  host: string;
  write?: { id: string; at: number; timestamp: string; path: string };
  launches: Launch[];
  launchTotal: number;
  history: { id: string; text: string }[];
}

function firstScriptWrites(events: readonly ForensicEvent[]): Map<string, HostCandidates["write"]> {
  const writes = new Map<string, HostCandidates["write"]>();
  for (const e of events) {
    const at = timeOf(e);
    if (at === undefined || isHistory(e) || !isScriptWrite(e)) continue;
    const host = hostOf(e);
    const prev = writes.get(host);
    if (!prev || at < prev.at) {
      writes.set(host, { id: e.id, at, timestamp: e.timestamp, path: flat(e.path, TEXT_CAP) });
    }
  }
  return writes;
}

/** One line per distinct launch: two rules reporting the same launch cite both ids on one line. */
function launchesBefore(events: readonly ForensicEvent[], host: string, writeAt: number): Launch[] {
  const byKey = new Map<string, Launch>();
  for (const e of events) {
    const at = timeOf(e);
    if (at === undefined || hostOf(e) !== host || at >= writeAt || writeAt - at > ENTRY_CANDIDATES_WINDOW_MS)
      continue;
    if (!isLaunch(e)) continue;
    const text = flat(e.commandLine, TEXT_CAP);
    const key = `${at}\u0000${text}`;
    const prev = byKey.get(key);
    byKey.set(
      key,
      prev ? { ...prev, ids: [...prev.ids, e.id] } : { ids: [e.id], at, timestamp: e.timestamp, text },
    );
  }
  return [...byKey.values()].sort((a, b) => a.at - b.at || a.text.localeCompare(b.text));
}

function collect(events: readonly ForensicEvent[]): HostCandidates[] {
  const writes = firstScriptWrites(events);
  const hosts = new Map<string, HostCandidates>();
  for (const [host, write] of writes) {
    if (!write) continue;
    const launches = launchesBefore(events, host, write.at);
    if (!launches.length) continue;
    hosts.set(host, {
      host,
      write,
      launches: launches.slice(0, ENTRY_CANDIDATES_MAX_LAUNCHES),
      launchTotal: launches.length,
      history: [],
    });
  }
  for (const e of events) {
    if (!isHistoryDownload(e)) continue;
    const host = hostOf(e);
    const entry = hosts.get(host) ?? { host, launches: [], launchTotal: 0, history: [] };
    hosts.set(host, { ...entry, history: [...entry.history, { id: e.id, text: historyText(e) }] });
  }
  return [...hosts.values()].sort(
    (a, b) => (a.write?.at ?? Infinity) - (b.write?.at ?? Infinity) || a.host.localeCompare(b.host),
  );
}

function historyText(e: ForensicEvent): string {
  return flat(e.commandLine || e.message || e.description, TEXT_CAP);
}

function renderHost(c: HostCandidates): string[] {
  const lines: string[] = [];
  if (c.write) {
    lines.push(
      `- ${c.host}: first script-file write [${c.write.id}] at ${c.write.timestamp} (${c.write.path}). ` +
        `Process launches in the ${ENTRY_CANDIDATES_WINDOW_MS / 60_000} min before it, earliest first:`,
    );
    for (const l of c.launches) lines.push(`  - [${l.ids.join(", ")}] ${l.timestamp} ${l.text}`);
    const rest = c.launchTotal - c.launches.length;
    if (rest > 0)
      lines.push(`  - …and ${rest} more ${rest === 1 ? "launch" : "launches"} in the window (not listed).`);
  }
  if (c.history.length) {
    lines.push(
      `- ${c.host}: console-history download lines (time unknown — the row carries the history file's time, not the command's):`,
    );
    const shown = c.history.slice(0, ENTRY_CANDIDATES_MAX_HISTORY);
    for (const h of shown) lines.push(`  - [${h.id}] (time unknown) ${h.text}`);
    const rest = c.history.length - shown.length;
    if (rest > 0)
      lines.push(`  - …and ${rest} more console-history download ${rest === 1 ? "line" : "lines"}.`);
  }
  return lines;
}

/**
 * One block naming each host's entry candidates. Returns "" when no host has a launch before a
 * script-file write and no console-history line fetches a URL. The caller passes the
 * synthesis-scoped forensic events only — never the super-timeline (CLAUDE.md §7).
 */
export function buildEntryCandidatesBlock(scopedEvents: readonly ForensicEvent[]): string {
  const hosts = collect(scopedEvents);
  if (!hosts.length) return "";
  const shown = hosts.slice(0, ENTRY_CANDIDATES_MAX_HOSTS);
  const lines = shown.flatMap(renderHost);
  const rest = hosts.length - shown.length;
  if (rest > 0) lines.push(`- …and ${rest} more ${rest === 1 ? "host" : "hosts"} with the same shape.`);
  return (
    `${ENTRY_CANDIDATES_BLOCK_HEADER}\n${lines.join("\n")}\n` +
    "Weigh each listed row as a candidate for the initial-access vector. Do not conclude from this block " +
    "alone: a launch just before a script write can be routine (an installer, an update). Name a candidate " +
    "as the vector only when other rows support it; otherwise keep the vector unknown and say which rows to " +
    "check. Never place a time-unknown line in the attack sequence by its row time."
  );
}
