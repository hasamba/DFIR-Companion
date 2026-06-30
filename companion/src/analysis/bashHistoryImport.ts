// Deterministic importer for Linux/Unix shell history files — `.bash_history` (and the zsh /
// ash / ksh equivalents). These are a high-signal IR artifact on a compromised *nix host: the
// exact commands an account ran, in order, and — when the shell was configured with
// `HISTTIMEFORMAT` (bash writes a `#<epoch>` comment line before each command) or zsh extended
// history (`: <epoch>:<elapsed>;<command>`) — WHEN. Like the other host-triage importers it is
// fully DETERMINISTIC (no AI call): one forensic event per command at the artifact's own time,
// Info by default (a shell history is mostly benign admin activity — over-flagging would drown
// real signal), with a CONSERVATIVE bump only on genuine attacker tradecraft (reverse shells,
// download-and-execute, credential access, log/history tampering, lateral SSH). IPs / URLs /
// domains in the command line become IOCs. Reuses siemImport's aggregation + IOC sink.

import {
  addIoc, aggregateEvents, cleanIp,
  type MappedEvent, type SiemImportOptions, type SiemIoc, type SiemParseResult,
} from "./siemImport.js";
import type { Severity } from "./stateTypes.js";

export interface BashHistoryImportOptions extends SiemImportOptions {
  // The account the history belongs to (derived from the filename by the pipeline, e.g.
  // "nina.kapoor" from "nina.kapoor.bash_history"). Surfaced in each event's description.
  user?: string;
}

// A parsed history line: the command + its own timestamp (ISO, "" when the shell stored none).
interface HistEntry { command: string; timestamp: string; }

// Filename signatures: bash/zsh/sh/ash/ksh history, the generic `.history`, or PSReadLine's
// `ConsoleHost_history.txt` (PowerShell). The username is the stem before the suffix.
const HISTORY_FILE_RE = /(?:^|[._-])(?:bash|zsh|sh|ash|ksh|fish)_history$|\.history$|consolehost_history\.txt$/i;

// bash HISTTIMEFORMAT line: a comment that is ONLY a 9–13 digit epoch (`#1715688014`).
const BASH_TS_RE = /^#(\d{9,13})$/;
// zsh extended-history line: `: 1715688014:0;the command`.
const ZSH_LINE_RE = /^:\s*(\d{9,13}):\d+;(.*)$/s;

export function looksLikeBashHistory(filename: string, text: string): boolean {
  if (HISTORY_FILE_RE.test((filename ?? "").trim())) return true;
  // Content signature (filename-agnostic): ≥2 bash `#<epoch>` lines each followed by a command,
  // or ≥2 zsh extended-history lines. Distinctive enough to claim ahead of the generic log.
  const lines = text.split(/\r\n|\r|\n/).slice(0, 200);
  let bashTs = 0, zsh = 0;
  for (let i = 0; i < lines.length; i++) {
    if (BASH_TS_RE.test(lines[i].trim())) { const next = lines[i + 1]?.trim() ?? ""; if (next && !next.startsWith("#")) bashTs++; }
    if (ZSH_LINE_RE.test(lines[i])) zsh++;
  }
  return bashTs >= 2 || zsh >= 2;
}

// Convert a bash/zsh epoch (seconds, or 13-digit milliseconds) to ISO "…Z"; "" if invalid.
function epochToIso(epoch: string): string {
  const n = Number(epoch);
  if (!Number.isFinite(n) || n <= 0) return "";
  const ms = n >= 1e12 ? n : n * 1000;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

// Parse a shell history file into ordered { command, timestamp } entries. Handles bash plain
// (commands only), bash HISTTIMEFORMAT (`#<epoch>` before each command), and zsh extended history.
export function parseShellHistory(text: string): HistEntry[] {
  const entries: HistEntry[] = [];
  let pendingTs = "";
  for (const raw of text.split(/\r\n|\r|\n/)) {
    const line = raw.replace(/\s+$/, "");
    if (!line.trim()) { continue; }

    const zsh = ZSH_LINE_RE.exec(line);
    if (zsh) {
      const cmd = zsh[2].trim();
      if (cmd) entries.push({ command: cmd, timestamp: epochToIso(zsh[1]) });
      continue;
    }

    const ts = BASH_TS_RE.exec(line.trim());
    if (ts) { pendingTs = epochToIso(ts[1]); continue; }

    // A real command line (a leading `#` that is not a pure-epoch line is treated as a typed
    // comment command — still evidence of what was entered).
    entries.push({ command: line.trim(), timestamp: pendingTs });
    pendingTs = "";
  }
  return entries;
}

// ───────────────────────────── suspicious-command classifier ─────────────────────────────

interface CmdRule { re: RegExp; severity: Severity; mitre: string[]; }

// Conservative, tradecraft-focused. Ordered worst-first; the FIRST match wins. Benign admin /
// recon commands intentionally match nothing → they stay Info (a shell history is mostly noise;
// flagging every `id`/`who`/`ip addr` would bury the real signal).
const CMD_RULES: CmdRule[] = [
  // Reverse / bind shells + remote code exec into a shell.
  { re: /\b(?:ba)?sh\s+-[a-z]*i\b.*(?:>&|\d>&)\s*\/dev\/(?:tcp|udp)\/|\/dev\/(?:tcp|udp)\/\d|\bnc(?:at)?\b[^\n]*\s-[a-z]*e\b|mkfifo\b[^\n]*\bnc\b|socat\b[^\n]*exec|python[0-9.]*\s+-c\s+['"][^'"]*socket|perl\s+-e\s+['"][^'"]*socket/i, severity: "High", mitre: ["T1059.004", "T1071"] },
  // Download-and-execute (curl/wget piped to a shell, or fetched then run).
  { re: /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/i, severity: "High", mitre: ["T1059.004", "T1105"] },
  // Credential access — reading/copying the shadow file, dumpers.
  { re: /\/etc\/shadow\b|\bunshadow\b|mimipenguin|gsecdump|\/etc\/gshadow\b|\bstrings\b[^\n]*\/dev\/mem/i, severity: "High", mitre: ["T1003.008"] },
  // History / log tampering — anti-forensics.
  { re: /\bhistory\s+-c\b|unset\s+HISTFILE|HISTFILE=\/dev\/null|HISTSIZE=0\b|\bshred\b|\b(?:rm|truncate|>\s*)\s*[^\n]*\/var\/log\b|\bjournalctl\b[^\n]*--rotate|\bln\s+-s\s+\/dev\/null\s+~\/\.bash_history/i, severity: "High", mitre: ["T1070.003", "T1070.002"] },
  // Persistence — cron, systemd unit, rc/profile, authorized_keys, ld.so.preload.
  { re: /\bcrontab\s+-|\/etc\/cron|systemctl\s+(?:enable|--now)\b|>>?\s*~?\/?\.?(?:bashrc|bash_profile|profile|zshrc)\b|authorized_keys\b|ld\.so\.preload|\/etc\/rc\.local/i, severity: "Medium", mitre: ["T1053.003", "T1543.002"] },
  // Privilege escalation tradecraft (setuid bits, pkexec, known sudo abuse) — NOT plain `sudo`.
  { re: /\bchmod\s+[0-7]*4[0-7]{3}\b|\bchmod\s+[ug]\+s\b|\bpkexec\b|\bsudo\s+-l\b|\bsetcap\b/i, severity: "Medium", mitre: ["T1548.001"] },
  // Exfiltration over web — curl/wget UPLOADING a file (POST form / --upload-file / --data-binary),
  // distinct from (and worse than) a plain download below. #199.
  { re: /\b(?:curl|wget)\b[^\n]*(?:--data-binary|--upload-file|\s-T\b|\s-F\b|--form|-d\s+@|--data\s+@)/i, severity: "Medium", mitre: ["T1041"] },
  // Collection — bulk database dump to a file (mysqldump/pg_dump/mongodump). #199.
  { re: /\b(?:mysqldump|pg_dump|pg_dumpall|mongodump)\b/i, severity: "Medium", mitre: ["T1005"] },
  // Ingress tool transfer — fetching files (not piped, so lower than download-and-exec above).
  { re: /\b(?:wget|curl|scp|sftp|tftp|ftp)\b/i, severity: "Low", mitre: ["T1105"] },
  // Lateral movement via SSH/SCP to another host.
  { re: /\bssh\b\s+[^\n]*@|\bscp\b\s+[^\n]*@[^\n]*:/i, severity: "Low", mitre: ["T1021.004"] },
  // Base64 decode (commonly used to stage payloads) — informative.
  { re: /\bbase64\s+(?:-d|--decode)\b|\bxxd\s+-r\b/i, severity: "Low", mitre: ["T1140"] },
];

function classify(command: string): { severity: Severity; mitre: string[] } {
  for (const rule of CMD_RULES) {
    if (rule.re.test(command)) return { severity: rule.severity, mitre: [...rule.mitre] };
  }
  return { severity: "Info", mitre: [] };
}

// ───────────────────────────── IOC extraction ─────────────────────────────

const IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s'"|;>]+/gi;
// A bare hostname token (label.label.tld). Excluded when it's clearly a file path segment.
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const FILE_EXT_RE = /\.(?:sh|conf|log|txt|json|xml|yml|yaml|cfg|service|py|pl|c|h|so|gz|tar|zip|tmp|bak|pid|sock|key|pem|crt)$/i;

function extractIocs(command: string, sink: Map<string, SiemIoc>): void {
  for (const m of command.match(URL_RE) ?? []) addIoc(sink, "url", m.replace(/[).,;]+$/, "").slice(0, 300));
  for (const m of command.match(IPV4_RE) ?? []) { const ip = cleanIp(m); if (ip) addIoc(sink, "ip", ip); }
  for (const m of command.matchAll(DOMAIN_RE)) {
    const d = m[0].toLowerCase();
    const after = command[(m.index ?? 0) + m[0].length] ?? "";
    // Skip IPs (caught above), pure file names, path-like tokens, and the local-part of a
    // user@host (e.g. "nina.kapoor" in `ssh nina.kapoor@10.44.30.10` is a username, not a domain).
    if (after === "@") continue;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(d) || FILE_EXT_RE.test(d)) continue;
    if (/\/[a-z0-9._-]*$/i.test(d)) continue;
    addIoc(sink, "domain", d);
  }
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseShellHistoryFile(text: string, opts: BashHistoryImportOptions = {}): SiemParseResult {
  const entries = parseShellHistory(text);
  const iocSink = new Map<string, SiemIoc>();
  const user = (opts.user ?? "").trim();
  const userTag = user ? ` [${user}]` : "";

  const mapped: MappedEvent[] = entries.map((e) => {
    extractIocs(e.command, iocSink);
    const { severity, mitre } = classify(e.command);
    const cmd = e.command.replace(/\s+/g, " ").trim();
    return {
      timestamp: e.timestamp,
      description: `Shell command${userTag}: ${cmd}`.slice(0, 600),
      severity,
      mitre,
      // Aggregate identical commands by the same user into one counted row (a history often
      // repeats `cat /etc/fstab`, `ls`, …). The text is the discriminator.
      aggKey: `bash|${user}|${cmd}`.toLowerCase().slice(0, 400),
    };
  });

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const maxIocs = opts.maxIocs ?? 5000;
  const represented = events.reduce((n, ev) => n + (ev.count ?? 1), 0);

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total: entries.length,
    kept: events.length,
    dropped: Math.max(0, entries.length - represented),
    groups,
    format: "shell-history",
    hostname: "",
  };
}

// Derive the account name from a stored history filename: strip a leading import sequence prefix
// ("0001_") and the history suffix. "0001_nina.kapoor.bash_history" → "nina.kapoor".
export function userFromHistoryFilename(filename: string): string {
  let n = (filename ?? "").trim().replace(/^\d+_/, "");
  n = n.replace(/(?:[._-](?:bash|zsh|sh|ash|ksh|fish))?_history$/i, "")
       .replace(/\.history$/i, "")
       .replace(/_?consolehost_history\.txt$/i, "");
  return n.trim();
}
