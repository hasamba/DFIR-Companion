// Deterministic importer for Linux **auditd** logs — the raw `/var/log/audit/audit.log`
// record format and `ausearch` output (raw or `-i`/interpreted). The first Linux-host ingest
// path; no AI call (closes #62, alongside the journald + sysdig importers).
//
// auditd writes one logical security event as SEVERAL `type=… msg=audit(TS:SERIAL): …` lines
// that share the same SERIAL — e.g. a process exec is a SYSCALL + EXECVE + PATH + PROCTITLE +
// CWD quartet. This module:
//   1. PARSES each line into { type, ts, serial, fields } — a robust `key=value` tokenizer that
//      handles quoted values, the nested `msg='op=… acct="root" …'` blob USER_* records carry,
//      and hex-encoded values (PROCTITLE / EXECVE args / sockaddr the kernel hex-escapes).
//   2. GROUPS lines by SERIAL into one logical event, picks the most-significant record type, and
//      maps it DETERMINISTICALLY to a forensic event: a per-type severity/MITRE table (logins,
//      account/group management, sudo, SELinux/AppArmor denials, audit-config tampering, anomaly
//      records…), bumped on a failed authentication or a suspicious command line.
//   3. EXTRACTS IOCs — `exe`/`comm`/argv[0] → process + file, watched file `name=` → file, the
//      remote login `addr`/`hostname` and decoded SOCKADDR → ip/domain.
//   4. AGGREGATES repetitive identical events (shared with the SIEM importer) and caps the total.
//
// The event's OWN time is the epoch in `msg=audit(SECONDS.MILLIS:SERIAL)` — never the import time.
// A line-oriented `aureport` numbered table (no `type=`/`msg=audit`) is handled as Info evidence
// rows so a summary report still lands on the timeline rather than being dropped.

import type { Severity } from "./stateTypes.js";
import {
  aggregateEvents,
  cleanIp,
  addIoc,
  baseName,
  oneLine,
  worst,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Fields = Record<string, string>;

export interface AuditdImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface AuditdParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;     // logical audit events found (grouped by serial) + aureport rows
  kept: number;      // events emitted (after aggregation + cap)
  dropped: number;   // events not represented (below floor / capped)
  groups: number;    // distinct event groups before the cap
  format: string;    // "auditd" | "aureport" | "empty"
  hostname: string;  // best-effort dominant node/host
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

// ───────────────────────────── per-type mapping ─────────────────────────────

interface AuditTypeDef {
  label: string;
  severity: Severity;
  mitre?: string[];
}

// auditd record types worth surfacing. Anything else falls back to a generic Info event.
const AUDIT_TYPES: Record<string, AuditTypeDef> = {
  // Execution
  EXECVE: { label: "Command executed", severity: "Low", mitre: ["T1059"] },
  ANOM_EXEC: { label: "Anomalous program execution", severity: "High", mitre: ["T1059"] },
  // Authentication / sessions
  USER_LOGIN: { label: "User login", severity: "Low", mitre: ["T1078"] },
  USER_AUTH: { label: "User authentication", severity: "Low" },
  USER_ACCT: { label: "User account validation", severity: "Info" },
  USER_ERR: { label: "User account error", severity: "Medium", mitre: ["T1110"] },
  CRED_ACQ: { label: "Credential acquired", severity: "Info" },
  CRED_REFR: { label: "Credential refreshed", severity: "Info" },
  CRED_DISP: { label: "Credential disposed", severity: "Info" },
  USER_START: { label: "Session started", severity: "Info" },
  USER_END: { label: "Session ended", severity: "Info" },
  LOGIN: { label: "Login UID assigned", severity: "Info" },
  ANOM_LOGIN_FAILURES: { label: "Excessive login failures", severity: "High", mitre: ["T1110"] },
  ANOM_LOGIN_LOCATION: { label: "Login from forbidden location", severity: "High", mitre: ["T1078"] },
  ANOM_LOGIN_TIME: { label: "Login at forbidden time", severity: "Medium", mitre: ["T1078"] },
  // Account / group management → persistence
  ADD_USER: { label: "User account created", severity: "High", mitre: ["T1136.001"] },
  DEL_USER: { label: "User account deleted", severity: "Medium" },
  ADD_GROUP: { label: "Group account created", severity: "Medium", mitre: ["T1136.002"] },
  DEL_GROUP: { label: "Group account deleted", severity: "Medium" },
  GRP_MGMT: { label: "Group management", severity: "Medium", mitre: ["T1098"] },
  USER_MGMT: { label: "User management", severity: "Medium", mitre: ["T1098"] },
  ACCT_LOCK: { label: "Account locked", severity: "Medium" },
  ACCT_UNLOCK: { label: "Account unlocked", severity: "Medium" },
  USER_CHAUTHTOK: { label: "Password / auth token changed", severity: "Medium", mitre: ["T1098"] },
  // Privilege escalation
  USER_CMD: { label: "User-run command (sudo)", severity: "Low", mitre: ["T1548.003"] },
  USER_ROLE_CHANGE: { label: "User role changed", severity: "Medium", mitre: ["T1548"] },
  ROLE_ASSIGN: { label: "SELinux role assigned to user", severity: "Medium", mitre: ["T1098"] },
  ROLE_REMOVE: { label: "SELinux role removed from user", severity: "Low" },
  // Defense evasion / policy
  CONFIG_CHANGE: { label: "Audit configuration changed", severity: "High", mitre: ["T1562.006"] },
  MAC_CONFIG_CHANGE: { label: "MAC policy configuration changed", severity: "Medium", mitre: ["T1562.001"] },
  MAC_STATUS: { label: "SELinux enforcing status changed", severity: "Medium", mitre: ["T1562.001"] },
  MAC_POLICY_LOAD: { label: "SELinux policy loaded", severity: "Low" },
  AVC: { label: "SELinux/AppArmor access denial", severity: "Medium", mitre: ["T1562.001"] },
  SECCOMP: { label: "Seccomp filter violation", severity: "Medium" },
  ANOM_ABEND: { label: "Process ended abnormally (crash)", severity: "Medium", mitre: ["T1499"] },
  ANOM_PROMISCUOUS: { label: "Network interface entered promiscuous mode", severity: "High", mitre: ["T1040"] },
  // Network / firewall
  NETFILTER_CFG: { label: "Netfilter (firewall) configuration", severity: "Low", mitre: ["T1562.004"] },
  // System lifecycle
  SERVICE_START: { label: "Service started", severity: "Info" },
  SERVICE_STOP: { label: "Service stopped", severity: "Info" },
  SYSTEM_BOOT: { label: "System boot", severity: "Info" },
  SYSTEM_SHUTDOWN: { label: "System shutdown", severity: "Info" },
  SYSTEM_RUNLEVEL: { label: "Runlevel changed", severity: "Info" },
  DAEMON_START: { label: "Audit daemon started", severity: "Info" },
  DAEMON_END: { label: "Audit daemon stopped", severity: "Low", mitre: ["T1562.001"] },
  DAEMON_ABORT: { label: "Audit daemon aborted", severity: "Medium", mitre: ["T1562.001"] },
  // Keystroke logging
  TTY: { label: "TTY input recorded", severity: "Low" },
  USER_TTY: { label: "TTY input recorded", severity: "Low" },
};

// Record types that only add CONTEXT to a logical event (they are never the "primary" type).
const CONTEXT_TYPES = new Set(["SYSCALL", "PATH", "CWD", "PROCTITLE", "SOCKADDR", "EXECVE_ARGS", "ARGS", "OBJ_PID", "BPRM_FCAPS", "FD_PAIR", "IPC"]);

// Linux attacker tradecraft in a command line → bump severity + add MITRE.
const SUSP_CMD: { re: RegExp; mitre: string[] }[] = [
  { re: /(?:\bnc\b|\bncat\b|\bnetcat\b)[^|]*\s-e\b|\bbash\s+-i\b|\bsh\s+-i\b|\/dev\/tcp\//i, mitre: ["T1059.004", "T1571"] },
  { re: /\b(?:curl|wget)\b[^|]*\|\s*(?:ba)?sh\b|base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh\b/i, mitre: ["T1059.004", "T1105"] },
  { re: /\/etc\/(?:shadow|gshadow)\b/i, mitre: ["T1003.008"] },
  { re: /\bchmod\s+(?:[0-7]*[4-7][0-7]{3}|u?\+s)\b|\bchattr\s+[+]i\b/i, mitre: ["T1548.001"] },
  { re: /\b(?:insmod|modprobe|rmmod)\b/i, mitre: ["T1547.006"] },
  { re: /\bcrontab\b|\/etc\/cron|systemctl\s+(?:enable|start)\b/i, mitre: ["T1053.003"] },
  { re: /\bhistory\s+-c\b|\bunset\s+HISTFILE\b|>\s*\/var\/log\/|\btruncate\b[^|]*\/var\/log/i, mitre: ["T1070.003"] },
  { re: /\bnmap\b|\bmasscan\b|\bmimikatz\b|\bhashcat\b|\bjohn\b/i, mitre: ["T1046"] },
];

// ───────────────────────────── line parsing ─────────────────────────────

const RE_MSG_AUDIT = /msg=audit\((\d+)\.(\d+):(\d+)\)/;
const RE_TYPE = /(?:^|\s)type=(\w+)/;
// One key=value pair: bareword, "double", or 'single' quoted.
const RE_PAIR = /([A-Za-z0-9_-]+)=("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g;

// Decode an even-length hex string (auditd hex-escapes PROCTITLE / EXECVE args / file names that
// contain spaces or control chars). NUL separators (argv) become spaces. Non-hex → returned as-is.
function decodeHex(v: string): string {
  if (!/^[0-9A-Fa-f]+$/.test(v) || v.length < 2 || v.length % 2 !== 0) return v;
  let out = "";
  for (let i = 0; i < v.length; i += 2) {
    const code = parseInt(v.slice(i, i + 2), 16);
    out += code === 0 ? " " : String.fromCharCode(code);
  }
  return oneLine(out).trim();
}

function unquote(v: string): string {
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  return v;
}

// Tokenize the `key=value` pairs of one record. The nested `msg='op=… acct="x" …'` blob USER_*
// records carry is recursed into and merged. Uses `matchAll` (which scans on a clone of the regex)
// so the recursion is reentrancy-safe — `.exec()` on the shared global regex would corrupt lastIndex.
function parseFields(body: string): Fields {
  const out: Fields = {};
  for (const m of body.matchAll(RE_PAIR)) {
    const key = m[1];
    const rawVal = m[2];
    if (key === "msg" && (rawVal.startsWith("'") || rawVal.startsWith('"'))) {
      const inner = parseFields(rawVal.slice(1, -1));
      for (const [k, v] of Object.entries(inner)) out[k] = v; // inner (interpreted) keys win
      continue;
    }
    if (key in out) continue; // first occurrence wins (kernel duplicates are identical)
    out[key] = unquote(rawVal);
  }
  return out;
}

interface AuditLine {
  type: string;
  serial: string;
  tsMs: number;     // epoch ms from msg=audit(); 0 when absent
  fields: Fields;
}

function parseAuditLine(line: string): AuditLine | null {
  const typeM = RE_TYPE.exec(line);
  if (!typeM) return null;
  const auditM = RE_MSG_AUDIT.exec(line);
  if (!auditM) return null;
  const tsMs = Number(auditM[1]) * 1000 + Number(auditM[2]);
  const serial = auditM[3];
  // Parse pairs from after the "msg=audit(...):" header so we don't re-capture it.
  const headerEnd = line.indexOf("):", auditM.index);
  const body = headerEnd >= 0 ? line.slice(headerEnd + 2) : line;
  return { type: typeM[1], serial, tsMs, fields: parseFields(body) };
}

// ───────────────────────────── sockaddr decode ─────────────────────────────

// Decode the hex `saddr=` of a SOCKADDR record. Linux stores the sockaddr in host byte order, so
// the AF family is little-endian (`0200…` = AF_INET, `0A00…` = AF_INET6); the port + address that
// follow are network (big-endian). Returns the IP (+ port) for AF_INET / AF_INET6; "" otherwise.
function decodeSaddr(hex: string): { ip: string; port: number } | null {
  if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length < 8) return null;
  const byte = (i: number): number => parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  const family = byte(0) | (byte(1) << 8); // little-endian sa_family_t
  if (family === 2 && hex.length >= 16) { // AF_INET: family(2) port(2) addr(4)
    const port = (byte(2) << 8) | byte(3);
    const ip = [byte(4), byte(5), byte(6), byte(7)].join(".");
    return { ip, port };
  }
  if (family === 10 && hex.length >= 56) { // AF_INET6: family(2) port(2) flowinfo(4) addr(16)
    const port = (byte(2) << 8) | byte(3);
    const seg: string[] = [];
    for (let i = 8; i < 24; i += 2) seg.push(((byte(i) << 8) | byte(i + 1)).toString(16));
    return { ip: seg.join(":").replace(/(^|:)(0:)+/, "::").replace(/::+/, "::"), port };
  }
  return null;
}

// ───────────────────────────── grouping + mapping ─────────────────────────────

interface AuditEvent {
  serial: string;
  tsMs: number;
  types: string[];
  fields: Fields;          // merged across records (context types fill in exe/argv/path/addr)
  argv: string[];          // EXECVE args, hex-decoded
  pathNames: string[];     // PATH name= entries
  saddr?: string;          // SOCKADDR saddr= hex
}

// EXECVE arguments are a0,a1,…; each may be hex-encoded (spaces / quotes) or quoted.
function execveArgv(f: Fields): string[] {
  const argc = Number(f["argc"]);
  const n = Number.isFinite(argc) && argc > 0 && argc < 512 ? argc : 64;
  const argv: string[] = [];
  for (let i = 0; i < n; i++) {
    const v = f[`a${i}`];
    if (v == null) { if (i >= argc) break; else continue; }
    argv.push(decodeHex(v));
  }
  return argv;
}

// Pick the primary (most security-significant) record type of a logical event.
function primaryType(types: string[]): string {
  let best: string | undefined;
  let bestRank = Infinity;
  const rank: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  for (const t of types) {
    if (CONTEXT_TYPES.has(t)) continue;
    const def = AUDIT_TYPES[t];
    const r = def ? rank[def.severity] : 3.5; // an unknown non-context type ranks just below Low
    if (r < bestRank) { bestRank = r; best = t; }
  }
  if (best) return best;
  if (types.includes("SYSCALL")) return "SYSCALL";
  return types[0] ?? "UNKNOWN";
}

function isFailure(f: Fields): boolean {
  const res = (f["res"] ?? "").toLowerCase();
  const success = (f["success"] ?? "").toLowerCase();
  return res === "failed" || res === "fail" || success === "no";
}

// Account reference for the description / asset graph (the acct username, else uid/auid).
function account(f: Fields): string {
  const acct = (f["acct"] ?? f["uid"] ?? f["auid"] ?? "").trim();
  return acct && acct !== "-" && acct !== "unset" && acct !== "4294967295" ? acct : "";
}

function mapAuditEvent(ev: AuditEvent, iocSink: Map<string, SiemIoc>): MappedEvent {
  const f = ev.fields;
  const ptype = primaryType(ev.types);
  const def = AUDIT_TYPES[ptype] ?? { label: ptype.replace(/_/g, " ").toLowerCase(), severity: "Info" as Severity };

  const exe = (f["exe"] ?? "").trim();
  const comm = (f["comm"] ?? "").trim();
  const acct = account(f);
  const node = (f["node"] ?? "").trim();
  const cmdLine = ev.argv.length ? ev.argv.join(" ") : decodeHex(f["proctitle"] ?? f["cmd"] ?? "");
  const key = (f["key"] ?? "").trim();
  const failed = isFailure(f);

  let severity = def.severity;
  const mitre = [...(def.mitre ?? [])];

  // Failed authentication → brute-force signal.
  if (failed && (ptype === "USER_LOGIN" || ptype === "USER_AUTH" || ptype === "USER_ACCT")) {
    severity = worst(severity, "Medium");
    if (!mitre.includes("T1110")) mitre.push("T1110");
  }
  // A watched-rule hit (admin assigned an audit key) on an otherwise-context event is worth a floor.
  if (key && key !== "(null)" && (CONTEXT_TYPES.has(ptype) || ptype === "SYSCALL")) {
    severity = worst(severity, "Low");
  }
  // Suspicious command line → bump + MITRE.
  const cmdBlob = `${exe} ${cmdLine}`;
  for (const s of SUSP_CMD) {
    if (s.re.test(cmdBlob)) {
      severity = worst(severity, "Medium");
      for (const t of s.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
  }

  // ── IOCs ──
  if (exe && exe !== "(null)") {
    addIoc(iocSink, "process", baseName(exe));
    if (exe.includes("/")) addIoc(iocSink, "file", exe.slice(0, 300));
  }
  if (comm && comm !== "(null)" && comm !== baseName(exe)) addIoc(iocSink, "process", comm);
  if (ev.argv[0] && ev.argv[0].includes("/")) addIoc(iocSink, "file", ev.argv[0].slice(0, 300));
  for (const name of ev.pathNames) if (name.includes("/")) addIoc(iocSink, "file", name.slice(0, 300));
  // Remote login source: addr (USER records) or decoded SOCKADDR.
  const addr = (f["addr"] ?? "").trim();
  if (addr) { const ip = cleanIp(addr); if (ip) addIoc(iocSink, "ip", ip); }
  const hostField = (f["hostname"] ?? "").trim();
  if (hostField && hostField !== "?" && hostField !== "(null)") {
    if (IPV4.test(hostField)) { const ip = cleanIp(hostField); if (ip) addIoc(iocSink, "ip", ip); }
    else if (DOMAIN.test(hostField)) addIoc(iocSink, "domain", hostField.toLowerCase());
  }
  let saddrInfo: { ip: string; port: number } | null = null;
  if (ev.saddr) { saddrInfo = decodeSaddr(ev.saddr); if (saddrInfo) { const ip = cleanIp(saddrInfo.ip); if (ip) addIoc(iocSink, "ip", ip); } }

  // ── description ──
  let description = `auditd ${def.label} (${ptype})`;
  if (acct) description += ` — acct=${acct}`;
  if (cmdLine) description += ` | cmd=${oneLine(cmdLine).slice(0, 200)}`;
  else if (exe) description += ` | exe=${exe}`;
  if (failed) description += " | res=failed";
  if (addr || saddrInfo) description += ` | addr=${addr || saddrInfo?.ip}`;
  if (hostField && hostField !== "?") description += ` (from ${hostField})`;
  const term = (f["terminal"] ?? f["tty"] ?? "").trim();
  if (term && term !== "(none)" && term !== "?") description += ` term=${term}`;
  if (key && key !== "(null)") description += ` key=${key}`;
  if (node) description += ` @ ${node}`;
  description = description.slice(0, 600);

  const aggKey = `auditd|${ptype}|${acct}|${baseName(exe)}|${oneLine(cmdLine)}`
    .toLowerCase()
    .replace(/\b\d{3,}\b/g, "#")
    .slice(0, 400);

  const procName = baseName(exe) || comm || undefined;
  return {
    timestamp: ev.tsMs > 0 ? new Date(ev.tsMs).toISOString() : "",
    description,
    severity,
    mitre,
    aggKey,
    sources: ["auditd"],
    ...(node ? { asset: node } : {}),
    ...(exe && exe.includes("/") ? { path: exe } : {}),
    ...(procName ? { processName: procName } : {}),
    ...(addr || saddrInfo ? { srcIp: cleanIp(addr) || saddrInfo?.ip } : {}),
    ...(saddrInfo?.port ? { port: saddrInfo.port } : {}),
  };
}

// ───────────────────────────── aureport tabular fallback ─────────────────────────────

// An `aureport` numbered row: "1. 04/01/2024 10:00:00 <columns…>". Column meaning varies per
// report (-au/-x/-f/…), so we keep the row whole as an Info evidence event at its own time and
// scrape any IP out of it. (The rich mapping is for the audit-record format above.)
const RE_AUREPORT = /^\s*\d+\.\s+(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}:\d{2}:\d{2})\s+(.*)$/;
const RE_IPV4_G = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

function mapAureportRow(m: RegExpMatchArray, iocSink: Map<string, SiemIoc>): MappedEvent {
  const [, mm, dd, yyyy, time, rest] = m;
  const iso = `${yyyy}-${mm}-${dd}T${time}Z`;
  const d = new Date(iso);
  const body = oneLine(rest);
  for (const ip of body.matchAll(RE_IPV4_G)) { const c = cleanIp(ip[0]); if (c) addIoc(iocSink, "ip", c); }
  const failed = /\bno\b\s*$|\bfailed\b/i.test(body);
  return {
    timestamp: Number.isNaN(d.getTime()) ? "" : d.toISOString(),
    description: `aureport: ${body}`.slice(0, 600),
    severity: failed ? "Low" : "Info",
    mitre: failed ? ["T1110"] : [],
    aggKey: `aureport|${body.toLowerCase().replace(/\b\d{2,}\b/g, "#")}`.slice(0, 400),
    sources: ["auditd"],
  };
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseAuditdLog(text: string, opts: AuditdImportOptions = {}): AuditdParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const lines = text.split(/\r\n|\r|\n/);

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const bySerial = new Map<string, AuditEvent>();
  const aureportRows: RegExpMatchArray[] = [];

  for (const line of lines) {
    const l = line.trim();
    if (!l || l === "----") continue;             // ausearch record separator
    if (l.startsWith("time->")) continue;          // ausearch -i header (epoch is in msg=audit)

    const parsed = parseAuditLine(l);
    if (!parsed) {
      const am = RE_AUREPORT.exec(l);
      if (am) aureportRows.push(am);
      continue;
    }

    let ev = bySerial.get(parsed.serial);
    if (!ev) {
      ev = { serial: parsed.serial, tsMs: parsed.tsMs, types: [], fields: {}, argv: [], pathNames: [] };
      bySerial.set(parsed.serial, ev);
    }
    if (!ev.types.includes(parsed.type)) ev.types.push(parsed.type);
    if (parsed.tsMs && (!ev.tsMs || parsed.tsMs < ev.tsMs)) ev.tsMs = parsed.tsMs;

    // Merge fields — first non-empty wins per key, so the SYSCALL exe/comm survives later context.
    for (const [k, v] of Object.entries(parsed.fields)) if (!(k in ev.fields)) ev.fields[k] = v;

    if (parsed.type === "EXECVE") ev.argv = execveArgv(parsed.fields);
    if (parsed.type === "PATH" && parsed.fields["name"]) ev.pathNames.push(decodeHex(parsed.fields["name"]));
    if (parsed.type === "SOCKADDR" && parsed.fields["saddr"]) ev.saddr = parsed.fields["saddr"];

    const node = (parsed.fields["node"] ?? "").trim();
    if (node) hostTally.set(node, (hostTally.get(node) ?? 0) + 1);
  }

  const mapped: MappedEvent[] = [];
  for (const ev of bySerial.values()) mapped.push(mapAuditEvent(ev, iocSink));
  for (const row of aureportRows) mapped.push(mapAureportRow(row, iocSink));

  const total = bySerial.size + aureportRows.length;
  const format = bySerial.size > 0 ? "auditd" : aureportRows.length > 0 ? "aureport" : "empty";

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format,
    hostname,
  };
}
