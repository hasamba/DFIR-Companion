// Linux persistence artifact PARSING (#908 item 5).
//
// The Companion could already read Linux shell history and grade the commands in it. That only sees
// what an operator typed. It does not see what the host will do on its own, tomorrow, with no one
// logged in — which is what persistence is. This module reads the collected files that hold that
// answer: SSH authorized keys, cron, systemd units, shell initialization files, SUID listings and
// the PATH.
//
// PARSING ONLY. Nothing here decides that anything is suspicious; linuxPersistRules.ts does that.
// The split is deliberate: the parsers are the part that must survive real-world formatting, and
// they are much easier to test when they return structure instead of a verdict.
//
// ─────────────────────────── HOW A COLLECTION ARRIVES ───────────────────────────
//
// A Linux triage collection is many small text files. Analysts hand them over as one file, because
// one file is what an upload takes. Every common way of making that file writes a header line per
// member, and there are only a few spellings in practice:
//
//   ==> /root/.ssh/authorized_keys <==      head / tail over several files — the most common
//   === /etc/crontab ===                    hand-written and script-written collections
//   ##### /home/u/.bashrc #####             CatScale-style banners
//   # FILE: /etc/systemd/system/x.service   scripted collections
//
// A header must be the WHOLE line and must name an ABSOLUTE path. A shell script that echoes
// something header-shaped in the middle of a line does not split the collection. A script that
// echoes a full header line on its own, naming an absolute path, still would — that is a real limit
// and the note the importer writes says which files it believed it read, so an analyst can see it.
//
// Modification times are graded when the collection recorded them, and their ABSENCE is stated
// rather than assumed. `head` writes no mtime, so most collections have none; a collection that ran
// `stat` can annotate a member with a `# mtime:` line and the incident-time rule then applies.

/** The artifact classes this module understands. */
export type LinuxArtifactKind =
  "authorized_keys" | "cron" | "systemd" | "shellrc" | "suid" | "env" | "unknown";

export interface CollectedFile {
  /** Absolute path as the collection recorded it. */
  path: string;
  kind: LinuxArtifactKind;
  content: string;
  /** ISO time, only when the collection recorded one. Undefined means NOT COLLECTED, not "unchanged". */
  mtime?: string;
  owner?: string;
}

/** Cap on members read from one collection, so a whole-filesystem dump cannot stall an import. */
export const MAX_MEMBERS = 500;

/** Cap on lines read from one member. */
export const MAX_LINES = 5_000;

// A header line, in the four spellings above. The path must be absolute.
const HEADER_RES: RegExp[] = [
  /^==>\s*(\/\S[^<]*?)\s*<==$/,
  /^={3,}\s*(\/\S.*?)\s*={3,}$/,
  /^#{3,}\s*(\/\S.*?)\s*#{3,}$/,
  /^#\s*FILE:\s*(\/\S.*?)\s*$/i,
];

function headerPath(line: string): string | null {
  for (const re of HEADER_RES) {
    const m = re.exec(line.trim());
    if (m) return m[1].trim();
  }
  return null;
}

/**
 * Which artifact a path holds, from the path alone.
 *
 * The path is the only reliable signal. A `.bashrc` and a systemd unit and a cron file are all
 * plain text, and content sniffing confuses them — a `.bashrc` that sets PATH looks exactly like a
 * crontab environment line.
 */
export function classifyLinuxArtifact(path: string): LinuxArtifactKind {
  const p = path.toLowerCase();
  const base = p.slice(p.lastIndexOf("/") + 1);

  if (base === "authorized_keys" || base === "authorized_keys2") return "authorized_keys";
  if (base.endsWith(".service") || base.endsWith(".timer") || base.endsWith(".socket")) return "systemd";
  if (p.includes("/systemd/") && !base.includes(".")) return "systemd";
  if (base === "crontab" || p.includes("/cron.d/") || p.includes("/spool/cron")) return "cron";
  if (/^cron(tab)?[-_.]/.test(base) || base.endsWith(".cron")) return "cron";
  if (
    base === ".bashrc" ||
    base === ".bash_profile" ||
    base === ".bash_login" ||
    base === ".profile" ||
    base === ".zshrc" ||
    base === ".zprofile" ||
    base === "bashrc" ||
    base === "profile" ||
    base === "zshrc" ||
    p.includes("/profile.d/")
  ) {
    return "shellrc";
  }
  // A SUID listing is named for what produced it, not for a file on the host.
  if (/suid|setuid|sgid/.test(p)) return "suid";
  if (base === "env" || base === "environment" || /printenv|\benv\b/.test(base)) return "env";
  return "unknown";
}

/**
 * Split one uploaded collection into its member files.
 *
 * A body before the first header belongs to no file and is dropped: it is a banner, not evidence.
 */
export function splitCollection(text: string): CollectedFile[] {
  const out: CollectedFile[] = [];
  const lines = (text ?? "").split(/\r?\n/);
  let current: { path: string; body: string[]; mtime?: string; owner?: string } | null = null;

  const flush = () => {
    if (!current) return;
    if (out.length < MAX_MEMBERS) {
      out.push({
        path: current.path,
        kind: classifyLinuxArtifact(current.path),
        content: current.body.slice(0, MAX_LINES).join("\n"),
        ...(current.mtime ? { mtime: current.mtime } : {}),
        ...(current.owner ? { owner: current.owner } : {}),
      });
    }
    current = null;
  };

  for (const line of lines) {
    const p = headerPath(line);
    if (p) {
      flush();
      current = { path: p, body: [] };
      continue;
    }
    if (!current) continue;
    // Metadata a `stat`-annotated collection can attach, read only directly under the header.
    if (current.body.length === 0) {
      const meta = /^#\s*(mtime|modified|owner|uid|user)\s*:\s*(.+)$/i.exec(line.trim());
      if (meta) {
        const key = meta[1].toLowerCase();
        const value = meta[2].trim();
        if (key === "mtime" || key === "modified") {
          const t = Date.parse(value);
          if (Number.isFinite(t)) current.mtime = new Date(t).toISOString();
        } else {
          current.owner = value;
        }
        continue;
      }
    }
    current.body.push(line);
  }
  flush();
  return out;
}

/**
 * Treat one uploaded file as a collection of one, when it carries no headers.
 *
 * The filename is all there is to go on, so an unrecognised name yields nothing rather than a guess.
 */
export function singleArtifact(filename: string, text: string): CollectedFile[] {
  const kind = classifyLinuxArtifact(filename);
  if (kind === "unknown") return [];
  return [{ path: filename, kind, content: text }];
}

// ─────────────────────────── SSH authorized keys ───────────────────────────

/** The key types OpenSSH accepts. The first token that matches one ENDS the options field. */
export const SSH_KEY_TYPES = [
  "ssh-rsa",
  "ssh-dss",
  "ssh-ed25519",
  "ssh-ed25519-cert-v01@openssh.com",
  "sk-ssh-ed25519@openssh.com",
  "sk-ecdsa-sha2-nistp256@openssh.com",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "rsa-sha2-256",
  "rsa-sha2-512",
];

export interface SshKey {
  /** The raw options field, empty when the line has none. */
  options: string;
  type: string;
  /** The base64 material. This IS the identity of the key; nothing is derived from it. */
  blob: string;
  comment: string;
  /** 1-based line number inside the file, for the evidence link. */
  line: number;
}

/**
 * Parse an authorized_keys file.
 *
 * The options field is the hard part: it is comma-separated, its values may be QUOTED, and a quoted
 * value may contain both spaces and commas — `command="/bin/bash -c 'x,y'",no-pty`. Splitting on
 * whitespace first therefore loses the command. The scan tracks quote state and stops at the first
 * unquoted token that is a known key type.
 */
export function parseAuthorizedKeys(content: string): SshKey[] {
  const out: SshKey[] = [];
  const lines = (content ?? "").split(/\r?\n/).slice(0, MAX_LINES);

  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;

    // Walk tokens, honouring double quotes and backslash escapes, until a key type appears.
    let quoted = false;
    let start = 0;
    let typeAt = -1;
    for (let c = 0; c <= line.length; c++) {
      const ch = line[c];
      if (ch === "\\" && quoted) {
        c++;
        continue;
      }
      if (ch === '"') {
        quoted = !quoted;
        continue;
      }
      const atEnd = c === line.length;
      if (!quoted && (atEnd || ch === " " || ch === "\t")) {
        const token = line.slice(start, c);
        if (token && SSH_KEY_TYPES.includes(token.toLowerCase())) {
          typeAt = start;
          break;
        }
        // Skip the run of whitespace.
        while (c + 1 < line.length && (line[c + 1] === " " || line[c + 1] === "\t")) c++;
        start = c + 1;
      }
    }
    if (typeAt < 0) return; // not a key line

    const options = line.slice(0, typeAt).trim().replace(/,$/, "");
    const rest = line.slice(typeAt).split(/\s+/);
    const type = rest[0] ?? "";
    const blob = rest[1] ?? "";
    const comment = rest.slice(2).join(" ");
    if (!blob) return;
    out.push({ options, type, blob, comment, line: i + 1 });
  });
  return out;
}

/** Read one option's value out of an authorized_keys options field, quotes removed. */
export function keyOption(options: string, name: string): string | null {
  const re = new RegExp(`(?:^|,)\\s*${name}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*"|[^,]*)`, "i");
  const m = re.exec(options);
  if (!m) return null;
  const v = m[1].trim();
  if (v.startsWith('"')) return v.slice(1, -1).replace(/\\(.)/g, "$1");
  return v;
}

// ─────────────────────────── cron ───────────────────────────

export interface CronEntry {
  /** `@reboot`, `@daily`, or the five schedule fields joined by a space. */
  schedule: string;
  /** Present for /etc/crontab and /etc/cron.d, which carry a user column; taken from the path for a spool file. */
  user: string;
  command: string;
  line: number;
}

/** Environment assignments a crontab carries, e.g. PATH and SHELL. */
export interface CronEnv {
  name: string;
  value: string;
  line: number;
}

const CRON_SPECIALS = new Set([
  "@reboot",
  "@yearly",
  "@annually",
  "@monthly",
  "@weekly",
  "@daily",
  "@midnight",
  "@hourly",
]);

/**
 * Does this cron file carry a user column?
 *
 * `/etc/crontab` and `/etc/cron.d/*` do. A user's own spool file does not, and its owner is the
 * directory entry's name. Nothing in the CONTENT distinguishes them reliably — a five-field line
 * whose command begins with a bare word is indistinguishable from a six-field line — so the path
 * decides.
 */
export function cronHasUserColumn(path: string): boolean {
  const p = path.toLowerCase();
  return p.endsWith("/crontab") || p.includes("/cron.d/") || p.includes("/cron.daily");
}

/** The account a spool crontab belongs to, from its filename. */
export function cronSpoolUser(path: string): string {
  const p = path.toLowerCase();
  if (!p.includes("/spool/cron")) return "";
  return path.slice(path.lastIndexOf("/") + 1);
}

export function parseCrontab(content: string, path: string): { entries: CronEntry[]; env: CronEnv[] } {
  const withUser = cronHasUserColumn(path);
  const spoolUser = cronSpoolUser(path);
  const entries: CronEntry[] = [];
  const env: CronEnv[] = [];

  (content ?? "")
    .split(/\r?\n/)
    .slice(0, MAX_LINES)
    .forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith("#")) return;

      const assign = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
      if (assign) {
        env.push({ name: assign[1], value: assign[2].trim().replace(/^["']|["']$/g, ""), line: i + 1 });
        return;
      }

      const parts = line.split(/\s+/);
      let schedule: string;
      let rest: string[];
      if (parts[0].startsWith("@")) {
        if (!CRON_SPECIALS.has(parts[0].toLowerCase())) return;
        schedule = parts[0];
        rest = parts.slice(1);
      } else {
        if (parts.length < (withUser ? 7 : 6)) return;
        schedule = parts.slice(0, 5).join(" ");
        rest = parts.slice(5);
      }
      const user = withUser ? (rest.shift() ?? "") : spoolUser;
      const command = rest.join(" ");
      if (!command) return;
      entries.push({ schedule, user, command, line: i + 1 });
    });

  return { entries, env };
}

// ─────────────────────────── systemd units ───────────────────────────

export interface SystemdUnit {
  description: string;
  /** Every ExecStart, in order. systemd allows several, and an empty `ExecStart=` RESETS the list. */
  execStart: string[];
  execStartPre: string[];
  user: string;
  restart: string;
  wantedBy: string;
  type: string;
}

/**
 * Parse a systemd unit file.
 *
 * Directives are read only inside `[Service]` except Description ([Unit]) and WantedBy ([Install]),
 * because a key outside its own section is inert to systemd and must be inert here too. Line
 * continuations with a trailing backslash are joined, since a long ExecStart is routinely wrapped.
 */
export function parseUnit(content: string): SystemdUnit {
  const unit: SystemdUnit = {
    description: "",
    execStart: [],
    execStartPre: [],
    user: "",
    restart: "",
    wantedBy: "",
    type: "",
  };

  const raw = (content ?? "").split(/\r?\n/).slice(0, MAX_LINES);
  // Join continuations first.
  const lines: string[] = [];
  let acc = "";
  for (const l of raw) {
    if (l.trimEnd().endsWith("\\")) {
      // One space joins the halves. Keeping both the trailing and the leading indentation produced a
      // run of spaces inside the command, which is harmless to a matcher and ugly in the evidence.
      acc += `${l.trimEnd().slice(0, -1).trimEnd()} `;
      continue;
    }
    lines.push(acc ? `${acc}${l.trimStart()}` : l);
    acc = "";
  }
  if (acc) lines.push(acc);

  let section = "";
  for (const l of lines) {
    const line = l.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) {
      section = sec[1].toLowerCase();
      continue;
    }
    const kv = /^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1].toLowerCase();
    const value = kv[2].trim();

    if (section === "unit" && key === "description") unit.description = value;
    if (section === "install" && key === "wantedby") unit.wantedBy = value;
    if (section !== "service") continue;

    if (key === "execstart") {
      // An empty assignment resets the list — systemd's own rule.
      if (value === "") unit.execStart = [];
      else unit.execStart.push(value);
    } else if (key === "execstartpre") {
      if (value === "") unit.execStartPre = [];
      else unit.execStartPre.push(value);
    } else if (key === "user") unit.user = value;
    else if (key === "restart") unit.restart = value;
    else if (key === "type") unit.type = value;
  }
  return unit;
}

/** Strip systemd's `-`, `@`, `+`, `!` and `:` execution-modifier prefixes off a command. */
export function stripExecPrefix(cmd: string): string {
  return cmd.replace(/^[-@+!:]+/, "").trim();
}

// ─────────────────────────── shell initialization ───────────────────────────

/**
 * The executable lines of a shell rc file, with comments and blanks dropped and backslash
 * continuations joined.
 *
 * A trailing `#` inside a quoted string is NOT a comment, so a naive strip loses part of a command.
 * Only a `#` that starts a line or follows whitespace outside quotes is treated as one.
 */
export function shellInitLines(content: string): { text: string; line: number }[] {
  const out: { text: string; line: number }[] = [];
  const raw = (content ?? "").split(/\r?\n/).slice(0, MAX_LINES);
  let acc = "";
  let accLine = 0;

  raw.forEach((l, i) => {
    if (l.trimEnd().endsWith("\\")) {
      if (!acc) accLine = i + 1;
      acc += `${l.trimEnd().slice(0, -1).trimEnd()} `;
      return;
    }
    const joined = acc ? `${acc}${l.trimStart()}` : l;
    const startLine = acc ? accLine : i + 1;
    acc = "";
    const text = stripComment(joined).trim();
    if (text) out.push({ text, line: startLine });
  });
  if (acc.trim()) out.push({ text: stripComment(acc).trim(), line: accLine });
  return out.filter((e) => e.text);
}

function stripComment(line: string): string {
  let single = false;
  let dbl = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "\\" && (dbl || (!single && !dbl))) {
      i++;
      continue;
    }
    if (ch === "'" && !dbl) single = !single;
    else if (ch === '"' && !single) dbl = !dbl;
    else if (ch === "#" && !single && !dbl && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

// ─────────────────────────── SUID listings ───────────────────────────

export interface SuidEntry {
  path: string;
  /** The mode string when the listing carried one, else empty. */
  mode: string;
  owner: string;
  /** true / false when the mode states it; null when the listing carried no mode at all. */
  setuid: boolean | null;
  line: number;
}

// `find -ls`, `ls -l` and a bare path list are the three shapes a SUID listing arrives in.
const MODE_RE = /(^|\s)([-lbcdps][rwxsStT-]{9})(\s|$)/;

/**
 * Parse a SUID listing.
 *
 * The path is taken from the first whitespace-preceded `/` to the END of the line, not as the last
 * whitespace-separated field: a real SUID binary can sit in a directory whose name has spaces, and
 * taking the last field silently truncated it to the final word.
 */
export function parseSuidListing(content: string): SuidEntry[] {
  const out: SuidEntry[] = [];
  (content ?? "")
    .split(/\r?\n/)
    .slice(0, MAX_LINES)
    .forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith("#")) return;

      const modeMatch = MODE_RE.exec(line);
      const mode = modeMatch ? modeMatch[2] : "";
      // Owner is the field after mode and link count in both `ls -l` and `find -ls`.
      let owner = "";
      if (mode) {
        const after = line.slice((modeMatch?.index ?? 0) + (modeMatch?.[1].length ?? 0) + mode.length).trim();
        const fields = after.split(/\s+/);
        owner = fields[1] ?? "";
      }

      let path = "";
      if (line.startsWith("/")) path = line;
      else {
        const m = /\s(\/[^\s].*)$/.exec(line);
        if (m) path = m[1];
      }
      if (!path) return;
      // `ls -l` renders a symlink as "target -> destination"; keep the entry itself.
      const arrow = path.indexOf(" -> ");
      if (arrow > 0) path = path.slice(0, arrow);

      out.push({
        path: path.trim(),
        mode,
        owner,
        setuid: mode ? mode[3] === "s" || mode[3] === "S" : null,
        line: i + 1,
      });
    });
  return out;
}

// ─────────────────────────── PATH ───────────────────────────

/**
 * Read PATH out of an `env` / `printenv` dump, an `/etc/environment` file, or a shell `export` line.
 *
 * Returns the entries in order. An EMPTY entry is preserved on purpose — a leading, trailing or
 * doubled colon means "the current directory", and dropping it would erase the finding.
 */
export function parsePathEntries(content: string): string[] | null {
  const lines = (content ?? "").split(/\r?\n/).slice(0, MAX_LINES);
  for (const raw of lines) {
    const m = /^\s*(?:export\s+)?PATH\s*=\s*(.*)$/.exec(raw);
    if (!m) continue;
    let value = m[1].trim();
    value = value.replace(/^["']|["']$/g, "");
    return value.split(":");
  }
  return null;
}

/** Split a PATH value that a caller already isolated (a crontab PATH=, a shell rc assignment). */
export function splitPathValue(value: string): string[] {
  return (value ?? "").replace(/^["']|["']$/g, "").split(":");
}
