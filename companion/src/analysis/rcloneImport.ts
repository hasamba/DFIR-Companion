// rclone and MEGAsync evidence (#908 item 9).
//
// These two tools move the data out. rclone is the exfiltration workhorse of modern intrusions
// because it speaks forty cloud backends, runs unattended, resumes, and encrypts in flight; MEGA is
// the destination of choice for several ransomware crews. Both leave two kinds of artifact, and
// they answer different questions:
//
//   • THE CONFIGURATION says where the operator COULD send data, and under whose account. It is
//     capability and intent. It is NOT proof that anything was sent, and this importer says so on
//     every configuration event it writes, because "rclone.conf found" reads like a conclusion and
//     is not one.
//   • THE TRANSFER LOG says what actually moved: file names, sizes, direction, the remote it went
//     to, whether each transfer succeeded, and — unlike any cloud audit log — the BYTE COUNT.
//
// ─────────────────────────── CREDENTIALS ARE REDACTED BEFORE ANYTHING ELSE ───────────────────────
//
// An rclone.conf holds live OAuth refresh tokens, S3 secret keys, service-account JSON and
// obscured passwords. Those are the attacker's credentials — and often the VICTIM's, because the
// operator configured the remote using the victim's own cloud account. They must never reach a
// report, a dashboard, an export, or an AI prompt.
//
// So redaction happens in the PARSER, not at display time. Nothing downstream is trusted to
// remember: the value never exists in the parsed structure at all. What survives is the fact that
// a secret was present and how long it was, which is what an analyst actually needs — "this remote
// carries a live token" is the finding, and the token itself adds nothing to it.
//
// ─────────────────────────── VERSIONS ───────────────────────────
//
// rclone's config format has been stable since v1.33 and its log format since v1.39, but neither
// artifact is required to carry a version. Where one is present it is recorded; where it is absent
// the note says the format could not be confirmed, rather than implying the parse was validated.

import type { Severity } from "./stateTypes.js";

/** What replaces a secret. Chosen to be obviously not a value. */
export const REDACTED = "[redacted]";

/** Cap on lines read from one artifact. */
export const MAX_LINES = 200_000;

/** Cap on events produced from one artifact. */
export const MAX_EVENTS = 2_000;

/**
 * Configuration keys whose values are secrets.
 *
 * Matched as a SUBSTRING of the key, deliberately: rclone backends spell them many ways
 * (`client_secret`, `secret_access_key`, `sas_url`, `service_account_credentials`, `chunk_token`),
 * and a new backend adding another spelling must fail CLOSED — redacted — not open.
 */
const SECRET_KEY_RE =
  /pass|token|secret|key|credential|auth|cookie|sas_url|signature|sig$|bearer|session|private/i;

/**
 * Strip credentials out of a value that is KEPT for its destination facts.
 *
 * `url`, `endpoint` and `host` are evidence — they say where the data goes — and they routinely
 * carry a credential inside them. A WebDAV url carries the account and its password inline,
 * ahead of the host; an Azure staging url carries a shared-access signature that grants write
 * access on its own. The first version kept those verbatim, so a live secret
 * reached the event description, the IOC list, every export and the AI prompt — through the branch
 * that exists to preserve evidence.
 *
 * The destination survives; the secret does not.
 */
export function stripEmbeddedSecrets(value: string): string {
  let out = (value ?? "").replace(
    /(\b[a-z][\w+.-]*:\/\/)([^/@\s]+)@/gi,
    (_m, scheme: string, userinfo: string) => {
      const user = userinfo.split(":")[0];
      return `${scheme}${user}:${REDACTED}@`;
    },
  );
  // Signed-URL and token parameters. The parameter NAME is kept, because "this url carries a
  // signature" is itself evidence; the value is not.
  out = out.replace(
    /([?&](?:[\w.-]*(?:sig|signature|token|key|secret|password|passwd|pwd|credential|auth|sas)[\w.-]*)=)[^&\s]*/gi,
    `$1${REDACTED}`,
  );
  return out;
}

/** Keys that are destination facts, not secrets. Kept because they are the evidence. */
const KEEP_KEY_RE =
  /^(?:type|provider|region|endpoint|location_constraint|storage_class|bucket|container|team_drive|root_folder_id|url|host|port|user|username|account|email|drive_id|upload_cutoff|remote|env_auth|auth_url|auth_version|acl|tenant|tenant_domain|domain|project|zone|nextcloud_chunk_size|vendor)$/i;

export interface RcloneRemote {
  name: string;
  /** The backend: drive, s3, mega, dropbox, onedrive, sftp… */
  type: string;
  /** Non-secret settings, verbatim. */
  settings: Record<string, string>;
  /** Secret keys that were present, with their value lengths. The values themselves are gone. */
  secretsPresent: { key: string; length: number }[];
}

/** Is this text an rclone configuration file? */
export function isRcloneConfig(text: string): boolean {
  const head = (text ?? "").slice(0, 65_536);
  if (!/^\s*\[[^\]\n]+\]\s*$/m.test(head)) return false;
  // `type = <backend>` is the one key every rclone remote has and almost no other INI does.
  return /^\s*type\s*=\s*(?:drive|s3|mega|dropbox|onedrive|b2|box|sftp|ftp|webdav|swift|azureblob|gcs|google cloud storage|pcloud|yandex|koofr|crypt|union|chunker|http|jottacloud|mailru|premiumizeme|putio|seafile|sharefile|sugarsync|tardigrade|storj|zoho|opendrive|qingstor|hubic|alias|cache|local)\b/im.test(
    head,
  );
}

/**
 * Parse an rclone configuration, redacting every secret as it is read.
 *
 * The secret value is dropped at the point of parsing. It is never stored, so no later change to
 * display, export or prompt-building can leak it.
 */
export function parseRcloneConfig(text: string): RcloneRemote[] {
  const out: RcloneRemote[] = [];
  let current: RcloneRemote | null = null;

  for (const raw of (text ?? "").split(/\r?\n/).slice(0, MAX_LINES)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;

    const section = /^\[([^\]]+)\]$/.exec(line);
    if (section) {
      if (current) out.push(current);
      current = { name: section[1].trim(), type: "", settings: {}, secretsPresent: [] };
      continue;
    }
    if (!current) continue;

    const kv = /^([^=]+?)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1].trim();
    const value = kv[2].trim();

    if (/^type$/i.test(key)) {
      current.type = value;
      current.settings[key.toLowerCase()] = value;
      continue;
    }
    // KEEP is tested FIRST. `env_auth` contains "auth", so the secret test claimed it and the
    // report told the analyst to rotate a boolean — `env_auth = true` means the opposite, that no
    // credential is stored in this file at all. `auth_url` (an OpenStack endpoint, i.e. evidence of
    // the destination) and `auth_version` were lost the same way.
    if (KEEP_KEY_RE.test(key)) {
      current.settings[key.toLowerCase()] = stripEmbeddedSecrets(value).slice(0, 300);
      continue;
    }
    if (SECRET_KEY_RE.test(key)) {
      current.secretsPresent.push({ key: key.toLowerCase(), length: value.length });
      continue;
    }
    // An unrecognised key. Kept, but only if it holds nothing that looks like a secret — a long
    // opaque blob in an unknown key is exactly what a new backend's token looks like.
    if (value.length > 64 || /^[A-Za-z0-9+/=_-]{40,}$/.test(value)) {
      current.secretsPresent.push({ key: key.toLowerCase(), length: value.length });
      continue;
    }
    current.settings[key.toLowerCase()] = value;
  }
  if (current) out.push(current);
  return out;
}

/** Where a remote sends data, in words, from its non-secret settings alone. */
export function describeRemote(remote: RcloneRemote): string {
  const s = remote.settings;
  const parts: string[] = [];
  if (s.bucket) parts.push(`bucket ${s.bucket}`);
  if (s.container) parts.push(`container ${s.container}`);
  if (s.endpoint) parts.push(`endpoint ${s.endpoint}`);
  if (s.host) parts.push(`host ${s.host}`);
  if (s.url) parts.push(`url ${s.url}`);
  if (s.region) parts.push(`region ${s.region}`);
  if (s.user || s.username) parts.push(`user ${s.user ?? s.username}`);
  if (s.account) parts.push(`account ${s.account}`);
  if (s.team_drive) parts.push(`team drive ${s.team_drive}`);
  return parts.join(", ");
}

// ─────────────────────────── transfer logs ───────────────────────────

export type TransferOutcome = "copied" | "deleted" | "failed" | "checked" | "renamed" | "summary";

export interface TransferRecord {
  time: string;
  /** The file rclone named. */
  file: string;
  outcome: TransferOutcome;
  /** The remote or path the transfer went to, when the line names one. */
  destination: string;
  /** Bytes, when the line carried a size. rclone DOES record this; cloud audit logs do not. */
  bytes: number | null;
  /** The line as collected. */
  raw: string;
}

// rclone: `2026/01/02 09:00:00 INFO  : docs/report.pdf: Copied (new)`
const RCLONE_LINE_RE =
  /^(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+(INFO|NOTICE|ERROR|DEBUG|WARNING)\s*:\s*(.*)$/;

// The end-of-run summary, which is where the byte total lives.
const TRANSFERRED_RE = /^Transferred:\s+([\d.]+\s*[KMGTP]?i?B)\s*\/\s*([\d.]+\s*[KMGTP]?i?B)/i;

// MEGAsync / megacmd: `01/02-09:00:00.123456 INFO  Sync - Upload finished: /docs/report.pdf`
const MEGA_LINE_RE =
  /^(\d{2}\/\d{2}-\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+(INFO|ERR|ERROR|WARN|DBG|DEBUG|CRIT)\s+(.*)$/i;

/**
 * Is this text an rclone transfer log?
 *
 * The line SHAPE alone is not enough. `2026/01/02 09:00:00 INFO  : x: Copied (new)` is a generic
 * timestamped log line, and one of them anywhere in the first 500 lines claimed the whole file —
 * so a concatenated or combined log holding a single rclone line was routed here entirely and
 * everything else in it was dropped. rclone's own vocabulary has to be present too.
 */
export function isRcloneLog(text: string): boolean {
  const head = (text ?? "").slice(0, 65_536);
  if (!firstMatchingLine(head, RCLONE_LINE_RE)) return false;
  return /\brclone\b|: Copied \(|: Failed to copy|^Transferred:|\bChecks:\s+\d/im.test(head);
}

/** Is this text a MEGAsync or megacmd log? */
export function isMegaLog(text: string): boolean {
  const head = (text ?? "").slice(0, 65_536);
  const line = firstMatchingLine(head, MEGA_LINE_RE);
  if (!line) return false;
  // The MEGA marker has to be in a MATCHING line, not merely somewhere in the first 64 KB. Scanning
  // the whole head let any application log that happened to mention a `mega-` filename and used
  // `MM/DD-HH:MM:SS LEVEL` be claimed in full.
  return (
    /\bMEGA(?:sync|cmd|client|sdk)\b/i.test(head) &&
    /\bMEGA(?:sync|cmd|client|sdk)?\b|\bSync\b|\bTransfer\b/i.test(line)
  );
}

function firstMatchingLine(text: string, re: RegExp): string | null {
  for (const line of (text ?? "").slice(0, 65_536).split(/\r?\n/).slice(0, 500)) {
    if (re.test(line.trim())) return line.trim();
  }
  return null;
}

/** Convert rclone's human sizes to bytes. Returns null when the text is not a size. */
export function parseSize(text: string): number | null {
  const m = /^([\d.]+)\s*([KMGTP]?)(i?)B$/i.exec((text ?? "").trim());
  if (!m) return null;
  const value = Number(m[1]);
  if (!Number.isFinite(value)) return null;
  const unit = m[2].toUpperCase();
  const base = m[3] ? 1024 : 1000;
  const power = { "": 0, K: 1, M: 2, G: 3, T: 4, P: 5 }[unit] ?? 0;
  return Math.round(value * base ** power);
}

/** rclone writes local time with no zone. Keep the wall-clock reading and say nothing about UTC. */
function rcloneTime(stamp: string): string {
  const [date, clock] = stamp.trim().split(/\s+/);
  return `${date.replace(/\//g, "-")}T${clock}`;
}

/**
 * MEGAsync omits the year. Take it from the reference time rather than inventing one.
 *
 * And step BACK a year when that would put the event in the future. A December log imported in
 * January otherwise landed eleven months AFTER the case instead of days before it — an exfiltration
 * placed on the wrong side of the incident is worse than one with no date at all.
 */
export function megaTime(stamp: string, yearFrom: string): string {
  const [md, clock] = stamp.split("-");
  const [month, day] = md.split("/");
  const ref = Date.parse(yearFrom) || Date.now();
  let year = new Date(ref).getUTCFullYear();
  if (Date.parse(`${year}-${month}-${day}T${clock}Z`) > ref + 24 * 60 * 60 * 1000) year -= 1;
  return `${year}-${month}-${day}T${clock}`;
}

export function parseRcloneLog(text: string): TransferRecord[] {
  const out: TransferRecord[] = [];
  let lastTime = "";
  for (const raw of (text ?? "").split(/\r?\n/).slice(0, MAX_LINES)) {
    if (out.length >= MAX_EVENTS) break;
    const line = raw.trim();

    // THE STATS BLOCK HAS NO TIMESTAMP PREFIX. rclone writes it on its own lines:
    //
    //   2026/01/02 09:05:00 INFO  :
    //   Transferred:        4.627 GiB / 4.627 GiB, 100%, 5.123 MiB/s, ETA 0s
    //   Checks:                 2 / 2, 100%
    //
    // The single-line form only appears with --stats-one-line, which is not the default — so
    // requiring the prefix meant the BYTE TOTAL, the one number no cloud audit log records and the
    // headline claim of this importer, never fired on an ordinary rclone log.
    const standalone = TRANSFERRED_RE.exec(line);
    if (standalone) {
      out.push({
        time: lastTime,
        file: "",
        outcome: "summary",
        destination: "",
        bytes: parseSize(standalone[1]),
        raw: stripEmbeddedSecrets(line),
      });
      continue;
    }

    const m = RCLONE_LINE_RE.exec(line);
    if (!m) continue;
    lastTime = rcloneTime(m[1]);
    const time = rcloneTime(m[1]);
    const body = m[3];

    const summary = TRANSFERRED_RE.exec(body);
    if (summary) {
      out.push({
        time,
        file: "",
        outcome: "summary",
        destination: "",
        bytes: parseSize(summary[1]),
        raw: line,
      });
      continue;
    }

    // `<file>: <what happened>`
    const split = body.indexOf(": ");
    if (split < 0) continue;
    const file = body.slice(0, split).trim();
    const what = body.slice(split + 2).trim();
    const outcome = rcloneOutcome(what);
    if (!outcome) continue;
    // THE LOG LINE IS REDACTED TOO. Redaction existed only on the config path, and every grade
    // appends 300 characters of the raw line — so an rclone error that echoes a presigned URL put
    // an access key id and a request signature straight into a forensic event.
    out.push({ time, file, outcome, destination: "", bytes: null, raw: stripEmbeddedSecrets(line) });
  }
  return out;
}

function rcloneOutcome(what: string): TransferOutcome | null {
  if (/^(?:copied|uploaded|moved|multi-thread copied)\b/i.test(what)) return "copied";
  if (/^deleted\b/i.test(what)) return "deleted";
  if (/^renamed\b/i.test(what)) return "renamed";
  if (/^failed to (?:copy|upload|move|transfer)\b/i.test(what)) return "failed";
  return null;
}

export function parseMegaLog(text: string, yearFrom: string): TransferRecord[] {
  const out: TransferRecord[] = [];
  for (const raw of (text ?? "").split(/\r?\n/).slice(0, MAX_LINES)) {
    if (out.length >= MAX_EVENTS) break;
    const line = raw.trim();
    const m = MEGA_LINE_RE.exec(line);
    if (!m) continue;
    const body = m[3];
    // `Upload finished: /docs/report.pdf` and `Sync - Upload finished: …`
    const up = /\b(?:upload|put)\s+(?:finished|complete[d]?|ok)\s*:?\s*(.+)$/i.exec(body);
    if (up) {
      out.push({
        time: megaTime(m[1], yearFrom),
        file: up[1].trim().slice(0, 400),
        outcome: "copied",
        destination: "MEGA",
        bytes: null,
        raw: stripEmbeddedSecrets(line),
      });
      continue;
    }
    const fail = /\b(?:upload|transfer)\s+(?:failed|error)\s*:?\s*(.+)$/i.exec(body);
    if (fail) {
      out.push({
        time: megaTime(m[1], yearFrom),
        file: fail[1].trim().slice(0, 400),
        outcome: "failed",
        destination: "MEGA",
        bytes: null,
        raw: stripEmbeddedSecrets(line),
      });
    }
  }
  return out;
}

// ─────────────────────────── grading ───────────────────────────

/** Backends that are consumer file-sharing services rather than corporate infrastructure. */
const CONSUMER_BACKEND_RE =
  /^(?:mega|dropbox|pcloud|yandex|mailru|premiumizeme|putio|jottacloud|opendrive|box)$/i;

export interface RcloneCaseContext {
  /** Process names already in the case, so a config can be tied to an execution. */
  processNames?: ReadonlySet<string>;
  /** Hosts and addresses already in the case, so a remote can be tied to a connection. */
  networkHosts?: ReadonlySet<string>;
}

export interface RcloneSignal {
  severity: Severity;
  mitre: string[];
  description: string;
}

/**
 * Grade one configured remote.
 *
 * NEVER above Medium on its own, and the wording is deliberate: a configuration establishes that
 * the host COULD send data to this destination and that someone set it up. It does not establish
 * that anything was sent. The transfer log is what answers that, and it is a different artifact.
 */
export function gradeRemote(remote: RcloneRemote, ctx: RcloneCaseContext = {}): RcloneSignal {
  const where = describeRemote(remote);
  const secrets = remote.secretsPresent;
  const consumer = CONSUMER_BACKEND_RE.test(remote.type);

  let description =
    `rclone remote "${remote.name}" is configured for ${remote.type || "an unnamed backend"}` +
    (where ? ` (${where})` : "") +
    ". ";
  description +=
    "A configured remote establishes CAPABILITY and intent — this host was set up to move data to that destination — and is NOT evidence that any data was transferred. The transfer log answers that; this file does not.";

  if (secrets.length) {
    description += ` The remote carries ${secrets.length} stored credential(s) (${secrets.map((s) => `${s.key}, ${s.length} chars`).join("; ")}), redacted here and never stored by this tool. Treat them as live and rotate them.`;
  }
  if (consumer) {
    description += ` ${remote.type} is a consumer file-sharing service, which is a common exfiltration destination and an uncommon corporate one.`;
  }

  // Execution and network corroboration, when the case already holds it.
  const ran = ctx.processNames?.has("rclone.exe") || ctx.processNames?.has("rclone");
  if (ran) description += " rclone execution is already recorded in this case.";
  const host = remote.settings.endpoint ?? remote.settings.host ?? remote.settings.url ?? "";
  const contacted =
    host && ctx.networkHosts
      ? [...ctx.networkHosts].some((h) => host.includes(h) || h.includes(host))
      : false;
  if (contacted) description += ` A connection to ${host} is already recorded in this case.`;

  const severity: Severity = ran || contacted || consumer ? "Medium" : "Low";
  return {
    severity,
    // T1567.002 is exfiltration TO cloud storage. A configuration is preparation for it, so the
    // technique that fits is the tool being staged, not the exfiltration having happened.
    mitre: ["T1608"],
    description: description.slice(0, 900),
  };
}

/** Grade one transfer record. This one IS evidence that data moved. */
export function gradeTransfer(
  record: TransferRecord,
  remoteNames: readonly string[] = [],
): RcloneSignal | null {
  if (record.outcome === "checked") return null;

  if (record.outcome === "summary") {
    const bytes = record.bytes;
    return {
      severity: "High",
      mitre: ["T1567.002"],
      description:
        `rclone run summary: ${bytes === null ? "an unreadable total" : `${groupDigits(bytes)} bytes`} transferred. ` +
        "Unlike a cloud audit log, an rclone log records the volume — this is the number of bytes the tool reports having moved. " +
        record.raw.slice(0, 300),
    };
  }

  const named = remoteNames.find((n) => record.file.startsWith(`${n}:`));
  const target = record.destination || named || "";

  if (record.outcome === "failed") {
    return {
      severity: "Medium",
      mitre: ["T1567.002"],
      description: `rclone recorded a FAILED transfer of ${record.file}${target ? ` to ${target}` : ""}. The outcome is recorded as failed, so this file is not established as having left the host. ${record.raw.slice(0, 300)}`,
    };
  }

  if (record.outcome === "deleted") {
    return {
      severity: "Medium",
      mitre: ["T1485"],
      description: `rclone deleted ${record.file}${target ? ` on ${target}` : ""}. ${record.raw.slice(0, 300)}`,
    };
  }

  return {
    severity: "High",
    mitre: ["T1567.002"],
    description: `rclone transferred ${record.file}${target ? ` to ${target}` : ""}, recorded as ${record.outcome}. ${record.raw.slice(0, 300)}`,
  };
}

/**
 * Group a byte count with commas, without asking the runtime's locale.
 *
 * toLocaleString would print 4.627.827.261 on a machine set to a European locale and 4,627,827,261
 * on another. A number in a forensic report must read the same for every analyst who opens it.
 */
function groupDigits(n: number): string {
  return String(Math.trunc(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** The version the artifact declared, or "" when it declared none. */
export function artifactVersion(text: string): string {
  return (
    /\brclone\s+v(\d+\.\d+(?:\.\d+)?)/i.exec(text ?? "")?.[1] ??
    /\bMEGA(?:sync|cmd)?\s+v?(\d+\.\d+(?:\.\d+)?)/i.exec(text ?? "")?.[1] ??
    ""
  );
}

/**
 * The note that goes on the import, including what could not be confirmed.
 *
 * A parser that says nothing about the version it assumed reads as though it validated one.
 */
export function versionNote(text: string): string {
  const v = artifactVersion(text);
  const zone =
    " rclone writes local time with no time zone and MEGAsync writes no year, so these events are placed at the endpoint's WALL-CLOCK reading and stored as if it were UTC. On an endpoint that is not on UTC the whole set is shifted by its offset — correct for that before correlating these against cloud audit logs.";
  return (
    (v
      ? `The artifact declares version ${v}.`
      : "The artifact carries no version marker, so the format this parser assumed could not be confirmed against the tool that wrote it. Check the fields against the raw file before relying on them.") +
    zone
  );
}
