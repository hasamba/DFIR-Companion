// Linux persistence GRADING (#908 item 5). The parsers live in linuxPersistence.ts.
//
// ─────────────────────────── THE RULE THIS MODULE IS BUILT AROUND ───────────────────────────
//
// Every artifact class here is something a working Linux host is FULL of. A server has authorized
// keys. It has cron jobs. It has systemd units and shell profiles and SUID binaries. Reporting them
// is not detection; it is a directory listing with a severity column, and it buries the one entry
// that matters under the four hundred that do not.
//
// So nothing is graded for EXISTING. Every finding here needs a second property that ordinary
// administration does not have:
//
//   • the payload runs out of a transient, world-writable directory (/tmp, /var/tmp, /dev/shm)
//   • the payload fetches code from the network and executes it in the same breath
//   • the payload is a reverse shell, or decodes itself before running
//   • root runs something a non-root account can rewrite
//   • a SUID binary is an interpreter, or is not part of any standard install
//   • PATH resolves commands out of the current directory or a writable one first
//   • the same private key opens two unrelated accounts
//
// Where an environment legitimately does one of those, the mechanism is a BASELINE the caller
// supplies — not a lowered threshold. That is the difference between "we allow it here" and "we
// cannot see it anywhere".
//
// ─────────────────────────── WHAT THE COLLECTION DOES NOT CONTAIN ───────────────────────────
//
// Most Linux collections are `cat` output, and `cat` writes no modification time. "Prioritize
// incident-time changes" is therefore conditional on evidence the collection usually lacks. Every
// signal carries `timeUnknown`, and its reason SAYS the modification time was not collected. An
// absent mtime never reads as "this file was not changed during the incident".

import type { Severity } from "./stateTypes.js";
import {
  keyOption,
  parseAuthorizedKeys,
  parseCrontab,
  parsePathEntries,
  parseSuidListing,
  parseUnit,
  shellInitLines,
  splitPathValue,
  stripExecPrefix,
  type CollectedFile,
  type LinuxArtifactKind,
} from "./linuxPersistence.js";
import {
  commandTarget,
  hiddenComponent,
  homeAccount,
  judgePayload,
  STANDARD_BIN_RE,
  TRANSIENT_RE,
  type PayloadJudgement,
} from "./linuxPayload.js";

export { commandTarget, hiddenComponent, homeAccount, judgePayload, type PayloadJudgement };

export interface LinuxSignal {
  /** The collected file the signal came from. */
  artifact: string;
  kind: LinuxArtifactKind;
  severity: Severity;
  mitre: string[];
  /** What happened and why it is suspicious, in one sentence an analyst can check. */
  reason: string;
  /** The collected line itself, so the finding links to evidence rather than replacing it. */
  evidence: string;
  line: number;
  /** The collection recorded no modification time, so an incident-time change could not be checked. */
  timeUnknown: boolean;
  /** The file the finding is ABOUT, when the rule identified one — the payload, not the artifact. */
  target?: string;
}

export interface LinuxBaseline {
  /** authorized_keys blobs this environment expects. */
  keys?: readonly string[];
  /** SUID paths this environment expects beyond the standard install set. */
  suid?: readonly string[];
  /** Unit or cron payload paths this environment expects. */
  paths?: readonly string[];
}

export interface LinuxContext {
  /** The incident window. A file changed inside it is prioritised. */
  incident?: { start: string; end: string };
  baseline?: LinuxBaseline;
}

const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const EVIDENCE_MAX = 300;

/** Interpreters that hand out a root shell the moment they are setuid. */
const INTERPRETER_RE =
  /^(?:ba|z|k|c|tc|da|a)?sh$|^busybox$|^python[\d.]*$|^perl[\d.]*$|^ruby[\d.]*$|^php[\d.]*$|^node$|^lua[\d.]*$|^awk$|^gawk$|^mawk$|^env$|^find$|^vim?$|^nano$|^less$|^more$|^man$|^nmap$|^tar$|^zip$|^socat$|^tcpdump$/;

/**
 * SUID binaries a standard Linux install ships.
 *
 * Not a security judgement — several of these have known abuse paths. It is the answer to "does this
 * host have a SUID binary the distribution did not put there", which is the question the artifact is
 * collected to answer. An environment that ships more supplies them as a baseline.
 */
export const SUID_BASELINE: readonly string[] = [
  "/bin/fusermount",
  "/bin/mount",
  "/bin/ping",
  "/bin/ping6",
  "/bin/su",
  "/bin/umount",
  "/sbin/mount.nfs",
  "/sbin/pam_timestamp_check",
  "/sbin/pccardctl",
  "/sbin/unix_chkpwd",
  "/usr/bin/at",
  "/usr/bin/chage",
  "/usr/bin/chfn",
  "/usr/bin/chsh",
  "/usr/bin/crontab",
  "/usr/bin/expiry",
  "/usr/bin/fusermount",
  "/usr/bin/fusermount3",
  "/usr/bin/gpasswd",
  "/usr/bin/ksu",
  "/usr/bin/mount",
  "/usr/bin/newgidmap",
  "/usr/bin/newgrp",
  "/usr/bin/newuidmap",
  "/usr/bin/passwd",
  "/usr/bin/pkexec",
  "/usr/bin/sg",
  "/usr/bin/su",
  "/usr/bin/sudo",
  "/usr/bin/umount",
  "/usr/bin/wall",
  "/usr/bin/write",
  "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
  "/usr/lib/eject/dmcrypt-get-device",
  "/usr/lib/openssh/ssh-keysign",
  "/usr/lib/polkit-1/polkit-agent-helper-1",
  "/usr/lib/policykit-1/polkit-agent-helper-1",
  "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
  "/usr/libexec/openssh/ssh-keysign",
  "/usr/libexec/polkit-agent-helper-1",
  "/usr/sbin/exim4",
  "/usr/sbin/mount.nfs",
  "/usr/sbin/pppd",
  "/usr/sbin/unix_chkpwd",
  "/usr/sbin/userhelper",
  "/usr/sbin/usernetctl",
];

const SUID_BASELINE_SET = new Set(SUID_BASELINE);

// Commands a shadowing binary earlier in PATH would intercept.
const SHADOWABLE = new Set([
  "ls",
  "ps",
  "id",
  "sudo",
  "su",
  "ssh",
  "scp",
  "cat",
  "grep",
  "netstat",
  "ss",
  "top",
  "find",
  "curl",
  "wget",
  "systemctl",
  "journalctl",
  "passwd",
  "kill",
  "df",
  "du",
  "who",
  "w",
  "last",
]);

// ─────────────────────────── shared helpers ───────────────────────────

function clip(s: string): string {
  const t = (s ?? "").replace(/\s+/g, " ").trim();
  return t.length > EVIDENCE_MAX ? `${t.slice(0, EVIDENCE_MAX)}…` : t;
}

function inIncident(file: CollectedFile, ctx: LinuxContext): boolean {
  if (!file.mtime || !ctx.incident) return false;
  const t = Date.parse(file.mtime);
  const a = Date.parse(ctx.incident.start);
  const b = Date.parse(ctx.incident.end);
  if (!Number.isFinite(t) || !Number.isFinite(a) || !Number.isFinite(b)) return false;
  return t >= Math.min(a, b) && t <= Math.max(a, b);
}

/**
 * Build a signal, applying the incident-time rule.
 *
 * Medium is raised to High when the collection PROVES the file changed inside the window. High is
 * never raised further: an incident-time change makes a finding more urgent, not more certain.
 */
function signal(
  file: CollectedFile,
  ctx: LinuxContext,
  s: { severity: Severity; mitre: string[]; reason: string; evidence: string; line: number; target?: string },
): LinuxSignal {
  const changed = inIncident(file, ctx);
  const timeUnknown = !file.mtime;
  let severity = s.severity;
  let reason = s.reason;
  if (changed && RANK[severity] === RANK.Medium) severity = "High";
  if (changed) reason += ` The file was modified inside the incident window (${file.mtime}).`;
  else if (timeUnknown) {
    reason +=
      " The collection recorded no modification time for this file, so whether it changed during the incident could not be checked.";
  }
  return {
    artifact: file.path,
    kind: file.kind,
    severity,
    mitre: s.mitre,
    reason,
    evidence: clip(s.evidence),
    line: s.line,
    timeUnknown,
    ...(s.target ? { target: s.target } : {}),
  };
}

function baselinePaths(ctx: LinuxContext): Set<string> {
  return new Set(ctx.baseline?.paths ?? []);
}

/** The wording every payload finding shares, so the reason names the property, not the artifact. */
function payloadReason(j: PayloadJudgement, what: string): string | null {
  if (j.reverseShell) return `${what} opens an interactive connection back to a remote host.`;
  if (j.fetchExec)
    return `${what} downloads code and executes it in the same command, so the payload never has to exist on disk before it runs.`;
  if (j.encoded)
    return `${what} decodes its own payload before running it, which keeps the command text out of the logs.`;
  if (j.transient)
    return `${what} runs from a world-writable directory that is cleared on reboot, which is not where installed software lives.`;
  if (j.hidden) return `${what} runs from a hidden directory.`;
  return null;
}

function payloadSeverity(j: PayloadJudgement): Severity {
  if (j.reverseShell || j.fetchExec || j.encoded || j.transient) return "High";
  return "Medium"; // hidden only
}

function payloadTechniques(j: PayloadJudgement, base: string[]): string[] {
  const out = [...base];
  if (j.fetchExec || j.encoded || j.reverseShell) out.push("T1059.004");
  if (j.fetchExec) out.push("T1105");
  return [...new Set(out)];
}

// ─────────────────────────── SSH authorized keys ───────────────────────────

/** The account an authorized_keys path belongs to. */
export function keyAccount(path: string): string {
  if (/^\/root\//.test(path)) return "root";
  const m = /^\/home\/([^/]+)\//.exec(path);
  if (m) return m[1];
  const m2 = /^\/(?:var\/lib|opt|srv)\/([^/]+)\//.exec(path);
  return m2 ? m2[1] : "";
}

export function gradeAuthorizedKeys(file: CollectedFile, ctx: LinuxContext): LinuxSignal[] {
  const known = new Set(ctx.baseline?.keys ?? []);
  const account = keyAccount(file.path);
  const out: LinuxSignal[] = [];

  for (const key of parseAuthorizedKeys(file.content)) {
    if (known.has(key.blob)) continue;
    const evidence = `${key.options ? `${key.options} ` : ""}${key.type} ${key.blob.slice(0, 24)}… ${key.comment}`;

    // A forced command is normally a RESTRICTION — rsync, borg, git-shell. It is only a finding when
    // the thing it forces is a shell or a payload, which turns the restriction into the backdoor.
    const forced = keyOption(key.options, "command");
    if (forced) {
      const j = judgePayload(forced);
      const reason = payloadReason(j, "A forced command on this authorized key");
      const isShell = /^(?:\/[\w./-]*\/)?(?:ba|z|k|da|a)?sh\b/.test(forced.trim());
      if (reason || isShell) {
        out.push(
          signal(file, ctx, {
            severity: reason ? payloadSeverity(j) : "High",
            mitre: payloadTechniques(j, ["T1098.004"]),
            reason:
              (reason ??
                `A forced command on this authorized key runs a shell, so the restriction grants interactive access instead of limiting it.`) +
              ` Account: ${account || "unknown"}. Forced command: ${clip(forced)}.`,
            evidence,
            line: key.line,
          }),
        );
        continue;
      }
    }

    // Otherwise the key itself is only remarkable if the collection can show it appeared during the
    // incident. A host has authorized keys; that is what the file is for.
    if (inIncident(file, ctx)) {
      out.push(
        signal(file, ctx, {
          severity: "Medium",
          mitre: ["T1098.004"],
          reason: `An SSH key authorising ${account || "this account"} is present in a file modified during the incident window. The file's timestamp covers every key in it, so this key is not necessarily the one that was added — compare against a known-good key list.`,
          evidence,
          line: key.line,
        }),
      );
    }
  }
  return out;
}

/**
 * The same key material authorising two accounts.
 *
 * A shared administrative key is a real and legitimate pattern, so this is Medium — the finding is
 * that the accounts are linked, and the analyst decides whether that link is expected. It becomes
 * High only when one of the accounts is root, because that is the shape of "a user key was copied
 * into root" rather than "one admin key was deployed everywhere".
 */
export function crossAccountKeyReuse(files: readonly CollectedFile[], ctx: LinuxContext): LinuxSignal[] {
  const known = new Set(ctx.baseline?.keys ?? []);
  const byBlob = new Map<string, { account: string; file: CollectedFile; line: number; comment: string }[]>();

  for (const file of files) {
    if (file.kind !== "authorized_keys") continue;
    const account = keyAccount(file.path);
    if (!account) continue;
    for (const key of parseAuthorizedKeys(file.content)) {
      if (known.has(key.blob)) continue;
      const list = byBlob.get(key.blob) ?? [];
      // One account, one entry: the same file listing a key twice is not two accounts.
      if (list.some((e) => e.account === account)) continue;
      list.push({ account, file, line: key.line, comment: key.comment });
      byBlob.set(key.blob, list);
    }
  }

  const out: LinuxSignal[] = [];
  for (const [blob, uses] of byBlob) {
    if (uses.length < 2) continue;
    const accounts = uses.map((u) => u.account);
    const hasRoot = accounts.includes("root");
    const first = uses[0];
    out.push(
      signal(first.file, ctx, {
        severity: hasRoot ? "High" : "Medium",
        mitre: ["T1098.004"],
        reason:
          `The same SSH key authorises ${accounts.length} accounts: ${accounts.join(", ")}. ` +
          (hasRoot
            ? "One of them is root, so whoever holds this key has both a user account and full control of the host. "
            : "") +
          "A shared administrative key is a legitimate pattern — confirm whether these accounts are meant to share one.",
        evidence: `${blob.slice(0, 24)}… ${first.comment}`,
        line: first.line,
      }),
    );
  }
  return out;
}

// ─────────────────────────── cron ───────────────────────────

export function gradeCron(file: CollectedFile, ctx: LinuxContext): LinuxSignal[] {
  const { entries, env } = parseCrontab(file.content, file.path);
  const allowed = baselinePaths(ctx);
  const out: LinuxSignal[] = [];

  for (const entry of entries) {
    const j = judgePayload(entry.command);
    if (allowed.has(j.target)) continue;
    const who = entry.user || "the file's owner";
    let reason = payloadReason(j, `A scheduled job running as ${who}`);
    let severity = payloadSeverity(j);
    const mitre = payloadTechniques(j, ["T1053.003"]);

    // Root running something a non-root account can rewrite: the job is the privilege escalation,
    // whatever the payload does today.
    if (entry.user.toLowerCase() === "root" && j.homeOwned && j.homeOwned !== "root") {
      reason = `A scheduled job runs as root but executes a file inside ${j.homeOwned}'s home directory, so that account can change what root runs.`;
      severity = "High";
    }
    if (!reason) continue;
    out.push(
      signal(file, ctx, {
        severity,
        mitre,
        reason: `${reason} Schedule: ${entry.schedule}.`,
        evidence: entry.command,
        line: entry.line,
        target: j.target,
      }),
    );
  }

  // A crontab sets its own PATH, and cron's default PATH is short — a writable entry here decides
  // what every job in the file resolves to.
  for (const e of env) {
    if (e.name.toUpperCase() !== "PATH") continue;
    const bad = gradePathEntries(splitPathValue(e.value));
    if (!bad) continue;
    out.push(
      signal(file, ctx, {
        severity: bad.severity,
        mitre: ["T1574.007"],
        reason: `${bad.reason} Every job in this crontab resolves its commands through it.`,
        evidence: `PATH=${e.value}`,
        line: e.line,
      }),
    );
  }
  return out;
}

// ─────────────────────────── systemd ───────────────────────────

export function gradeUnit(file: CollectedFile, ctx: LinuxContext): LinuxSignal[] {
  const unit = parseUnit(file.content);
  const allowed = baselinePaths(ctx);
  const out: LinuxSignal[] = [];
  const commands = [...unit.execStartPre, ...unit.execStart];

  for (const raw of commands) {
    const cmd = stripExecPrefix(raw);
    const j = judgePayload(cmd);
    if (allowed.has(j.target)) continue;
    const runsAs = unit.user ? unit.user : "root";
    let reason = payloadReason(j, `A systemd service running as ${runsAs}`);
    let severity = payloadSeverity(j);

    if (!unit.user && j.homeOwned && j.homeOwned !== "root" && !file.path.includes("/.config/")) {
      reason = `A system-wide systemd service runs as root but executes a file inside ${j.homeOwned}'s home directory, so that account can change what root runs.`;
      severity = "High";
    }
    if (!reason) continue;
    if (/^always$/i.test(unit.restart))
      reason += " The unit restarts automatically, so killing the process does not remove it.";
    if (unit.wantedBy) reason += ` It starts at ${unit.wantedBy}.`;
    out.push(
      signal(file, ctx, {
        severity,
        mitre: payloadTechniques(j, ["T1543.002"]),
        reason,
        evidence: raw,
        line: 1,
        target: j.target,
      }),
    );
  }
  return out;
}

// ─────────────────────────── shell initialization ───────────────────────────

const HISTORY_OFF_RE =
  /\bunset\s+HISTFILE\b|\bHISTFILE\s*=\s*\/dev\/null\b|\bHISTSIZE\s*=\s*0\b|\bHISTFILESIZE\s*=\s*0\b|\bset\s+\+o\s+history\b|\bhistory\s+-c\b/i;

export function gradeShellInit(file: CollectedFile, ctx: LinuxContext): LinuxSignal[] {
  const allowed = baselinePaths(ctx);
  const out: LinuxSignal[] = [];

  for (const { text, line } of shellInitLines(file.content)) {
    // PATH first: an assignment is not a command to judge as a payload.
    const pathAssign = /^\s*(?:export\s+)?PATH\s*=\s*(.*)$/.exec(text);
    if (pathAssign) {
      const bad = gradePathEntries(splitPathValue(expandPathSelf(pathAssign[1])));
      if (bad)
        out.push(
          signal(file, ctx, {
            severity: bad.severity,
            mitre: ["T1574.007"],
            reason: `${bad.reason} Every command this shell runs resolves through it.`,
            evidence: text,
            line,
          }),
        );
      continue;
    }

    if (HISTORY_OFF_RE.test(text)) {
      out.push(
        signal(file, ctx, {
          severity: "Medium",
          mitre: ["T1070.003"],
          reason:
            "This shell profile turns off command history for every session the account opens, so shell history will not record what was run.",
          evidence: text,
          line,
        }),
      );
      continue;
    }

    const alias = /^\s*alias\s+([A-Za-z_][\w.-]*)\s*=\s*(.+)$/.exec(text);
    if (alias && SHADOWABLE.has(alias[1].toLowerCase())) {
      out.push(
        signal(file, ctx, {
          severity: "Medium",
          mitre: ["T1036"],
          reason: `This shell profile redefines the common command "${alias[1]}", so what the account sees when it runs that command is not what the command does.`,
          evidence: text,
          line,
        }),
      );
      continue;
    }

    const j = judgePayload(text);
    if (allowed.has(j.target)) continue;
    const reason = payloadReason(j, "A line in this shell profile");
    if (!reason) continue;
    out.push(
      signal(file, ctx, {
        severity: payloadSeverity(j),
        mitre: payloadTechniques(j, ["T1546.004"]),
        reason: `${reason} It runs every time the account opens a shell.`,
        evidence: text,
        line,
        target: j.target,
      }),
    );
  }
  return out;
}

/**
 * Replace a `$PATH` / `${PATH}` self-reference with a sentinel entry.
 *
 * Deleting the reference instead — the first version — turned `PATH=$PATH:/home/alice/bin`, which is
 * the single most common line in any shell profile, into `:/home/alice/bin`. That leading colon is
 * an EMPTY entry, and an empty entry means the current working directory, so every ordinary profile
 * on every host produced a High "PATH resolves out of the current directory" finding. The sentinel
 * keeps the colon a separator and stands in for the inherited value, which begins with the system
 * directories — so anything appended after it is correctly graded as "after the system ones".
 */
export const PATH_INHERITED = "\uE000PATH";

function expandPathSelf(value: string): string {
  return value.replace(/\$\{?PATH\}?/g, PATH_INHERITED);
}

/** Render a parsed PATH for display, putting the self-reference back the way it was written. */
function showPath(entries: readonly string[]): string {
  return entries.map((e) => (e === PATH_INHERITED ? "$PATH" : e)).join(":");
}

/** A directory the system installs commands into — or the inherited PATH, which starts with them. */
function isSystemDir(entry: string): boolean {
  if (entry === PATH_INHERITED) return true;
  return STANDARD_BIN_RE.test(`${entry.replace(/\/$/, "")}/`);
}

// ─────────────────────────── PATH ───────────────────────────

/**
 * Judge a PATH value.
 *
 * An EMPTY entry and `.` are the same thing to the shell: resolve commands out of the working
 * directory. That is the classic finding and it is unambiguous. A writable directory placed before
 * the system ones is Medium — build tooling does it legitimately, and the analyst decides.
 */
export function gradePathEntries(entries: readonly string[]): { severity: Severity; reason: string } | null {
  const cwdEntry = entries.some((e) => e === "" || e === "." || e === "./");
  if (cwdEntry) {
    return {
      severity: "High",
      reason:
        "PATH resolves commands out of the current working directory, so moving into a directory an attacker can write decides what a typed command runs.",
    };
  }
  const firstSystem = entries.findIndex(isSystemDir);
  const before = firstSystem < 0 ? entries : entries.slice(0, firstSystem);
  const risky = before.find((e) => TRANSIENT_RE.test(e) || /^\/home\//.test(e) || hiddenComponent(e));
  if (risky) {
    return {
      severity: "Medium",
      reason: `PATH searches ${risky} before the system directories, so a file placed there is what runs when a system command name is typed.`,
    };
  }
  return null;
}

export function gradeEnv(file: CollectedFile, ctx: LinuxContext): LinuxSignal[] {
  const entries = parsePathEntries(file.content);
  if (!entries) return [];
  const bad = gradePathEntries(entries);
  if (!bad) return [];
  return [
    signal(file, ctx, {
      severity: bad.severity,
      mitre: ["T1574.007"],
      reason: bad.reason,
      evidence: `PATH=${entries.join(":")}`,
      line: 1,
    }),
  ];
}

/**
 * Commands a directory earlier in PATH would intercept.
 *
 * Only answerable when the collection also lists files in that directory. With no listing this
 * returns nothing rather than guessing — the absence of a listing is not the absence of a shadow.
 */
export function shadowedCommands(pathEntries: readonly string[], knownFiles: readonly string[]): string[] {
  const firstSystem = pathEntries.findIndex(isSystemDir);
  const early = (firstSystem < 0 ? pathEntries : pathEntries.slice(0, firstSystem)).map((e) =>
    e.replace(/\/$/, ""),
  );
  const out: string[] = [];
  for (const f of knownFiles) {
    const dir = f.slice(0, f.lastIndexOf("/"));
    const name = f.slice(f.lastIndexOf("/") + 1).toLowerCase();
    if (early.includes(dir) && SHADOWABLE.has(name)) out.push(f);
  }
  return [...new Set(out)];
}

// ─────────────────────────── SUID ───────────────────────────

export function gradeSuid(file: CollectedFile, ctx: LinuxContext): LinuxSignal[] {
  const allowed = new Set([...SUID_BASELINE_SET, ...(ctx.baseline?.suid ?? [])]);
  const out: LinuxSignal[] = [];

  for (const entry of parseSuidListing(file.content)) {
    // The listing said this file is not setuid. Believe it.
    if (entry.setuid === false) continue;
    if (allowed.has(entry.path)) continue;

    const name = entry.path.slice(entry.path.lastIndexOf("/") + 1).toLowerCase();
    let severity: Severity;
    let reason: string;

    if (INTERPRETER_RE.test(name)) {
      severity = "High";
      reason = `${entry.path} is setuid and is an interpreter, so any account that runs it gets a shell with the file owner's privileges. No standard install ships this setuid.`;
    } else if (TRANSIENT_RE.test(entry.path) || /^\/home\//.test(entry.path)) {
      severity = "High";
      reason = `${entry.path} is a setuid binary in a directory any account can write. A package manager does not install there.`;
    } else if (!STANDARD_BIN_RE.test(entry.path)) {
      severity = "High";
      reason = `${entry.path} is a setuid binary outside every directory a distribution installs into.`;
    } else {
      severity = "Medium";
      reason = `${entry.path} is setuid and is not part of the standard install set. Third-party packages do add setuid binaries — confirm it against this environment's package list before treating it as an implant.`;
    }
    if (entry.owner && entry.owner !== "root") reason += ` It is owned by ${entry.owner}, not root.`;

    out.push(
      signal(file, ctx, {
        severity,
        mitre: ["T1548.001"],
        reason,
        evidence: file.content.split(/\r?\n/)[entry.line - 1] ?? entry.path,
        line: entry.line,
        target: entry.path,
      }),
    );
  }
  return out;
}

// ─────────────────────────── the collection pass ───────────────────────────

/** Cap on signals returned from one collection, so a pathological file cannot flood the timeline. */
export const MAX_SIGNALS = 300;

export function analyzeLinuxCollection(
  files: readonly CollectedFile[],
  ctx: LinuxContext = {},
): LinuxSignal[] {
  const out: LinuxSignal[] = [];
  const push = (list: LinuxSignal[]) => {
    for (const s of list) if (out.length < MAX_SIGNALS) out.push(s);
  };

  for (const file of files) {
    switch (file.kind) {
      case "authorized_keys":
        push(gradeAuthorizedKeys(file, ctx));
        break;
      case "cron":
        push(gradeCron(file, ctx));
        break;
      case "systemd":
        push(gradeUnit(file, ctx));
        break;
      case "shellrc":
        push(gradeShellInit(file, ctx));
        break;
      case "suid":
        push(gradeSuid(file, ctx));
        break;
      case "env":
        push(gradeEnv(file, ctx));
        break;
      default:
        break;
    }
  }
  push(crossAccountKeyReuse(files, ctx));

  // Suspicious command resolution needs both halves: a PATH and a listing of what is in it.
  const listing = files
    .filter((f) => f.kind === "suid")
    .flatMap((f) => parseSuidListing(f.content).map((e) => e.path));
  for (const file of files) {
    const entries =
      file.kind === "env"
        ? parsePathEntries(file.content)
        : file.kind === "shellrc"
          ? pathFromShellInit(file)
          : null;
    if (!entries) continue;
    const shadowed = shadowedCommands(entries, listing);
    if (shadowed.length === 0) continue;
    push([
      signal(file, ctx, {
        severity: "High",
        mitre: ["T1574.007"],
        reason: `PATH searches a directory that contains ${shadowed.join(", ")} before the system directories, so typing that command name runs the file found there instead of the system one.`,
        evidence: `PATH=${showPath(entries)}`,
        line: 1,
      }),
    ]);
  }
  return out;
}

function pathFromShellInit(file: CollectedFile): string[] | null {
  for (const { text } of shellInitLines(file.content)) {
    const m = /^\s*(?:export\s+)?PATH\s*=\s*(.*)$/.exec(text);
    if (m) return splitPathValue(expandPathSelf(m[1]));
  }
  return null;
}
