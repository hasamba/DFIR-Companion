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
  parseCrontab,
  parsePathEntries,
  parseSuidListing,
  parseUnit,
  shellInitLines,
  splitPathValue,
  stripExecPrefix,
  type CollectedFile,
} from "./linuxPersistence.js";
export { crossAccountKeyReuse, gradeAuthorizedKeys, isNeuteredKey, keyAccount } from "./linuxSshKeys.js";
export { SUID_BASELINE, type LinuxBaseline, type LinuxContext, type LinuxSignal } from "./linuxSignal.js";

import { crossAccountKeyReuse, gradeAuthorizedKeys } from "./linuxSshKeys.js";
import {
  baselinePaths,
  hostPathInImage,
  IMAGE_ROOT_RE,
  INTERPRETER_RE,
  SHADOWABLE,
  payloadReason,
  payloadSeverity,
  payloadTechniques,
  signal,
  SUID_BASELINE_SET,
  type LinuxContext,
  type LinuxSignal,
} from "./linuxSignal.js";
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
    const bad = gradePathEntries(splitPathValue(expandPathSelf(e.value)));
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
  // Every key that runs something, not just ExecStart. ExecStopPost runs on failure, which for a
  // unit that fails on purpose is a reliable trigger, and Environment= carries LD_PRELOAD.
  // An Environment= value is `KEY=value`. The VALUE is the payload — commandTarget skips a leading
  // assignment, so passing the whole thing left no target and the finding graded a preload Medium.
  const commands = [
    ...unit.execStartPre,
    ...unit.execStart,
    ...unit.execOther,
    ...unit.environment.map((e) => e.replace(/^[A-Za-z_][A-Za-z0-9_]*=/, "")),
  ];

  for (const raw of commands) {
    const cmd = stripExecPrefix(raw);
    const j = judgePayload(cmd);
    if (allowed.has(j.target)) continue;
    const runsAs = unit.user ? unit.user : "root";
    let reason = payloadReason(j, `A systemd service running as ${runsAs}`);
    let severity = payloadSeverity(j);

    // A user unit runs as that user, never as root. They live under ~/.config/systemd/user AND
    // ~/.local/share/systemd/user — testing only the first graded a syncthing user unit as a
    // system-wide root service.
    const userUnit = /\/systemd\/user\//.test(file.path);
    if (!unit.user && j.homeOwned && j.homeOwned !== "root" && !userUnit) {
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

/**
 * Grade an alias.
 *
 * THE NAME IS NOT THE SIGNAL. Ubuntu's own /etc/skel/.bashrc ships `alias ls='ls --color=auto'` and
 * `alias grep='grep --color=auto'` uncommented, so a rule that fired on "this redefines a common
 * command" produced two Medium timeline events for every home directory on every Debian-family
 * host — raised to High whenever the file's mtime fell inside the incident window. A developer Mac
 * adds `alias cat='bat'`, `alias top='htop'`, `alias du='dust'`. None of that is tradecraft.
 *
 * What IS tradecraft is an alias whose body does something the command does not: it runs a payload
 * at every prompt, or it removes lines from the output of an enumeration command so the account
 * cannot see what is there. Those two are the rule.
 */
export function gradeAlias(
  name: string,
  body: string,
): { severity: Severity; mitre: string[]; reason: string } | null {
  const target = body.replace(/^['"]|['"]$/g, "").trim();
  const j = judgePayload(target);
  if (j.transient || j.fetchExec || j.reverseShell || j.encoded) {
    return {
      severity: "High",
      mitre: payloadTechniques(j, ["T1546.004"]),
      reason:
        `The alias "${name}" runs a payload rather than the command it is named after, so it executes whenever the account types that name. ` +
        `${payloadReason(j, "The alias body") ?? ""}`.trim(),
    };
  }
  // Output filtering on an enumeration command: the account is shown a shortened truth.
  const enumerates =
    /^(?:ls|ps|netstat|ss|who|w|last|find|df|du|top|lsof|ip|ifconfig|dmesg|journalctl)$/i.test(name);
  const filters = /\|\s*(?:grep|egrep|sed|awk)\b[^|]*(?:-v\b|\/d\b|!~)/i.test(target);
  if (enumerates && filters) {
    return {
      severity: "Medium",
      mitre: ["T1564"],
      reason: `The alias "${name}" pipes the command's output through a filter that REMOVES lines, so anyone using this account sees a shortened result and has no sign that anything was hidden.`,
    };
  }
  return null;
}

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
    if (alias) {
      const verdict = gradeAlias(alias[1], alias[2]);
      if (verdict) {
        out.push(
          signal(file, ctx, {
            severity: verdict.severity,
            mitre: verdict.mitre,
            reason: verdict.reason,
            evidence: text,
            line,
          }),
        );
      }
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
  // ~/.local/bin is created by `pip install --user` and prepended by Ubuntu's stock .profile, and
  // ~/.cargo/bin and ~/.npm-global/bin are the same story. A home directory on the PATH is only
  // remarkable when it is not one of those.
  const ORDINARY_USER_BIN = /\/\.(?:local|cargo|rustup|nvm|npm-global|bun|deno|pyenv|rbenv|volta)\//;
  const risky = before.find(
    (e) =>
      TRANSIENT_RE.test(e) ||
      (!ORDINARY_USER_BIN.test(`${e}/`) && (/^\/home\//.test(e) || hiddenComponent(e))),
  );
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
  // expandPathSelf, like the shell-profile grader. Skipping it here meant `PATH="$PATH:/home/x"` in
  // /etc/environment read as "searches /home/x BEFORE the system directories" — the opposite of the
  // evidence, on a Medium finding. It is the same bug the shell grader already had once.
  const expanded = entries.map((e) => (e === "$PATH" || e === "${PATH}" ? PATH_INHERITED : e));
  const bad = gradePathEntries(expanded);
  if (!bad) return [];
  return [
    signal(file, ctx, {
      severity: bad.severity,
      mitre: ["T1574.007"],
      reason: bad.reason,
      evidence: `PATH=${showPath(expanded)}`,
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

    // A binary inside a snap mount or a container layer is a packaged copy, not an implant. Judge
    // it at the path it would have on the host; report it only if THAT is not standard.
    if (IMAGE_ROOT_RE.test(entry.path)) {
      const asHost = hostPathInImage(entry.path);
      // No bin/lib segment inside the image means this is NOT a packaged binary — a setuid file
      // under /snap/core22/1122/tmp is an implant wherever it sits. Fall through and grade it.
      if (asHost && (allowed.has(asHost) || (!INTERPRETER_RE.test(name) && STANDARD_BIN_RE.test(asHost))))
        continue;
    }

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

  // THE CROSS-FILE FINDINGS GO FIRST, on purpose. They used to run after the per-file loop, so a
  // host with hundreds of SUID rows filled the cap and the one shared root key — the finding that
  // actually matters — was silently evicted. The findings that need the whole collection to exist
  // at all are the ones least able to survive being dropped.
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
  return out;
}

function pathFromShellInit(file: CollectedFile): string[] | null {
  for (const { text } of shellInitLines(file.content)) {
    const m = /^\s*(?:export\s+)?PATH\s*=\s*(.*)$/.exec(text);
    if (m) return splitPathValue(expandPathSelf(m[1]));
  }
  return null;
}
