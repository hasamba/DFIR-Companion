// What a launchd plist establishes about its CONTEXT and its TARGET, and the two collection facts
// that can say more (#933 item 8). Grading is in macosPersistRules.ts; this module only reads.
//
// A plist is a configuration. It names a label, a target and triggers, and — from where it sits —
// which launchd domain would load it and as whom. It does not establish that launchd loaded it,
// that the target exists, or that anything ran. The words here are built so a finding can say
// exactly that, and no more:
//
//   • UserName is honoured only in the system domain (LaunchDaemons). On an agent launchd ignores
//     it, so a user agent that says `UserName root` is configured for the logged-in user.
//   • A LoginWindow agent (LimitLoadToSessionType) is configured for root, before anyone logs in.
//   • A plist outside the launchd directories is loaded by nothing unless something loads it.
//   • A bare ProgramArguments[0] is looked up by launchd in ITS OWN standard path
//     (_PATH_STDPATH). The PATH the plist sets reaches the child; it does not choose the file.
//   • launchd does not expand `~`. A relative path resolves against WorkingDirectory, else `/`.
//
// Two header facts a collection can add under the plist (absent = NOT COLLECTED, never "no"):
//
//   # target: path=/usr/local/bin/x owner=alice mode=0755 [group=staff] [mtime=<ISO>]
//   # target: path=/usr/local/bin/x missing
//   # launchctl: system 412 0 com.vendor.helper        (`launchctl list` line, domain first)
//   # launchctl: gui/501 not loaded
//
// `# target:` binds only to the job's resolved ABSOLUTE target, byte for byte; a fact recorded for
// any other path is shown and applied to nothing. `# launchctl:` needs the domain the collector
// queried — labels are unique only within a domain — and the domain must be one that loads this
// plist's scope. Both are the collector's assertions and are worded as such.

import type { LaunchJob, LaunchScope } from "./macosPersistence.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";

/** launchd's own search path for a bare ProgramArguments[0] (_PATH_STDPATH). */
export const LAUNCHD_STD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";

const SHOWN_MAX = 120;

/** A collected or plist-written string, safe to place in prose: no tags, no hash runs, bounded. */
export function shown(value: string): string {
  const t = breakHashRuns(showToken(value ?? ""));
  return t.length > SHOWN_MAX ? `${t.slice(0, SHOWN_MAX)}…` : t;
}

// ─────────────────────────── execution context ───────────────────────────

export interface LaunchContext {
  /** Who the plist is configured to run as, in words: "root at boot", "that user at login", … */
  who: string;
  /** The plist sets UserName on an agent, where launchd ignores it. */
  userNameIgnored: boolean;
  /** launchd reads this location by itself. False for a plist anywhere else. */
  autoLoaded: boolean;
  /** Configured for root — what the writable-target rules need to know. */
  root: boolean;
  /** Sentences the finding appends, when the context has something to say. */
  note: string;
}

const SESSION_TYPES = new Set(["Aqua", "Background", "LoginWindow", "StandardIO", "System"]);

function agentWho(job: LaunchJob, scope: LaunchScope): { who: string; root: boolean } {
  const each = scope === "user-agent" ? "that user at login" : "each user at login";
  const st = job.sessionType;
  if (!st || st === "Aqua") return { who: each, root: false };
  if (st === "LoginWindow") return { who: "root at the login window, before anyone logs in", root: true };
  if (st === "Background") return { who: `${each} (Background session: no GUI needed)`, root: false };
  if (SESSION_TYPES.has(st)) return { who: `${each} (${st} session)`, root: false };
  return { who: `${each}, session type ${shown(st)}, which is not one launchd documents`, root: false };
}

/** Who this plist is configured to run as, from where it sits and the keys launchd honours there. */
export function configuredContext(job: LaunchJob, scope: LaunchScope): LaunchContext {
  const daemon = scope === "system-daemon" || scope === "apple-daemon";
  if (daemon) {
    const user = job.userName;
    return {
      who: user ? `${shown(user)} at boot` : "root at boot",
      userNameIgnored: false,
      autoLoaded: true,
      root: !user || user === "root",
      note: "",
    };
  }
  if (scope === "elsewhere") {
    return {
      who: "an unknown context",
      userNameIgnored: false,
      autoLoaded: false,
      root: false,
      note: "The plist sits in a location launchd does not read; it runs only if something loads it explicitly (launchctl load, a login hook, a script). The plist alone does not establish that it was ever loaded.",
    };
  }
  const { who, root } = agentWho(job, scope);
  const ignored = Boolean(job.userName);
  return {
    who,
    userNameIgnored: ignored,
    autoLoaded: true,
    root,
    note: ignored
      ? `The plist sets UserName ${shown(job.userName)}, which launchd ignores for an agent; the job is configured for the user whose session loads it.`
      : "",
  };
}

// ─────────────────────────── target resolution ───────────────────────────

export type TargetForm = "absolute" | "bare" | "tilde" | "relative" | "program-not-absolute";

export interface ResolvedTarget {
  form: TargetForm;
  /** The absolute path the plist names, or "" when it names none (bare, tilde, invalid Program). */
  target: string;
  /** What the finding says about the target when it is not simply an absolute path. */
  note: string;
}

/** What the plist itself names as the thing to execute, read the way launchd would. */
export function resolveTarget(job: LaunchJob): ResolvedTarget {
  const p = job.program;
  const argv0 = job.argv0 ? ` [argv0: ${shown(job.argv0)}]` : "";
  if (p.startsWith("/")) return { form: "absolute", target: p, note: argv0.trim() };
  if (job.programSet) {
    return {
      form: "program-not-absolute",
      target: "",
      note: `Program is not absolute as launchd requires (${shown(p)}); as written this job does not launch.${argv0}`,
    };
  }
  if (p.startsWith("~")) {
    return {
      form: "tilde",
      target: "",
      note: `The program is written as ${shown(p)}; launchd does not expand ~, so the literal path is what it would try to launch.`,
    };
  }
  if (!p.includes("/")) {
    return {
      form: "bare",
      target: "",
      note: `The program is a bare name (${shown(p)}); the plist does not name the file — launchd looks it up in its standard path (${LAUNCHD_STD_PATH}), not in any PATH the plist sets.`,
    };
  }
  const base = job.workingDirectory.startsWith("/") ? job.workingDirectory.replace(/\/+$/, "") : "";
  const joined = `${base}/${p.replace(/^\.\//, "")}`;
  return {
    form: "relative",
    target: joined,
    note: `The program is a relative path (${shown(p)}), read against ${base ? `WorkingDirectory ${shown(base)}` : "/ (no WorkingDirectory is set)"}: ${shown(joined)}.`,
  };
}

// ─────────────────────────── # target: ───────────────────────────

export interface TargetFacts {
  path: string;
  missing: boolean;
  owner?: string;
  group?: string;
  /** Permission bits, from a 3–4 digit octal mode. */
  mode?: number;
  /** ISO, normalised. */
  mtime?: string;
  /** Pairs the grammar rejected, verbatim — shown, never applied. */
  unreadable: string[];
}

/** Read a `# target:` value. Null when it names no path — then it binds to nothing. */
export function readTargetFacts(value: string): TargetFacts | null {
  const tokens = (value ?? "").trim().split(/\s+/).filter(Boolean);
  const out: TargetFacts = { path: "", missing: false, unreadable: [] };
  for (const tok of tokens) {
    if (tok === "missing") {
      out.missing = true;
      continue;
    }
    const eq = tok.indexOf("=");
    const key = eq > 0 ? tok.slice(0, eq) : "";
    const val = eq > 0 ? tok.slice(eq + 1) : "";
    if (key === "path" && val.startsWith("/")) out.path = val;
    else if (key === "owner" && val) out.owner = val;
    else if (key === "group" && val) out.group = val;
    else if (key === "mode" && /^[0-7]{3,4}$/.test(val)) out.mode = parseInt(val, 8);
    else if (key === "mtime" && isoTime(val)) out.mtime = new Date(Date.parse(val)).toISOString();
    else out.unreadable.push(tok);
  }
  return out.path ? out : null;
}

/** An ISO-8601 date-time with a zone, and a real calendar date (Date.parse rolls 02-30 over). */
function isoTime(v: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})$/.exec(v);
  if (!m) return false;
  const t = Date.parse(v);
  if (!Number.isFinite(t)) return false;
  const d = new Date(t);
  const [y, mo, da] = [Number(m[1]), Number(m[2]), Number(m[3])];
  return d.getUTCFullYear() === y && d.getUTCMonth() + 1 === mo && d.getUTCDate() === da;
}

// ─────────────────────────── # launchctl: ───────────────────────────

export interface LaunchctlFact {
  /** The domain target the collector queried: system, user/<uid>, gui/<uid>, login/<asid>. */
  domain: string;
  loaded: boolean;
  pid?: number;
  /** launchctl's last-status column: 0 also for a job that has not run; negative is a signal. */
  status?: number;
  label?: string;
}

const DOMAIN_RE = /^(?:system|(?:user|gui|login)\/\d+)$/;

/** Read a `# launchctl:` value. Null when it is not a domain-first `launchctl list` line. */
export function readLaunchctl(value: string): LaunchctlFact | null {
  const tokens = (value ?? "").trim().split(/\s+/).filter(Boolean);
  const domain = tokens[0] ?? "";
  if (!DOMAIN_RE.test(domain)) return null;
  const rest = tokens.slice(1);
  if (rest.join(" ") === "not loaded") return { domain, loaded: false };
  // A label may carry spaces (it is the plist author's string), so it is the remainder of the line.
  if (rest.length < 3) return null;
  const [pidTok, statusTok] = rest;
  const label = rest.slice(2).join(" ");
  const pid = pidTok === "-" ? undefined : /^\d+$/.test(pidTok) ? Number(pidTok) : NaN;
  if (Number.isNaN(pid)) return null;
  if (!/^-?\d+$/.test(statusTok)) return null;
  return { domain, loaded: true, pid, status: Number(statusTok), label };
}

/** Does a domain of this kind load a plist of this scope? */
export function domainFitsScope(domain: string, scope: LaunchScope): boolean {
  const daemon = scope === "system-daemon" || scope === "apple-daemon";
  if (scope === "elsewhere") return true;
  return daemon ? domain === "system" : domain !== "system";
}
