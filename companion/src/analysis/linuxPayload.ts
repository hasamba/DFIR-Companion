// What a command DOES, read without running any part of it (#908 items 5 and 6).
//
// Split out of linuxPersistRules.ts because macOS reuses it: a launchd job that pipes curl into a
// shell is the same finding as a cron job that does, and the regexes that recognise it should have
// exactly one home. The path rules stay platform-specific — /tmp means something different from
// /private/var/folders — but "this command downloads code and executes it" does not.
//
// NOTHING IS EVALUATED. Every judgement is a pattern match against the text as collected. A grader
// that ran a candidate command to find out what it does would be the vulnerability, not the tool.

/** Directories any account can write and nothing should run from. */
export const TRANSIENT_RE = /^\/(?:tmp|var\/tmp|dev\/shm|run\/shm|var\/lock)(?:\/|$)/;

/** Directories a standard install puts binaries in. */
export const STANDARD_BIN_RE =
  /^\/(?:usr\/(?:bin|sbin|lib|lib64|libexec|local\/(?:bin|sbin))|bin|sbin|opt)\//;

/** Ordinary hidden directories. A payload under one of these is not remarkable for being hidden. */
const ORDINARY_HIDDEN = new Set([".config", ".local", ".ssh", ".gnupg", ".pki", ".mozilla"]);

export interface PayloadJudgement {
  /** The executable the command actually runs, as written. */
  target: string;
  transient: boolean;
  hidden: boolean;
  homeOwned: string;
  fetchExec: boolean;
  reverseShell: boolean;
  encoded: boolean;
}

const FETCH_EXEC_RES: RegExp[] = [
  // curl|wget piped straight into a shell, in either order and through any shell name.
  /\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:sudo\s+)?(?:\/[\w./-]*\/)?(?:ba|z|k|da|a)?sh\b/i,
  // command substitution: bash -c "$(curl …)" and eval "$(wget …)"
  /(?:eval|(?:ba|z|k|da|a)?sh\s+-c)\s*["']?\$\(\s*(?:curl|wget|fetch)\b/i,
  // python/perl one-liner that opens a URL and executes the body
  /\bpython[\d.]*\s+-c\b[^\n]*\b(?:urlopen|urllib|requests\.get)\b[^\n]*\bexec\b/i,
];

const REVERSE_SHELL_RES: RegExp[] = [
  /\/dev\/(?:tcp|udp)\/[^\s/]+\/\d+/i,
  /\bn(?:c|cat|etcat)\b[^\n]*\s-[a-z]*e[a-z]*\s/i,
  /\bsocat\b[^\n]*\bexec:/i,
  /\bmkfifo\b[^\n]*\|[^\n]*\bn(?:c|cat)\b/i,
  /\bpython[\d.]*\s+-c\b[^\n]*\bsocket\b[^\n]*\b(?:dup2|subprocess|pty\.spawn)\b/i,
  /\bperl\s+-e\b[^\n]*\bsocket\b[^\n]*\bexec\b/i,
];

const ENCODED_RES: RegExp[] = [
  /\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:\/[\w./-]*\/)?(?:ba|z|k|da|a)?sh\b/i,
  /\b(?:ba|z|k|da|a)?sh\s+-c\s*["']?\$\(\s*(?:echo|printf)\b[^\n]*base64\s+(?:-d|--decode)/i,
  /\bopenssl\s+enc\s+-d\b[^\n]*\|\s*(?:ba|z|k|da|a)?sh\b/i,
];

/** The first token of a command that names something to run, ignoring env assignments and wrappers. */
export function commandTarget(command: string): string {
  const tokens = (command ?? "").trim().split(/\s+/);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].replace(/^["']|["']$/g, "");
    if (!t) continue;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) continue; // FOO=bar prefix
    if (/^(?:sudo|nohup|setsid|nice|ionice|env|exec|command|time|timeout)$/.test(t)) continue;
    // A shell wrapper: what matters is the script it is given, which the payload regexes read.
    if (/^(?:\/[\w./-]*\/)?(?:ba|z|k|da|a)?sh$/.test(t) && tokens[i + 1]?.startsWith("-")) return t;
    return t;
  }
  return "";
}

/** Does a path sit under a user's home directory? Returns the account, or "". */
export function homeAccount(path: string): string {
  const m = /^\/home\/([^/]+)\//.exec(path);
  if (m) return m[1];
  if (/^\/root\//.test(path)) return "root";
  return "";
}

/** A dot-directory component that is not one of the ordinary ones. */
export function hiddenComponent(path: string): boolean {
  return (path ?? "")
    .split("/")
    .some((seg) => seg.startsWith(".") && seg.length > 1 && seg !== ".." && !ORDINARY_HIDDEN.has(seg));
}

/** Grade what a command does, without running or evaluating any part of it. */
export function judgePayload(command: string): PayloadJudgement {
  const cmd = command ?? "";
  const target = commandTarget(cmd);
  // A transient path ANYWHERE in the command counts: `bash /tmp/x.sh` runs bash, but the code is the
  // argument. Reading only the first token missed every wrapper form.
  const transientArg = /(?:^|[\s"'=(])\/(?:tmp|var\/tmp|dev\/shm|run\/shm)\//.test(cmd);
  return {
    target,
    transient: TRANSIENT_RE.test(target) || transientArg,
    hidden: hiddenComponent(target),
    homeOwned: homeAccount(target),
    fetchExec: FETCH_EXEC_RES.some((re) => re.test(cmd)),
    reverseShell: REVERSE_SHELL_RES.some((re) => re.test(cmd)),
    encoded: ENCODED_RES.some((re) => re.test(cmd)),
  };
}
