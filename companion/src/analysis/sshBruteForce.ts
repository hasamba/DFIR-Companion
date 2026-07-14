// Deterministic SSH brute-force-SUCCESS detection for sshd auth logs. Where Timesketch's
// ssh_sessionizer only GROUPS sshd events into sessions (by PID) with no threat verdict, this instead
// surfaces the outcome that actually matters in an intrusion: a successful login that follows a burst
// of failed attempts from the SAME source IP — i.e. a password-guessing attack that eventually landed
// (ATT&CK T1110 / T1110.001).
//
// Pure and stateful-per-call: parse each sshd message to an auth outcome, then correlate accepted
// logins against the preceding failures from that IP within a lookback window. AI-free, unit-tested.
// Reused by the syslog importer (and available to any sshd-log source). IPv4 only (matching the
// upstream analyzer's scope); IPv6 sources are not correlated.

export interface SshAuth {
  result: "accepted" | "failed";
  user: string;
  ip: string; // IPv4
}

const IPV4 = String.raw`(\d{1,3}(?:\.\d{1,3}){3})`;
// "Accepted password|publickey|keyboard-interactive/pam for [invalid user] <user> from <ip> ..."
const ACCEPTED_RE = new RegExp(String.raw`^Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?(\S+) from ${IPV4}\b`, "i");
// "Failed password|publickey for [invalid user] <user> from <ip> ..."
const FAILED_RE = new RegExp(String.raw`^Failed (?:password|publickey) for (?:invalid user )?(\S+) from ${IPV4}\b`, "i");
// "Invalid user <user> from <ip> ..." — a pre-auth failure (unknown account), counts as a failed try.
const INVALID_RE = new RegExp(String.raw`^Invalid user (\S+) from ${IPV4}\b`, "i");

// Parse one sshd message (the free text after "sshd[pid]: ") into an auth outcome, or null when the
// line isn't a login success/failure we correlate on.
export function parseSshAuth(message: string): SshAuth | null {
  const msg = message.trim();
  let m = ACCEPTED_RE.exec(msg);
  if (m) return { result: "accepted", user: m[1], ip: m[2] };
  m = FAILED_RE.exec(msg);
  if (m) return { result: "failed", user: m[1], ip: m[2] };
  m = INVALID_RE.exec(msg);
  if (m) return { result: "failed", user: m[1], ip: m[2] };
  return null;
}

export const DEFAULT_SSH_MIN_FAILURES = 5;
export const DEFAULT_SSH_WINDOW_MS = 60 * 60 * 1000; // 1 hour lookback

// Minimum prior failures, overridable via DFIR_SSH_BRUTEFORCE_MIN_FAILS (positive integer).
export function sshMinFailures(): number {
  const n = Number(process.env.DFIR_SSH_BRUTEFORCE_MIN_FAILS);
  return Number.isInteger(n) && n > 0 ? n : DEFAULT_SSH_MIN_FAILURES;
}
// Lookback window in ms, overridable via DFIR_SSH_BRUTEFORCE_WINDOW_MIN (positive minutes).
export function sshWindowMs(): number {
  const n = Number(process.env.DFIR_SSH_BRUTEFORCE_WINDOW_MIN);
  return Number.isFinite(n) && n > 0 ? n * 60 * 1000 : DEFAULT_SSH_WINDOW_MS;
}

// One auth event to correlate: `key` is the caller's own id (e.g. the event's index), `ms` the epoch
// time (0 / NaN ⇒ undated, skipped from correlation since the window can't be applied).
export interface SshAuthEvent<K> {
  key: K;
  ms: number;
  ip: string;
  result: "accepted" | "failed";
}

export interface SshBruteForceHit<K> {
  key: K;
  ip: string;
  failures: number; // failed attempts from this IP within the window before the success
}

export interface SshBruteForceOptions {
  minFailures?: number;
  windowMs?: number;
}

// Correlate accepted logins against preceding failures from the same IP. Returns one hit per accepted
// event that was preceded by >= minFailures failed attempts from its IP within windowMs — the
// brute-force-success signal. Events are processed in chronological order (sorted here defensively).
export function markSshBruteForce<K>(
  events: SshAuthEvent<K>[],
  opts: SshBruteForceOptions = {},
): SshBruteForceHit<K>[] {
  const minFailures = opts.minFailures ?? sshMinFailures();
  const windowMs = opts.windowMs ?? sshWindowMs();

  const dated = events.filter((e) => Number.isFinite(e.ms) && e.ms > 0);
  const ordered = [...dated].sort((a, b) => a.ms - b.ms);

  const failuresByIp = new Map<string, number[]>(); // IP → sorted failure timestamps seen so far
  const hits: SshBruteForceHit<K>[] = [];

  for (const e of ordered) {
    if (e.result === "failed") {
      const list = failuresByIp.get(e.ip) ?? [];
      list.push(e.ms);
      failuresByIp.set(e.ip, list);
      continue;
    }
    // accepted — count this IP's failures inside [ms - windowMs, ms].
    const list = failuresByIp.get(e.ip);
    if (!list || list.length === 0) continue;
    const lower = e.ms - windowMs;
    let count = 0;
    for (const t of list) if (t >= lower && t <= e.ms) count++;
    if (count >= minFailures) hits.push({ key: e.key, ip: e.ip, failures: count });
  }
  return hits;
}
