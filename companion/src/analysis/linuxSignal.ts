// The shape of a Linux/macOS persistence finding, and the helpers every grader shares (#908 items
// 5, 6 and 10).
//
// Split out so the graders can live in their own files without importing each other in a circle.
// Nothing here decides anything; it carries the incident-time rule, the severity wording and the
// "this could not be checked" disclosure that every finding is required to make.

import type { Severity } from "./stateTypes.js";
import type { CollectedFile, LinuxArtifactKind } from "./linuxPersistence.js";
import { TRANSIENT_RE, type PayloadJudgement } from "./linuxPayload.js";

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

export const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const EVIDENCE_MAX = 300;

/** Interpreters that hand out a root shell the moment they are setuid. */
export const INTERPRETER_RE =
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

export const SUID_BASELINE_SET = new Set(SUID_BASELINE);

/**
 * Roots that hold a COPY of a distribution image rather than the running system.
 *
 * A stock Ubuntu host has one setuid binary per snap revision — core20, core22, snapd, lxd,
 * firefox — and one per container layer under /var/lib/docker. Every one of them was landing in the
 * "outside every directory a distribution installs into" branch at High. A real host produced
 * dozens to hundreds of them, which is not merely noise: the signal cap then evicted the findings
 * that mattered. Inside one of these roots the file IS a packaged binary, so it is judged on its
 * name against the same baseline, at the path it would have on the host.
 */
export const IMAGE_ROOT_RE =
  /^\/(?:snap\/|var\/lib\/(?:docker|containers|containerd|lxd|lxc|snapd)\/|nix\/store\/|var\/lib\/flatpak\/|proc\/\d+\/root\/)/;

/**
 * The path a file inside an image root would have on the host.
 *
 * The LAST bin/lib segment, not the first: `/var/lib/docker/overlay2/…/diff/usr/bin/mount` starts
 * with `/var/lib/`, so taking the first match produced `/lib/docker/…` — not a standard directory,
 * so the exclusion never applied and the row was still reported.
 */
export function hostPathInImage(path: string): string {
  const re = /\/(?:usr\/)?(?:s?bin|lib|lib64|libexec)\//g;
  let last = -1;
  for (let m = re.exec(path); m; m = re.exec(path)) last = m.index;
  return last < 0 ? "" : path.slice(last);
}

// Commands a shadowing binary earlier in PATH would intercept.
export const SHADOWABLE = new Set([
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

export function clip(s: string): string {
  const t = (s ?? "").replace(/\s+/g, " ").trim();
  return t.length > EVIDENCE_MAX ? `${t.slice(0, EVIDENCE_MAX)}…` : t;
}

export function inIncident(file: CollectedFile, ctx: LinuxContext): boolean {
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
export function signal(
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

export function baselinePaths(ctx: LinuxContext): Set<string> {
  return new Set(ctx.baseline?.paths ?? []);
}

/** The wording every payload finding shares, so the reason names the property, not the artifact. */
export function payloadReason(j: PayloadJudgement, what: string): string | null {
  if (j.reverseShell) return `${what} opens an interactive connection back to a remote host.`;
  if (j.fetchExec)
    return `${what} downloads code and executes it in the same command, so the payload never has to exist on disk before it runs.`;
  if (j.encoded)
    return `${what} decodes its own payload before running it, which keeps the command text out of the logs.`;
  if (j.transient) {
    // The claim is worded on WHICH half matched. `/usr/local/bin/backup.sh >> /tmp/backup.log` runs
    // from /usr/local/bin; /tmp is a log target. Saying "runs from a world-writable directory" of
    // that command was simply false, on a High-severity forensic event.
    return TRANSIENT_RE.test(j.target)
      ? `${what} runs from a world-writable directory that is cleared on reboot, which is not where installed software lives.`
      : `${what} references a world-writable directory that is cleared on reboot. Check whether that path is what runs or only where output goes — the command names it, but the program itself is ${j.target || "not identifiable here"}.`;
  }
  if (j.hidden) return `${what} runs from a hidden directory.`;
  return null;
}

export function payloadSeverity(j: PayloadJudgement): Severity {
  if (j.reverseShell || j.fetchExec || j.encoded) return "High";
  // A program that IS in a world-writable directory is High. A command that merely mentions one —
  // a log path, a bind mount, a cache directory — is Medium and says which it is.
  if (j.transient) return TRANSIENT_RE.test(j.target) ? "High" : "Medium";
  return "Medium"; // hidden only
}

export function payloadTechniques(j: PayloadJudgement, base: string[]): string[] {
  const out = [...base];
  if (j.fetchExec || j.encoded || j.reverseShell) out.push("T1059.004");
  if (j.fetchExec) out.push("T1105");
  return [...new Set(out)];
}
