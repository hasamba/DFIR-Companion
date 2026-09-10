// SSH authorized-key grading (#908 item 5). Split out of linuxPersistRules.ts, which reached the
// file-size ceiling; the rules here are the ones about WHO CAN LOG IN, which is a different question
// from what runs on a schedule.
//
// ─────────────────────────── A FORCED COMMAND IS USUALLY HARDENING ───────────────────────────
//
// `command="/usr/bin/rrsync /srv"` RESTRICTS a key to one program. Reporting that would punish good
// practice, and a backup estate would fill the panel. It is only a finding when the thing it forces
// is a shell or a payload — which turns the restriction into the backdoor.
//
// The opposite case matters too: cloud-init writes the launch key into /root/.ssh/authorized_keys
// behind a forced command that prints a message and exits, and the SAME key into the default
// user's file. Read naively that is "one key authorises root and ubuntu" on every cloud image ever
// launched. The root entry is inert and the forced command says so, so it is read.

import { keyOption, parseAuthorizedKeys, type CollectedFile } from "./linuxPersistence.js";
import { judgePayload } from "./linuxPayload.js";
import {
  clip,
  inIncident,
  payloadReason,
  payloadSeverity,
  payloadTechniques,
  signal,
  type LinuxContext,
  type LinuxSignal,
} from "./linuxSignal.js";

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
    // environment="LD_PRELOAD=…" on a key is persistence that runs on every login under that key,
    // and it is invisible to a rule that reads only command=.
    const env = keyOption(key.options, "environment");
    if (env && /\b(?:LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|PYTHONSTARTUP|BASH_ENV|ENV)\s*=/i.test(env)) {
      out.push(
        signal(file, ctx, {
          severity: "High",
          mitre: ["T1098.004", "T1574.006"],
          reason: `This authorized key sets ${clip(env)} for every session it opens, so a library or script of the operator's choosing is loaded into whatever the account runs. Account: ${account || "unknown"}.`,
          evidence,
          line: key.line,
        }),
      );
      continue;
    }

    const forced = keyOption(key.options, "command");
    if (forced) {
      const j = judgePayload(forced);
      const reason = payloadReason(j, "A forced command on this authorized key");
      // A forced command that spawns a shell through an interpreter is the same backdoor as one
      // that names the shell directly — `python3 -c 'import pty;pty.spawn("/bin/sh")'` was missed
      // by a shell-name-only test.
      const isShell =
        /^(?:\/[\w./-]*\/)?(?:ba|z|k|da|a)?sh\b/.test(forced.trim()) ||
        /\b(?:pty\.spawn|spawn\(["']\/bin\/|os\.system|subprocess\.(?:call|run|Popen)|exec\s*\(["']\/bin\/)/.test(
          forced,
        );
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
 * A forced command that DENIES the login rather than granting one.
 *
 * cloud-init writes the launch key into /root/.ssh/authorized_keys behind exactly this, and the
 * same key into the default user's file — so every EC2, Debian and RHEL cloud image ever launched
 * produced a High "the same SSH key authorises root and ubuntu" finding. The root entry is inert,
 * and the forced command is the readable proof of that.
 */
export function isNeuteredKey(options: string): boolean {
  const forced = keyOption(options, "command") ?? "";
  return /please login as|exit\s+142|\bexit\s+1\b/i.test(forced) && /echo|printf/i.test(forced);
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
  const byBlob = new Map<
    string,
    { account: string; file: CollectedFile; line: number; comment: string; neutered: boolean }[]
  >();

  for (const file of files) {
    if (file.kind !== "authorized_keys") continue;
    const account = keyAccount(file.path);
    if (!account) continue;
    for (const key of parseAuthorizedKeys(file.content)) {
      if (known.has(key.blob)) continue;
      const list = byBlob.get(key.blob) ?? [];
      // One account, one entry: the same file listing a key twice is not two accounts.
      if (list.some((e) => e.account === account)) continue;
      list.push({
        account,
        file,
        line: key.line,
        comment: key.comment,
        neutered: isNeuteredKey(key.options),
      });
      byBlob.set(key.blob, list);
    }
  }

  const out: LinuxSignal[] = [];
  for (const [blob, uses] of byBlob) {
    // An account whose copy of the key is neutered does not have access through it, so it is not a
    // second account this key opens.
    const live = uses.filter((u) => !u.neutered);
    if (live.length < 2) continue;
    const accounts = live.map((u) => u.account);
    const hasRoot = accounts.includes("root");
    const first = live[0];
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
