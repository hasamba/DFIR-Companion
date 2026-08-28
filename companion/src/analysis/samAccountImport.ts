// Windows.Forensics.SAM — the local user account database, one row per account.
//
// The artifact parses `SAM\Domains\Account\Users` into two nested blobs: `ParsedV` (the account's
// strings — username, full name, comment, and the LM/NT password hash material) and `ParsedF` (its
// numbers — RID, flags, and the login/password-reset timestamps). velociraptorImport's generic
// mapper flattens whatever it is handed into `key=value` text, so these rows arrived on the
// timeline as `ParsedV.lmpwd_hash=…` — a wall of decoded binary with the username buried in it and
// no statement of what happened. The one question the SAM answers on a ransomware case, "which
// local accounts exist and when were they made", was unanswerable from the event.
//
// GRADING. A local account is graded on its RID, which is the only reliable fact here:
//
//   • RID < 1000 — a built-in (500 Administrator, 501 Guest, 503 DefaultAccount, 504 WDAGUtility).
//     Every Windows host has these. Graded Info: marking them would flag every host in every case.
//   • RID >= 1000 — a CUSTOM account, meaning one that is not shipped with Windows. Graded Low and
//     described as existing, nothing more. Low is above the forensic floor, so the account and its
//     dates reach the timeline; the event makes no claim about when or by whom it was made.
//   • RID >= 1000 AND the row carries a real creation timestamp — only then is this an account
//     CREATION: Medium with T1136.001, worded "Local account created".
//
// That last distinction is the point. A RID separates a custom account from a built-in and says
// NOTHING about when it appeared: the ordinary owner of a laptop holds RID 1001. Grading the RID
// alone turned every long-lived user account on every host into a T1136.001 creation finding dated
// by the account key's last write — a timestamp that moves on any password change or group edit, so
// the "creation" would also have been dated wrong. A creation finding needs creation evidence.
//
// The event NEVER renders the hash columns. `lmpwd_hash` / `ntpwd_hash` are credential material, and
// a description is copied into reports, exported bundles, and AI prompts.
//
// Kept out of velociraptorImport.ts, which is frozen at its current size by the file-size ledger
// (#384) — see check-file-size.mjs.

import { getCI, getPath, str, type MappedEvent } from "./siemImport.js";
import { withHostSuffix } from "./velociraptorTitle.js";
import { vrTime } from "./veloRowTime.js";

type Row = Record<string, unknown>;

// The account-control bits in ParsedF.Flags that change how an account should be read. Velociraptor
// renders Flags as a decoded string list on most versions and as a raw number on others, so both
// forms are handled.
//
// These are the SAM ACB_* bits, which are NOT Active Directory's userAccountControl bits. The two
// sets look interchangeable and are not: userAccountControl spells password-not-required 0x0020 and
// password-never-expires 0x10000, while the SAM's own ACB_PWNOTREQ / ACB_PWNOEXP are 0x0004 and
// 0x0200. Using the AD values here silently dropped both warnings and read unrelated bits (ACB_MNS,
// and a bit the SAM does not define) as if they were these two.
const FLAG_DISABLED = 0x0001; // ACB_DISABLED
const FLAG_PWD_NOT_REQUIRED = 0x0004; // ACB_PWNOTREQ
const FLAG_PWD_NEVER_EXPIRES = 0x0200; // ACB_PWNOEXP

/**
 * Is this a Windows.Forensics.SAM account row?
 *
 * `ParsedV` and `ParsedF` are that artifact's own container names and appear in no other
 * Velociraptor artifact, so the pair is a safe signature even on an export whose `_Source` marker
 * was lost. Either container alone is enough — some versions omit `ParsedF` for an account whose F
 * value failed to parse — but the row must also carry a `Key`/`OSPath` naming the SAM hive path, so
 * a hand-built row cannot reach a mapper that assumes an account.
 */
export function isSamAccountRow(row: Row): boolean {
  const hasParsed = getCI(row, "ParsedV") != null || getCI(row, "ParsedF") != null;
  if (!hasParsed) return false;
  const key = `${str(getCI(row, "Key"))} ${str(getCI(row, "OSPath"))} ${str(getPath(row, "Key.OSPath"))}`;
  return /\\sam\b|\\domains\\account\\users/i.test(key) || getCI(row, "ParsedV") != null;
}

// The first non-empty string among several candidate paths (dotted paths allowed).
function pick(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(v).trim();
    if (s) return s;
  }
  return "";
}

// The account's RID as a number, or null. Velociraptor reports it as a decimal under ParsedF.Rid on
// most versions; on others the only carrier is the registry key name, which is the RID in hex
// ("000001F4" = 500).
function ridOf(row: Row): number | null {
  const direct = pick(row, ["ParsedF.Rid", "ParsedF.RID", "Rid", "RID", "UserRID"]);
  if (direct) {
    const n = Number(direct);
    if (Number.isInteger(n) && n > 0) return n;
  }
  const key = pick(row, ["Name", "Key", "Key.Name", "OSPath", "KeyName"]);
  const hex = /(?:^|\\)([0-9a-f]{8})\s*$/i.exec(key.trim());
  if (hex) {
    const n = Number.parseInt(hex[1], 16);
    if (Number.isInteger(n) && n > 0) return n;
  }
  return null;
}

// The account-control flags, rendered as the short labels worth showing. Accepts the decoded string
// (or string list) Velociraptor emits on recent versions and the raw bitmask on older ones.
function flagLabels(row: Row): string[] {
  const raw = getCI(row, "ParsedF") != null ? getPath(row, "ParsedF.Flags") : getCI(row, "Flags");
  const out: string[] = [];
  if (typeof raw === "number" && Number.isFinite(raw)) {
    if (raw & FLAG_DISABLED) out.push("disabled");
    if (raw & FLAG_PWD_NOT_REQUIRED) out.push("password not required");
    if (raw & FLAG_PWD_NEVER_EXPIRES) out.push("password never expires");
    return out;
  }
  const text = (Array.isArray(raw) ? raw.join(" ") : str(raw)).toLowerCase();
  if (!text) return out;
  if (/account_disabled|\bdisabled\b/.test(text)) out.push("disabled");
  if (/password_not_required|passwd_notreqd/.test(text)) out.push("password not required");
  if (/dont_expire|password_never/.test(text)) out.push("password never expires");
  return out;
}

/**
 * Map one SAM account row to a timeline event.
 *
 * Leads with the account, not the hive path: "Local account: dfir (RID 1001) [disabled] - last
 * login 2026-07-02T…". Says "created" ONLY when the row carries a creation timestamp; see the
 * grading note at the top of this file. Times the event at that creation where one exists, so a
 * backdoor account made during the intrusion lands inside the window rather than at collection time.
 */
export function mapSamAccount(row: Row, artifact: string, host: string): MappedEvent {
  const user =
    pick(row, ["ParsedV.username", "ParsedV.Username", "ParsedV.UserName", "Username", "UserName", "Name"]) ||
    "(account)";
  const rid = ridOf(row);
  const custom = rid !== null && rid >= 1000;

  const fullName = pick(row, ["ParsedV.fullname", "ParsedV.FullName"]);
  const comment = pick(row, ["ParsedV.comment", "ParsedV.Comment"]);
  const flags = flagLabels(row);
  const lastLogin = vrTime(getPath(row, "ParsedF.LastLoginDate") ?? getCI(row, "LastLogin"));
  const pwdReset = vrTime(
    getPath(row, "ParsedF.PasswordResetDate") ??
      getPath(row, "ParsedF.PasswordLastSet") ??
      getCI(row, "PasswordLastSet"),
  );
  const logins = pick(row, ["ParsedF.LoginCount", "LoginCount"]);

  // A real creation time — the SAM/CreateTimes source's own column, and nothing else. The account
  // key's last-write time is deliberately NOT accepted here: it is rewritten by a password change or
  // a group membership edit, so it dates the last modification, not the creation. It is still the
  // best available timestamp for the event, so it is used below for that and only that.
  const createdAt = vrTime(getCI(row, "CreateTime") ?? getCI(row, "Created") ?? getCI(row, "AccountCreated"));
  const keyWritten = vrTime(getCI(row, "KeyMTime") ?? getCI(row, "Mtime") ?? getPath(row, "Key.Mtime"));
  const isCreation = custom && createdAt !== "";

  const parts: string[] = [];
  parts.push(`${isCreation ? "Local account created" : "Local account"}: ${user}`);
  if (rid !== null) parts[0] += ` (RID ${rid})`;
  if (fullName && fullName.toLowerCase() !== user.toLowerCase()) parts.push(`"${fullName}"`);
  if (flags.length) parts.push(`[${flags.join(", ")}]`);
  if (pwdReset) parts.push(`password set ${pwdReset}`);
  if (lastLogin) parts.push(`last login ${lastLogin}`);
  if (logins && logins !== "0") parts.push(`${logins} logins`);
  if (comment) parts.push(`- ${comment}`);

  let description = `Velociraptor${artifact ? ` [${artifact}]` : ""}: ${parts.join(" - ")}`;
  description = withHostSuffix(description, host).slice(0, 600);

  return {
    timestamp: createdAt || keyWritten || pwdReset || lastLogin,
    description,
    // Every rendered fact is in the key EXCEPT the timestamps, so re-collecting the same host does
    // not emit a second event per account while two different accounts stay apart.
    aggKey: `vr|sam|${host.toLowerCase()}|${user.toLowerCase()}|${rid ?? "?"}`.slice(0, 400),
    severity: isCreation ? "Medium" : custom ? "Low" : "Info",
    mitre: isCreation ? ["T1136.001"] : [],
    sources: ["Velociraptor"],
    ...(host ? { asset: host } : {}),
  };
}
