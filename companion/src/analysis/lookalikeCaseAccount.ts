// Look-alikes of the case's OWN accounts (#1971). A new account (4720) or a group member
// (4728/4732/4756) named one edit away from an account the case already holds — "svc-backupl" next
// to "svc-backup" — is how an attacker hides a backdoor in plain sight. lookalikeAccount.ts checks a
// name against the built-in accounts, one row at a time; this check needs every account name in the
// forensic timeline, so it runs once per import in the settle (routes/importSettleLookalike.ts).
//
// The pool is the forensic timeline only — never the super-timeline or the login graph (which is
// built from the super-timeline). A real account's 4624 logons are Low, so they stay in the
// forensic timeline and supply the names.
//
// Forward only: the candidates are the rows THIS import added. A real "svc-backup" that first appears
// in a LATER import does not re-check an earlier "svc-backupl" row.
//
// False-positive guards: a numbered copy ("user1"/"user2") is not a look-alike; a pair whose only
// difference is the first letter ("asmith"/"bsmith", initial + surname) is not one either; machine
// accounts ("PC01$") and service-noise accounts are skipped; a base shorter than five characters is
// skipped; and the candidate's own name never matches itself.
import { canonicalAccounts } from "./canonicalEvent.js";
import { appendDerivedNote } from "./derivedNote.js";
import { levenshtein } from "./lookalikeDomains.js";
import { accountBase, bareName, foldConfusables, memberCn, MIN_NAME_LENGTH } from "./lookalikeAccount.js";
import { worstSeverity, type ForensicEvent } from "./stateTypes.js";

export const LOOKALIKE_ACCOUNT_MARKER = "[look-alike account:";

const ACCOUNT_CREATED = /\(EID 4720\)/;
const GROUP_ADD = /\(EID (?:4728|4732|4756)\)/;
// The member as the importer renders it: "- MemberName=CN=…,OU=… @ HOST". The value ends at the next
// " - key=" field, the " @ host" suffix, or the end. memberCn stops at the DN's first unescaped comma.
const MEMBER_NAME = /\bMemberName=(.*?)(?= - [A-Za-z]+=| @ |$)/;
// The same noise set as loginGraph.isNoiseAccount (machine "$", DWM-/UMFD- sessions, anonymous),
// plus the built-in service principals. Not imported: loginGraph pulls in the whole SIEM importer.
const NOISE_ACCOUNT =
  /\$$|^(?:dwm|umfd)-\d+$|^(?:anonymous logon|system|local service|network service|localsystem)$/i;

/** The new account of a 4720, or the member of a group add; "" for any other row. */
export function lookalikeCandidateName(e: ForensicEvent): string {
  const description = e.description ?? "";
  // winRoleBlocks puts the 4720's target (the new account) first, as the actor.
  if (ACCOUNT_CREATED.test(description)) return canonicalAccounts(e)[0] ?? "";
  if (!GROUP_ADD.test(description)) return "";
  // A member named only by SID ("MemberName=-") cannot be named from the row alone.
  return memberCn(MEMBER_NAME.exec(description)?.[1] ?? "");
}

interface Keyed {
  bare: string;
  base: string;
  folded: string;
}

function keyed(name: string): Keyed | null {
  const bare = bareName(name);
  if (!bare || NOISE_ACCOUNT.test(bare)) return null;
  // Digits are stripped BEFORE the fold, which would read a trailing "1" as an "l".
  const base = accountBase(bare);
  if (base.length < MIN_NAME_LENGTH) return null;
  return { bare, base, folded: foldConfusables(base) };
}

// Same length, first letter changed, rest equal: "asmith"/"bsmith" — two real people.
const onlyFirstLetterDiffers = (a: string, b: string): boolean =>
  a.length === b.length && a[0] !== b[0] && a.slice(1) === b.slice(1);

/**
 * The case account `name` imitates, or null. A match is one edit after homoglyph folding (or zero
 * edits, when only the fold makes the names equal). Returned as the pool name's bare form.
 */
export function caseLookalike(name: string, pool: Iterable<string>): string | null {
  const cand = keyed(name);
  if (!cand) return null;
  const names = [...new Set([...pool].map((p) => bareName(p)))].sort();
  for (const p of names) {
    const other = keyed(p);
    // Same bare name (self) or same base (a numbered sibling) is never a look-alike.
    if (!other || other.bare === cand.bare || other.base === cand.base) continue;
    if (Math.abs(other.folded.length - cand.folded.length) > 1) continue;
    if (onlyFirstLetterDiffers(cand.folded, other.folded)) continue;
    if (levenshtein(cand.folded, other.folded) <= 1) return other.bare;
  }
  return null;
}

/** The row raised to High with a note naming both accounts. Idempotent: a noted row is returned as is. */
export function flagCaseLookalikeRow(e: ForensicEvent, name: string, match: string): ForensicEvent {
  if ((e.description ?? "").includes(LOOKALIKE_ACCOUNT_MARKER)) return e;
  return {
    ...e,
    severity: worstSeverity(e.severity, "High"),
    description: appendDerivedNote(
      e.description,
      LOOKALIKE_ACCOUNT_MARKER,
      `"${bareName(name)}" is one edit from case account "${match}"`,
    ),
  };
}
