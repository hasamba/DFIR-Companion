// Deterministic grading of Windows account changes: a new account (4720) and a group add
// (4728 global / 4732 local / 4756 universal). Two signals, either one enough for High:
//   1. the GROUP is privileged — by name or by its SID;
//   2. the account NAME is a look-alike of a built-in account (#1956): "administratr" or a
//      Cyrillic "аdministrator" is how an attacker hides a backdoor admin in plain sight.
// The look-alike check is per row, against a static built-in list. A look-alike of the case's own
// service accounts ("svc-backupl") needs every name in the case and is not done here.
import { worstSeverity as worst, type Severity } from "./stateTypes.js";
import { CONFUSABLES, levenshtein } from "./lookalikeDomains.js";

// Groups whose membership IS privilege. An add to one of these is the difference between routine
// user administration and an attacker granting themselves the domain — so it, not the bare event id,
// is what earns a group change its High.
const PRIVILEGED_GROUP =
  /\b(?:domain admins|enterprise admins|schema admins|administrators|account operators|server operators|backup operators|print operators|dnsadmins|group policy creator owners|domain controllers|enterprise key admins|key admins)\b/i;

// The name above is English. AD localises built-in group display names at domain creation, so the
// same add reads "Admins du domaine" on a French domain and "Domänen-Admins" on a German one, and
// the regex misses the one event class where a miss costs a High — and with it the deterministic
// finding backfill that a High guarantees. A group's SID does not localise, so it is checked
// ALONGSIDE the name, never instead of it: DnsAdmins is created by the DNS Server role with a
// variable domain RID, so it has no well-known SID and is only ever reachable by name.
// Builtin groups (S-1-5-32-<rid>): Administrators, Account/Server/Backup/Print Operators. 545
// (Users) and the rest are deliberately absent — they are where routine provisioning lands.
const BUILTIN_PRIVILEGED_RIDS = new Set([544, 548, 549, 550, 551]);
// Domain-relative (S-1-5-21-<3 domain ids>-<rid>): Enterprise Read-only Domain Controllers 498,
// Domain Admins 512, Domain Controllers 516, Schema Admins 518, Enterprise Admins 519, Group Policy
// Creator Owners 520, Read-only Domain Controllers 521, Cloneable Domain Controllers 522, Key
// Admins 526, Enterprise Key Admins 527. Domain Users 513 is NOT privilege.
// 498 and 522 are here because the name check already grades them — both end in "Domain
// Controllers", which PRIVILEGED_GROUP matches — so leaving them out would make the SID path grade
// a localised domain STRICTLY worse than an English one, which is the whole bug this fixes.
const DOMAIN_PRIVILEGED_RIDS = new Set([498, 512, 516, 518, 519, 520, 521, 522, 526, 527]);
const BUILTIN_SID_RE = /^S-1-5-32-(\d{1,10})$/i;
// Same shape as TEXT_SID_RE in siemImport.ts: exactly three domain sub-authorities, then the RID.
const DOMAIN_SID_RE = /^S-1-5-21-(?:\d{1,10}-){3}(\d{1,10})$/i;

function isPrivilegedGroupSid(sid: string): boolean {
  const trimmed = sid.trim();
  const builtin = BUILTIN_SID_RE.exec(trimmed);
  if (builtin) return BUILTIN_PRIVILEGED_RIDS.has(Number(builtin[1]));
  const domain = DOMAIN_SID_RE.exec(trimmed);
  return domain ? DOMAIN_PRIVILEGED_RIDS.has(Number(domain[1])) : false;
}

// Built-in Windows / AD accounts an attacker imitates. Lower-case, English.
const BUILTIN_ACCOUNTS = [
  "administrator",
  "admin",
  "guest",
  "krbtgt",
  "defaultaccount",
  "wdagutilityaccount",
];

// Built-in names as Windows localises them. "Administrateur" is two edits from "administrator", so
// without this list every French domain's real built-in admin would grade High. Exact match only.
const LOCALIZED_BUILTINS = new Set(
  [
    "administrateur",
    "administrador",
    "administratör",
    "administrátor",
    "administratorius",
    "järjestelmänvalvoja",
    "rendszergazda",
    "yönetici",
    "gast",
    "gäst",
    "invité",
    "invitado",
    "convidado",
    "ospite",
    "vieras",
    "vendég",
    "gość",
  ].map((n) => n.normalize("NFC")),
);

// Group names and plurals. "Administrators" is one edit from "administrator", but it is the group.
const PLURALS = new Set(["administrators", "admins", "guests"]);

const MIN_NAME_LENGTH = 5;
// A built-in name this long tolerates two edits; a shorter one only one.
const LONG_NAME = 8;
const DESCRIPTION_CAP = 600;

// Strip a domain prefix or UPN suffix, lower-case, and normalise composed characters.
function bareName(name: string): string {
  const afterSlash = name.trim().split("\\").pop() ?? "";
  return (afterSlash.split("@")[0] ?? "").toLowerCase().normalize("NFC");
}

function foldConfusables(s: string): string {
  let out = "";
  for (const ch of s) out += CONFUSABLES[ch] ?? ch;
  return out;
}

// "admin" is short and common inside real names ("sadmin", "radmin"), so it accepts one
// SUBSTITUTION only — same length, one letter changed.
function isNear(candidate: string, builtin: string): boolean {
  const d = levenshtein(candidate, builtin);
  if (d === 0) return false;
  if (builtin === "admin") return d === 1 && candidate.length === builtin.length;
  return d <= (builtin.length >= LONG_NAME ? 2 : 1);
}

/**
 * The built-in account `name` imitates, or null. The exact built-in name, a localised built-in name,
 * a plural, a numbered copy ("admin2", "krbtgt_12345" — an RODC's real krbtgt) and a name shorter
 * than five characters are never look-alikes. Homoglyphs are folded first, so an all-Cyrillic
 * spelling is caught as well as a single swapped letter.
 */
export function lookalikeBuiltin(name: string): string | null {
  const raw = bareName(name);
  if (!raw || LOCALIZED_BUILTINS.has(raw) || PLURALS.has(raw)) return null;
  // Digits are stripped BEFORE the fold, which would read a trailing "1" as an "l".
  const base = raw.replace(/[._-]?\d+$/, "");
  if (base.length < MIN_NAME_LENGTH || BUILTIN_ACCOUNTS.includes(base)) return null;
  const folded = foldConfusables(base);
  for (const builtin of BUILTIN_ACCOUNTS) {
    if (folded === builtin || isNear(folded, builtin)) return builtin;
  }
  return null;
}

/**
 * The CN of an LDAP member DN ("CN=Smith\, J,OU=Staff,DC=…" → "Smith, J"). "-" or empty means the
 * event names the member only by MemberSid (common on 4732). That member cannot be named from this
 * row alone — it needs a join on the SID across rows. A value that is not a DN passes through.
 */
export function memberCn(dn: string): string {
  const v = dn.trim();
  if (!v || v === "-") return "";
  if (!/^cn=/i.test(v)) return v;
  let out = "";
  for (let i = 3; i < v.length; i++) {
    const ch = v[i];
    if (ch === "\\" && i + 1 < v.length) out += v[++i];
    else if (ch === ",") break;
    else out += ch;
  }
  return out.trim();
}

const GROUP_ADD_EIDS = new Set([4728, 4732, 4756]);
const ACCOUNT_CREATED = 4720;

/**
 * Grade a new account or a group add; null for any other event. 4728/4732/4756 name the group in
 * TargetUserName and the member in MemberName, not the other way round; 4720 names the new account
 * in TargetUserName. A look-alike name grades High whatever the group, and appends a note naming
 * both accounts, kept inside the description cap.
 */
export function accountChangeOverlay(
  eid: number,
  field: (key: string) => string,
  description: string,
  severity: Severity,
): { description: string; severity: Severity } | null {
  const isGroupAdd = GROUP_ADD_EIDS.has(eid);
  if (!isGroupAdd && eid !== ACCOUNT_CREATED) return null;
  let graded = severity;
  // The name is localised and the SID is not, so either identifying the group is enough — see
  // isPrivilegedGroupSid for why neither check subsumes the other.
  if (
    isGroupAdd &&
    (PRIVILEGED_GROUP.test(field("TargetUserName")) || isPrivilegedGroupSid(field("TargetSid")))
  )
    graded = worst(graded, "High");
  const builtin = lookalikeBuiltin(isGroupAdd ? memberCn(field("MemberName")) : field("TargetUserName"));
  if (!builtin) return { description, severity: graded };
  const note = `[look-alike of built-in account "${builtin}"]`;
  return {
    description: `${description.slice(0, DESCRIPTION_CAP - note.length - 1)} ${note}`,
    severity: worst(graded, "High"),
  };
}
