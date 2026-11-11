// Look-alike account and app names inside an M365 tenant (#2557). In a BEC or tenant takeover the
// attacker creates users and OAuth apps named to pass a glance: "rnicrosoft_office", or the
// company's own name with "rn" for "m". A creation or grant row (Add user, Add application, Add
// service principal, consent, an app or directory role grant) whose target name imitates a
// Microsoft brand, the tenant's own name, or the admin account is raised to High with a note naming
// both — the same rule as the Windows 4720 path (lookalikeAccount.ts).
//
// One post-pass over the rows of one export, after the BEC pairings. Names come from re-reading the
// row's own record (readEntraAuditRecord: the UAL and the Graph directory-audit shapes alike), never
// from the row's prose. The tenant's name is the label of the most common UPN domain in the export;
// a streamed import reads it per batch of records.
//
// False-positive guards: a name is split into words and each word is checked on its own; an exact
// brand word ("Microsoft Graph") is never a look-alike; a short target (under eight letters) matches
// only when the homoglyph or two-letter fold makes the word EQUAL to it — "Stearns" folds to
// "steams", which is not "teams", and "Armin" is not "admin"; only a long target also accepts one
// edit or containment after the fold. A Microsoft first-party app id exempts the row. Failures are
// skipped. Later (not here): a check against the tenant's other accounts, and Exchange trustees.
import { appendDerivedNote } from "./derivedNote.js";
import { readEntraAuditRecord, type EntraAuditRecord } from "./entraAuditRecord.js";
import { accountBase, foldConfusables, MIN_NAME_LENGTH } from "./lookalikeAccount.js";
import { LOOKALIKE_ACCOUNT_MARKER } from "./lookalikeCaseAccount.js";
import { foldMultiChar, levenshtein, registrable } from "./lookalikeDomains.js";
import { isMicrosoftFirstPartyService } from "./microsoftFirstPartyApps.js";
import { getCI, isObject, str, type MappedEvent } from "./siemImport.js";
import { worstSeverity } from "./stateTypes.js";

type Row = Record<string, unknown>;

export type LookalikeKind = "brand" | "tenant" | "admin";
export interface NameMatch {
  kind: LookalikeKind;
  name: string;
}

// Microsoft brands an attacker imitates in an app or account name. Lower-case.
const BRANDS = ["microsoft", "office", "outlook", "azure", "exchange", "sharepoint", "onedrive", "teams"];
const ADMIN_NAMES = ["admin", "administrator"];
const LONG_TARGET = 8;
const NAME_MAX = 80;
const OPS =
  /^(?:add user|add application|add service principal|consent to application|add delegated permission grant|add app role assignment to service principal|add (?:eligible )?member to role)$/i;
// Targets that are not an account or an app: a role's display name is Microsoft's own wording.
const UNNAMED_TYPE = /^(?:role|group|policy|device|directory)/i;
// Properties that state the target app's immutable id, in either export shape.
const APP_ID_PROP = /^(?:targetid\.|serviceprincipal\.)?(?:appid|appprincipalid|serviceprincipalnames)$/i;
const GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const ONMICROSOFT = ".onmicrosoft.com";
// The raw operation, read before the full record is decoded: most records of an export are not one.
const opOf = (rec: Row): string =>
  str(getCI(rec, "Operation") ?? getCI(rec, "activityDisplayName"))
    .trim()
    .replace(/\.$/, "");

const words = (name: string): string[] =>
  name
    .toLowerCase()
    .normalize("NFC")
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);

function wordMatches(word: string, target: string): boolean {
  // Digits are stripped BEFORE the fold, which would read a trailing "1" as an "l".
  const base = accountBase(word);
  if (base.length < MIN_NAME_LENGTH || base.includes(target) || base === `${target}s`) return false;
  const folded = foldConfusables(base);
  const shapes = [folded, foldMultiChar(folded)];
  if (shapes.includes(target)) return true;
  if (target.length < LONG_TARGET) return false;
  return shapes.some((s) => s.includes(target) || levenshtein(s, target) === 1);
}

/** What `name` imitates — a brand, the tenant label, or the admin account — or null. */
export function lookalikeNameMatch(name: string, tenant: string): NameMatch | null {
  const targets: NameMatch[] = [
    ...BRANDS.map((n) => ({ kind: "brand" as const, name: n })),
    ...(tenant && !BRANDS.includes(tenant) ? [{ kind: "tenant" as const, name: tenant }] : []),
    ...ADMIN_NAMES.map((n) => ({ kind: "admin" as const, name: n })),
  ];
  for (const word of words(name)) {
    const hit = targets.find((t) => wordMatches(word, t.name));
    if (hit) return hit;
  }
  return null;
}

function upnLabel(upn: string): string {
  if (!upn.includes("@") || /#ext#/i.test(upn)) return "";
  const domain = (upn.split("@").pop() ?? "").trim().toLowerCase();
  if (domain.endsWith(ONMICROSOFT)) return domain.slice(0, -ONMICROSOFT.length).split(".").pop() ?? "";
  return registrable(domain).split(".")[0] ?? "";
}

function recordUpns(rec: Row): string[] {
  const by = getCI(rec, "initiatedBy");
  const user = isObject(by) ? getCI(by, "user") : undefined;
  return [
    str(getCI(rec, "UserId")),
    str(getCI(rec, "userPrincipalName")),
    isObject(user) ? str(getCI(user, "userPrincipalName")) : "",
  ];
}

/** The tenant's own name: the label of the most common UPN domain in the export; "" when short. */
export function tenantLabel(records: readonly Row[]): string {
  const counts = new Map<string, number>();
  for (const rec of records)
    for (const label of recordUpns(rec).map(upnLabel).filter(Boolean))
      counts.set(label, (counts.get(label) ?? 0) + 1);
  const [best] = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return best && best[0].length >= MIN_NAME_LENGTH ? best[0] : "";
}

function hasFirstPartyAppId(rec: Row, r: EntraAuditRecord): boolean {
  const raw = [
    ...r.props.filter((p) => APP_ID_PROP.test(p.name)).map((p) => JSON.stringify(p.newValue ?? "")),
    JSON.stringify(getCI(rec, "Target") ?? ""),
  ].join(" ");
  return (raw.match(GUID) ?? []).some(isMicrosoftFirstPartyService);
}

function candidateNames(r: EntraAuditRecord): string[] {
  const fromTargets = r.targets
    .filter((t) => !UNNAMED_TYPE.test(t.type))
    .flatMap((t) => [t.upn.split("@")[0] ?? "", t.name]);
  const fromProps = r.props
    .filter((p) => /^(?:displayname|userprincipalname)$/i.test(p.name))
    .flatMap((p) => (Array.isArray(p.newValue) ? p.newValue : [p.newValue]))
    .map((v) => str(v).split("@")[0] ?? "");
  return [...new Set([...fromTargets, ...fromProps].map((n) => n.trim()).filter(Boolean))];
}

// The adversary's name inside the note: one line, no brackets or quotes that could forge or break a
// registered note, bounded.
const noteName = (name: string): string => {
  const clean = name
    .replace(/[\u0000-\u001f\u007f-\u009f"[\]]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return clean.length > NAME_MAX ? `${clean.slice(0, NAME_MAX)}…` : clean;
};
const WHAT: Record<LookalikeKind, string> = {
  brand: "the Microsoft brand name",
  tenant: "the tenant name",
  admin: "the admin account name",
};

/** The note for one record, or "" when its target names imitate nothing (or it is exempt). */
function recordNote(rec: Row, tenant: string): string {
  const r = readEntraAuditRecord(rec);
  if (!r || r.outcome === "failure" || !OPS.test(r.operation) || hasFirstPartyAppId(rec, r)) return "";
  for (const name of candidateNames(r)) {
    const hit = lookalikeNameMatch(name, tenant);
    if (hit) return `"${noteName(name)}" looks like ${WHAT[hit.kind]} "${hit.name}"`;
  }
  return "";
}

/**
 * Raise the rows of one export whose created or granted account or app name is a look-alike (see the
 * header). `rowRecords[i]` is the index in `records` of row `i`'s record. Returns new rows.
 */
export function applyM365Lookalike(
  rows: readonly MappedEvent[],
  rowRecords: readonly number[],
  records: readonly Row[],
): MappedEvent[] {
  const tenant = tenantLabel(records);
  const notes = new Map<number, string>();
  return rows.map((row, i) => {
    const record = rowRecords[i];
    const rec = record === undefined ? undefined : records[record];
    if (!rec || !OPS.test(opOf(rec))) return row;
    if (!notes.has(record)) notes.set(record, recordNote(rec, tenant));
    const note = notes.get(record);
    if (!note) return row;
    return {
      ...row,
      severity: worstSeverity(row.severity, "High"),
      description: appendDerivedNote(row.description, LOOKALIKE_ACCOUNT_MARKER, note),
    };
  });
}
