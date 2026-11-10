// The case's principal-name ledger (#2490): which display name each cloud principal id carries,
// learned at import from records that state the pair (an Entra service-principal sign-in, an Entra
// directory-audit app initiator or service-principal target) — Info rows included, because the
// harvest reads records, not graded events. Modelled on the host-rename ledger (#1495): a small fact
// table on the state, unioned on every merge, consumed by the settle-time carry
// (principalNameCarry.ts). Nothing here reads the super-timeline.
//
// The conflict rule is the one entraAuditImport's resolver uses: an id with two names resolves to
// nothing. Names are compared on the FULL stored form (Entra caps displayName at 256), never on
// the shortened text a row shows, so two names that differ only past the display cap still
// conflict. Display cleaning happens only when a suffix is rendered (principalNameCarry.ts).
// Shared layer: stateTypes names the type and stateMerge unions it, so nothing here imports ingest.

export interface PrincipalNameRecord {
  /** A lower-cased GUID: a service principal's object id or an application's app id. */
  id: string;
  /** Distinct names seen for the id, first spelling kept; two or more means "conflict". */
  names: string[];
}

/** Entra's own displayName limit: no real name is collapsed by storing this much. */
export const PRINCIPAL_NAME_STORED_MAX = 256;
/** Ids kept per case. A new id past it is dropped; a known id still learns a conflicting name. */
export const PRINCIPAL_NAMES_MAX = 20_000;
// Two names already make a conflict; a third adds nothing to the rule.
const NAMES_PER_ID = 2;

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROLS = /[\u0000-\u001f\u007f-\u009f]/g;
// Zero-width, bidi and line/paragraph separators (bidiControl.ts FORMAT_CHARS, kept local: shared layer).
const FORMAT = /[\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;

/** The stored form: one line, controls and format characters gone, bounded at Entra's limit. */
function storedName(raw: string): string {
  return raw
    .replace(FORMAT, "")
    .replace(CONTROLS, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, PRINCIPAL_NAME_STORED_MAX);
}

/** One id → name fact, or null when the id is not a GUID or the name is empty after cleaning. */
export function principalPair(id: string, name: string): PrincipalNameRecord | null {
  const key = id.trim().toLowerCase();
  const stored = storedName(name);
  if (!GUID.test(key) || !/[\p{L}\p{N}]/u.test(stored)) return null;
  // A name that is itself the id (or any GUID) names nothing.
  if (GUID.test(stored)) return null;
  return { id: key, names: [stored] };
}

const sameName = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/**
 * Union two ledgers by id. Stable: `a`'s ids first, then `b`'s new ones, so the state file does not
 * churn. Malformed records (a non-GUID id, no names) are dropped.
 */
export function mergePrincipalNames(
  a: readonly PrincipalNameRecord[] = [],
  b: readonly PrincipalNameRecord[] = [],
): PrincipalNameRecord[] {
  const out = new Map<string, string[]>();
  for (const r of [...a, ...b]) {
    const id = typeof r?.id === "string" ? r.id.trim().toLowerCase() : "";
    if (!GUID.test(id) || !Array.isArray(r.names)) continue;
    const cur = out.get(id);
    if (!cur && out.size >= PRINCIPAL_NAMES_MAX) continue;
    const names = cur ? [...cur] : [];
    for (const raw of r.names) {
      const n = typeof raw === "string" ? storedName(raw) : "";
      if (n && names.length < NAMES_PER_ID && !names.some((x) => sameName(x, n))) names.push(n);
    }
    if (names.length) out.set(id, names);
  }
  return [...out.entries()].map(([id, names]) => ({ id, names }));
}

/** The name to show for an id: defined only when exactly one name is known. */
export function principalNameLookup(
  ledger: readonly PrincipalNameRecord[] = [],
): (id: string) => string | undefined {
  const byId = new Map<string, string>();
  for (const r of ledger) if (r.names.length === 1) byId.set(r.id.toLowerCase(), r.names[0]);
  return (id) => byId.get(id.trim().toLowerCase());
}

export type PrincipalLedger = { principalNames?: PrincipalNameRecord[] };

/** True when the ledger says something different about any id. Content, not identity. */
export function principalLedgerChanged(before: PrincipalLedger, after: PrincipalLedger): boolean {
  return JSON.stringify(before.principalNames ?? []) !== JSON.stringify(after.principalNames ?? []);
}
