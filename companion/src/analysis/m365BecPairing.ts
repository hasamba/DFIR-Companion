// BEC pairings over one M365 export (#2550): two grades that no single record can carry, because each
// needs a second record. The join itself, its windows and its notes live in m365BecMerge.ts.
//
// This pass stamps every row that can take part with a `canonical.m365Bec` block — an inbox rule that
// forwards outside or hides mail, an `Add user`, a privileged directory-role grant (a role the Entra
// decoder places in a tier other than "other") — and runs the join over this parse. A streamed import
// parses one batch at a time and a case is built from many uploads; the merge chain runs the same
// join over every stored row (m365BecMerge.ts raiseCaseBecPairs, #2570), so a pair split across
// batches or uploads is raised when the second half arrives.
//
// Only successful records count, and a row is only ever RAISED, never lowered; each raised row says
// why. The facts come from re-reading the row's own record with the same decoders the importer used
// (never from the row's prose), and only records whose operation can take part are re-read.

import type { M365BecBlock } from "./canonicalMailbox.js";
import { decodeEntraAppChanges } from "./entraAppChange.js";
import { readEntraAuditRecord } from "./entraAuditRecord.js";
import { decodeExchangeRecord } from "./exchangeAudit.js";
import { domainOf, localName } from "./exchangeAuditValues.js";
import { applyBecRaise, becJoinRow, becRaises } from "./m365BecMerge.js";
import { getCI, str, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

const RULE_OP = /inboxrule/i;
const ADD_USER_OP = /^add user\.?$/i;
const ROLE_OP = /^add (?:eligible )?member to role/i;
const KEY_MAX = 400;
const ID_MAX = 320;
const TENANT_MAX = 100;
const ROLE_MAX = 160;

const opOf = (rec: Row): string => str(getCI(rec, "Operation") ?? getCI(rec, "activityDisplayName")).trim();
/** A block before its time is stamped from the row. */
type Fact = Omit<M365BecBlock, "at">;
const tenantOf = (t: string): Partial<Fact> => {
  const v = t.trim().toLowerCase().slice(0, TENANT_MAX);
  return v ? { tenant: v } : {};
};
const identityKeys = (...v: string[]): string[] => [
  ...new Set(v.map((x) => x.trim().toLowerCase().slice(0, ID_MAX)).filter(Boolean)),
];

/** The block of an inbox rule that forwards outside or hides mail, or null. */
function ruleBlock(rec: Row, record: number): Fact | null {
  const c = decodeExchangeRecord(rec, record);
  if (!c || c.kind !== "rule" || c.attempted || c.polarity !== "adds") return null;
  if (!c.forwardsOutside && !c.hidesHard) return null;
  // One mailbox is written as an alias, an Exchange path or a UPN: key on its local name, and keep
  // the UPN's domain so `finance@a` and `finance@b` stay two mailboxes (#2570 review).
  const domain = c.mailbox.includes("@") ? domainOf(c.mailbox) : "";
  return {
    role: "rule",
    rule: `${c.actor.toLowerCase()}|${localName(c.mailbox)}`.slice(0, KEY_MAX),
    ...(domain ? { mailboxDomain: domain } : {}),
    ...tenantOf(c.tenant),
    forwardsOut: c.forwardsOutside,
    hidesHard: c.hidesHard,
  };
}

/** The blocks of a directory record's rows: one for an `Add user`, one per privileged grant. */
function entraBlocks(rec: Row): Fact[] {
  const r = readEntraAuditRecord(rec);
  if (!r || r.outcome !== "success") return [];
  if (ADD_USER_OP.test(r.operation)) {
    const user = r.targets.find((t) => /user/i.test(t.type)) ?? r.targets[0];
    const ids = identityKeys(user?.id ?? "", user?.upn ?? "");
    return ids.length ? [{ role: "created", ids, ...tenantOf(r.tenant) }] : [];
  }
  return decodeEntraAppChanges(r).flatMap((c): Fact[] => {
    if (c.kind !== "role-assigned" || c.attempted || !c.role || c.role.tier === "other") return [];
    const member = r.targets.find((t) => t.id && t.id === c.role?.memberId);
    // A display name is no identity; a UPN-shaped one is (#2570 review).
    const name = c.role.memberName.includes("@") ? c.role.memberName : "";
    const ids = identityKeys(c.role.memberId, name, member?.upn ?? "");
    return ids.length
      ? [{ role: "grant", ids, roleName: c.role.name.slice(0, ROLE_MAX), ...tenantOf(r.tenant) }]
      : [];
  });
}

/**
 * Each row's block, by the record it came from. A directory record maps to one row per change, so a
 * grant's block goes to the row whose target is that member (the envelope's target, set from the
 * same decoded change), never to the record's other rows.
 */
function blocksOf(rows: readonly MappedEvent[], rowRecords: readonly number[], records: readonly Row[]) {
  const cache = new Map<number, Fact[]>();
  return rows.map((row, i): Fact | null => {
    const record = rowRecords[i];
    const rec = record === undefined ? undefined : records[record];
    if (!rec) return null;
    const op = opOf(rec);
    if (RULE_OP.test(op)) return ruleBlock(rec, record);
    if (!ADD_USER_OP.test(op) && !ROLE_OP.test(op)) return null;
    if (!cache.has(record)) cache.set(record, entraBlocks(rec));
    const list = cache.get(record)!;
    if (list[0]?.role === "created") return list[0];
    const target = identityKeys(row.canonical?.target?.id ?? "", row.canonical?.target?.name ?? "");
    return list.find((b) => (b.ids ?? []).some((id) => target.includes(id))) ?? null;
  });
}

/**
 * Stamp the pairing block on the rows of one export and raise the rows a BEC pairing proves (see
 * the header). `rowRecords[i]` is the index in `records` of the record row `i` came from. Returns
 * new rows; the input is not changed.
 */
export function applyBecPairing(
  rows: readonly MappedEvent[],
  rowRecords: readonly number[],
  records: readonly Row[],
): MappedEvent[] {
  const blocks = blocksOf(rows, rowRecords, records);
  const stamped = rows.map((row, i): MappedEvent => {
    const block = blocks[i];
    return block && row.canonical && row.timestamp
      ? { ...row, canonical: { ...row.canonical, m365Bec: { ...block, at: row.timestamp } } }
      : row;
  });
  const join = stamped.map((row) => becJoinRow(row.canonical?.m365Bec));
  const raise = becRaises(join, "export");
  return raise.size
    ? stamped.map((row, i) => (raise.has(i) ? applyBecRaise(row, raise.get(i)!) : row))
    : stamped;
}
