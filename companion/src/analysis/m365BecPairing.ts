// BEC pairings over one M365 export (#2550): two grades that no single record can carry, because each
// needs a second record of the same export.
//
// 1. A hiding inbox rule (deletes mail, or moves it to a known hiding folder) created by the same
//    actor on the same mailbox within HIDE_PAIR_WINDOW_MS of a rule that forwards outside the domain
//    is the BEC twin: the second rule hides the replies the first rule's forwards would draw. The
//    hiding rule is raised to Critical.
// 2. A privileged directory role (a role the Entra decoder places in a tier other than "other")
//    granted to a user that an `Add user` record of the same export created at most
//    NEW_USER_GRANT_WINDOW_MS earlier is raised to High. The creation row keeps its grade.
//
// Only successful records count, and a row is only ever RAISED, never lowered; each raised row says
// why. The facts come from re-reading the row's own record with the same decoders the importer used
// (never from the row's prose), and only records whose operation can take part are re-read. A
// streamed import pairs within one batch of records only.

import { decodeEntraAppChanges } from "./entraAppChange.js";
import { readEntraAuditRecord } from "./entraAuditRecord.js";
import { decodeExchangeRecord } from "./exchangeAudit.js";
import { localName } from "./exchangeAuditValues.js";
import { getCI, str, type MappedEvent } from "./siemImport.js";
import { SEVERITY_RANK, type Severity } from "./stateTypes.js";

type Row = Record<string, unknown>;

export const HIDE_PAIR_WINDOW_MS = 10 * 60_000;
export const NEW_USER_GRANT_WINDOW_MS = 24 * 60 * 60_000;
const DESCRIPTION_MAX = 600;

const RULE_OP = /inboxrule/i;
const ADD_USER_OP = /^add user\.?$/i;
const ROLE_OP = /^add (?:eligible )?member to role/i;

const opOf = (rec: Row): string => str(getCI(rec, "Operation") ?? getCI(rec, "activityDisplayName")).trim();

interface RuleFact {
  row: number;
  record: number;
  key: string;
  time: number;
  forwardsOut: boolean;
  hidesHard: boolean;
}
interface Grant {
  row: number;
  ids: string[];
  time: number;
  role: string;
}

function ruleFact(rec: Row, row: number, record: number, time: number): RuleFact | null {
  const c = decodeExchangeRecord(rec, record);
  if (!c || c.kind !== "rule" || c.attempted || c.polarity !== "adds") return null;
  if (!c.forwardsOutside && !c.hidesHard) return null;
  // One mailbox is written as an alias, an Exchange path or a UPN: key on its local name.
  const key = `${c.actor.toLowerCase()}|${localName(c.mailbox)}`;
  return { row, record, key, time, forwardsOut: c.forwardsOutside, hidesHard: c.hidesHard };
}

/** The pairing decisions: row index → the grade it is raised to and the clause that says why. */
type Raise = Map<number, { severity: Severity; why: string }>;

function pairHidingRules(rules: readonly RuleFact[], out: Raise): void {
  for (const hide of rules) {
    if (!hide.hidesHard) continue;
    const fwd = rules.find(
      (f) =>
        f.forwardsOut &&
        f.record !== hide.record &&
        f.key === hide.key &&
        Math.abs(f.time - hide.time) <= HIDE_PAIR_WINDOW_MS,
    );
    if (fwd)
      out.set(hide.row, {
        severity: "Critical",
        why: "hides mail; a forward-out rule by the same actor on this mailbox is within 10 minutes",
      });
  }
}

function pairNewUserGrants(
  created: ReadonlyMap<string, number[]>,
  grants: readonly Grant[],
  out: Raise,
): void {
  for (const g of grants) {
    const hit = g.ids.some((id) =>
      (created.get(id) ?? []).some((t) => g.time >= t && g.time - t <= NEW_USER_GRANT_WINDOW_MS),
    );
    if (hit && !out.has(g.row))
      out.set(g.row, {
        severity: "High",
        why: `${g.role} granted to a user created within 24 hours in this export`,
      });
  }
}

const identityKeys = (...v: string[]): string[] => v.map((x) => x.trim().toLowerCase()).filter(Boolean);

function readEntra(
  rec: Row,
  row: number,
  time: number,
  created: Map<string, number[]>,
  grants: Grant[],
): void {
  const r = readEntraAuditRecord(rec);
  if (!r || r.outcome !== "success") return;
  if (ADD_USER_OP.test(r.operation)) {
    const user = r.targets.find((t) => /user/i.test(t.type)) ?? r.targets[0];
    for (const k of identityKeys(user?.id ?? "", user?.upn ?? ""))
      created.set(k, [...(created.get(k) ?? []), time]);
    return;
  }
  for (const c of decodeEntraAppChanges(r)) {
    if (c.kind !== "role-assigned" || c.attempted || !c.role || c.role.tier === "other") continue;
    const member = r.targets.find((t) => t.id && t.id === c.role?.memberId);
    grants.push({
      row,
      ids: identityKeys(c.role.memberId, c.role.memberName, member?.upn ?? ""),
      time,
      role: c.role.name,
    });
  }
}

/**
 * Raise the rows of one export that a BEC pairing proves (see the header). `rowRecords[i]` is the
 * index in `records` of the record row `i` came from. Returns new rows; the input is not changed.
 */
export function applyBecPairing(
  rows: readonly MappedEvent[],
  rowRecords: readonly number[],
  records: readonly Row[],
): MappedEvent[] {
  const rules: RuleFact[] = [];
  const created = new Map<string, number[]>();
  const grants: Grant[] = [];
  rows.forEach((row, i) => {
    const record = rowRecords[i];
    const rec = record === undefined ? undefined : records[record];
    const time = Date.parse(row.timestamp);
    if (!rec || !Number.isFinite(time)) return;
    const op = opOf(rec);
    if (RULE_OP.test(op)) {
      const f = ruleFact(rec, i, record, time);
      if (f) rules.push(f);
    } else if (ADD_USER_OP.test(op) || ROLE_OP.test(op)) readEntra(rec, i, time, created, grants);
  });
  const raise: Raise = new Map();
  pairHidingRules(rules, raise);
  pairNewUserGrants(created, grants, raise);
  if (!raise.size) return [...rows];
  return rows.map((row, i) => {
    const r = raise.get(i);
    if (!r || SEVERITY_RANK[r.severity] >= SEVERITY_RANK[row.severity]) return row;
    const tail = ` [${r.why}]`;
    return {
      ...row,
      severity: r.severity,
      description: row.description.slice(0, DESCRIPTION_MAX - tail.length) + tail,
    };
  });
}
