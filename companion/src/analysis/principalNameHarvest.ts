// What a cloud record teaches the principal-name ledger (#2490, principalNames.ts). Read from the
// RECORD, before any grade, aggregation or duplicate gate: a service-principal sign-in graded Info
// never reaches the forensic timeline, and a re-uploaded record the case already holds maps to no
// event, but both still state the pair.
//
// Only records that state an id → name pair by construction:
//   - an Entra service-principal sign-in: `servicePrincipalId` and `appId` both carry
//     `servicePrincipalName` (else `appDisplayName`). Read from the raw fields, not readSpSignIn's
//     `name`, which is cut at 50 characters for the row — a cut name could hide a conflict;
//   - an Entra directory audit in the Graph shape: an app initiator (`servicePrincipalId`, `appId` →
//     `displayName`) and every target of type ServicePrincipal (`id` → `displayName`).
// The UAL shape is skipped: its Actor list spreads one identity over several entries, and the entry
// carrying a name need not be the one carrying the id.

import { isServicePrincipalSignIn } from "./entraAuditImport.js";
import { readEntraAuditRecord } from "./entraAuditRecord.js";
import { mergePrincipalNames, principalPair, type PrincipalNameRecord } from "./principalNames.js";
import { getCI, isObject, str } from "./siemImport.js";

type Row = Record<string, unknown>;

function pairs(rec: Row): Array<PrincipalNameRecord | null> {
  if (isServicePrincipalSignIn(rec)) {
    const name = str(getCI(rec, "servicePrincipalName")) || str(getCI(rec, "appDisplayName"));
    return [str(getCI(rec, "servicePrincipalId")), str(getCI(rec, "appId"))].map((id) =>
      principalPair(id, name),
    );
  }
  if (getCI(rec, "activityDisplayName") === undefined) return [];
  const audit = readEntraAuditRecord(rec);
  if (!audit || audit.shape !== "graph") return [];
  const out: Array<PrincipalNameRecord | null> = [];
  const by = getCI(rec, "initiatedBy");
  const app = isObject(by) ? getCI(by, "app") : undefined;
  if (audit.initiator.kind === "app" && isObject(app)) {
    const name = str(getCI(app, "displayName"));
    out.push(principalPair(audit.initiator.id, name), principalPair(audit.initiator.appId, name));
  }
  for (const t of audit.targets)
    if (/^serviceprincipal$/i.test(t.type)) out.push(principalPair(t.id, t.name));
  return out;
}

/** Every id → name pair the records state, merged (a second name for an id is kept as a conflict). */
export function principalNamesFromRecords(records: readonly Row[]): PrincipalNameRecord[] {
  const found: PrincipalNameRecord[] = [];
  for (const rec of records) {
    if (!isObject(rec)) continue;
    for (const p of pairs(rec)) if (p) found.push(p);
  }
  return found.length ? mergePrincipalNames([], found) : [];
}
