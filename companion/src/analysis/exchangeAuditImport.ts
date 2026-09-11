// Exchange Online audit rows (#931 item 2) — the ingest half: the decoder's reading rendered with
// the reserved-budget description (the posture, the mailbox and the qualifiers survive the clip)
// and a canonical envelope keyed on ids, so nothing downstream re-parses prose to know which
// mailbox was reached, by whom, in which session.

import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { renderAwsDescription } from "./awsDescription.js";
import { decodeExchangeRecord } from "./exchangeAudit.js";
import {
  addIoc,
  cleanIp,
  getCI,
  normalizeTime,
  oneLine,
  str,
  type MappedEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

const WHO_MAX = 50;

/** True for a UAL record of the Exchange workload. */
export function isExchangeRecord(rec: Row): boolean {
  return /^exchange$/i.test(str(getCI(rec, "Workload")).trim());
}

/**
 * Map one Exchange record to its row, or null when the decoder does not narrate the operation
 * (the caller keeps the plain row). `index` is the record's position in the file — the locator.
 */
export function mapExchangeRow(rec: Row, sink: Map<string, SiemIoc>, index: number): MappedEvent | null {
  const c = decodeExchangeRecord(rec, index);
  if (!c) return null;
  const ip = cleanIp(c.ip);
  if (ip) addIoc(sink, "ip", ip);
  const who = oneLine(c.actor).slice(0, WHO_MAX);
  const head = `M365 Exchange: ${c.operation}${who ? ` by ${who}` : ""}${ip ? ` from ${ip}` : ""}`;
  const outcome = c.attempted ? (c.outcome === "failure" ? "failed" : "result unknown") : "";
  const description = renderAwsDescription({
    head,
    posture: c.posture,
    outcome,
    object: c.object,
    optional: [c.words],
    tail: "",
    qualifiers: c.qualifiers,
  });
  const observed = c.time;
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: c.severity,
    mitre: [...c.mitre],
    aggKey: boundedAggKey(c.key),
    sources: ["Microsoft 365"],
    canonical: createCanonicalEvent({
      event: { category: "email", type: c.kind, action: c.operation, outcome: c.outcome },
      ...(c.actor
        ? {
            actor: c.actorIsApp
              ? { kind: "cloud_principal", ...(c.appId ? { id: c.appId } : {}), name: c.actor }
              : { kind: "account", name: c.actor },
          }
        : {}),
      ...(c.mailbox || c.mailboxId
        ? {
            object: {
              kind: "mailbox",
              ...(c.mailboxId ? { id: c.mailboxId } : {}),
              ...(c.mailbox ? { name: c.mailbox } : {}),
            },
          }
        : {}),
      ...(c.target ? { target: { kind: "other", name: c.target.slice(0, 200) } } : {}),
      ...(ip ? { network: { source: { address: ip } } } : {}),
      cloud: {
        provider: "m365",
        ...(c.tenant ? { tenant: c.tenant } : {}),
        ...(c.appId ? { principalId: c.appId } : {}),
        principalType: c.actorIsApp ? "application" : "user",
      },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: {
        rawRecords: [
          { source: "m365-ual", locator: `record:${index}`, ...(c.recordId ? { recordId: c.recordId } : {}) },
        ],
      },
      producer: {
        importer: "m365-audit",
        parserVersion: "1",
        mappingVersion: "m365-ual-exchange-v1",
        ruleVersions: ["exchange-audit-v1"],
      },
      rawFieldMap: {
        "event.action": ["Operation"],
        "event.outcome": ["ResultStatus"],
        "time.observed": ["CreationTime"],
        ...(c.actor ? { "actor.name": ["UserId"] } : {}),
        ...(c.mailbox ? { "object.name": ["MailboxOwnerUPN", "ObjectId"] } : {}),
        ...(ip ? { "network.source.address": ["ClientIPAddress", "ClientIP"] } : {}),
      },
    }),
  };
}
