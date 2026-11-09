// The cloud importers as the streaming import sees them (#2303; GuardDuty findings #2361): how to prepare a batch of
// raw records, identify each one for dedup, map the batch with the importer's own parse function
// (`rowsOnly`, so nothing is aggregated or capped there), read each record's rule / actor / address
// for the output budget, and build the whole-export summaries over the bounded summary window.
//
// Each importer's mapping, severity, Sigma grading and coverage code is the one the whole-file path
// runs — nothing is re-implemented here, only adapted to batches. The two whole-file lookups the
// M365 importer needs (the object-id → app-id resolver that lets a consent record name its API, and
// the mailbox-audit date order) are learned by a preliminary pass over the whole file first.

import type { MappedEvent, SiemEvent, SiemIoc } from "../siemImport.js";
import { getCI, getPath, str } from "../siemFieldPick.js";
import type { CloudCoverageDraft } from "../cloudCoverage.js";
import type { CloudRecordIdentity } from "../cloudRecordIdentity.js";
import { cloudActivityRecordProvider, cloudRecordIdentity } from "../cloudRecordIdentity.js";
import type { RecordGate } from "../cloudRecordGate.js";
import type { SigmaGradingSnapshot } from "../sigmaImportGrade.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import type { RowFacts } from "../cloudOutputBudget.js";
import type { StoredAuthObservation } from "../authObservationStore.js";
import { m365RecordIdentities, normalizeRecord, parseM365Audit } from "../m365Import.js";
import {
  adaptM365ExportRow,
  createMailboxDateOrderLearner,
  type UndatedRows,
} from "../m365ExportAdapters.js";
import { createApiResolverLearner, type Resolver } from "../entraAuditImport.js";
import { cloudTrailSummaries, parseCloudTrail } from "../awsImport.js";
import { cloudTrailConsoleRow } from "../cloudRecords.js";
import { parseCloudActivity } from "../cloudActivityImport.js";
import { guardDutyRemoteIp, parseGuardDuty, GUARDDUTY_SOURCE } from "../guardDutyImport.js";
import { unwrapGuardDutyRecords } from "../guardDutyRecord.js";
import type { SummaryScope } from "../summaryScope.js";

type Row = Record<string, unknown>;

export type StreamKind = "m365" | "aws" | "cloud" | "guardduty"; // the import kinds (importIngest.ts dispatch)

export interface BatchMapping {
  mapped: MappedEvent[];
  rowRecords: number[];
  iocs: SiemIoc[];
  coverage: CloudCoverageDraft[];
  format: string;
  sigmaRows: number;
  signInObservations: Array<Omit<StoredAuthObservation, "importBatch">>;
}

export interface BatchContext {
  gate?: RecordGate;
  base: number;
  sigma?: SigmaGradingSnapshot;
  debug?: ImportDebugRecorder;
}

/** What the preliminary pass learned over the whole file (M365 only; the others need none). */
export interface Preliminary {
  resolver?: Resolver;
  dateOrder?: ReturnType<ReturnType<typeof createMailboxDateOrderLearner>["finish"]>;
}

export interface StreamProvider {
  kind: StreamKind;
  /** The note's and the events' source name. */
  source: string;
  /** CSV row adapter for the reader (the CloudTrail console CSV). */
  csvAdapt?: (row: Row) => Row;
  /** A preliminary pass, when the importer has whole-file lookups. */
  preliminary?: () => { add(raw: Row[]): void; finish(): Preliminary };
  prepare(raw: Row[], pre: Preliminary): Row[];
  identities(records: Row[]): CloudRecordIdentity[];
  map(records: Row[], ctx: BatchContext, pre: Preliminary): BatchMapping;
  facts(rec: Row): RowFacts;
  /** The whole-export summary rows over the summary window (fresh records, duplicates blanked). */
  summaries(window: Row[], pre: Preliminary): SiemEvent[];
  /**
   * The whole-export summaries over a live collection's window — every page of one run, in page
   * order (#2482, cloudCollectionSummary.ts). A provider that has it summarizes once per collection:
   * its collection pages skip `summaries` (and M365 pages their spray rows, #2493).
   */
  collectionSummaries?(window: Row[], scope: SummaryScope, pre: Preliminary): SiemEvent[];
  undated?(pre: Preliminary): UndatedRows | undefined;
}

const pick = (rec: Row, keys: string[]): string => {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(rec, k) : getCI(rec, k);
    const s = str(Array.isArray(v) ? v[0] : v).trim();
    if (s) return s;
  }
  return "";
};
/** CloudTrail's readOnly flag: a JSON boolean, or "true" in a console CSV / stringified export. */
const isReadOnly = (v: unknown): boolean => v === true || /^true$/i.test(str(v).trim());
const firstIp = (raw: string): string =>
  /(\d{1,3}(?:\.\d{1,3}){3})/.exec(raw)?.[1] ?? raw.replace(/^\[|\]:\d+$/g, "");

const asMapping = (r: {
  mapped?: MappedEvent[];
  rowRecords?: number[];
  iocs: SiemIoc[];
  coverage: CloudCoverageDraft[];
  format: string;
  sigmaRowsMatched?: number;
}): Omit<BatchMapping, "signInObservations"> => ({
  mapped: r.mapped ?? [],
  rowRecords: r.rowRecords ?? [],
  iocs: r.iocs,
  coverage: r.coverage,
  format: r.format,
  sigmaRows: r.sigmaRowsMatched ?? 0,
});

const m365: StreamProvider = {
  kind: "m365",
  source: "Microsoft 365",
  preliminary() {
    const resolver = createApiResolverLearner();
    const order = createMailboxDateOrderLearner();
    return {
      add(raw) {
        order.add(raw);
        resolver.add(raw.map((r) => normalizeRecord(adaptM365ExportRow(r, null))));
      },
      finish: () => ({ resolver: resolver.finish(), dateOrder: order.finish() }),
    };
  },
  prepare: (raw, pre) => raw.map((r) => normalizeRecord(adaptM365ExportRow(r, pre.dateOrder?.order ?? null))),
  identities: (records) => m365RecordIdentities(records),
  map(records, ctx, pre) {
    const r = parseM365Audit("", {
      prepared: { normalized: records, undated: { rows: 0, mixedOrders: false } },
      recordGate: ctx.gate,
      recordIndexBase: ctx.base,
      resolver: pre.resolver,
      sigma: ctx.sigma,
      debug: ctx.debug,
      rowsOnly: true,
    });
    return { ...asMapping(r), signInObservations: r.signInObservations };
  },
  facts: (rec) => ({
    rule:
      pick(rec, ["Operation", "Operations", "activityDisplayName"]) ||
      (getCI(rec, "userPrincipalName") ? "sign-in" : "record"),
    actor: pick(rec, [
      "UserId",
      "UserKey",
      "UserIds",
      "userPrincipalName",
      "initiatedBy.user.userPrincipalName",
    ]),
    ip: firstIp(pick(rec, ["ClientIP", "ClientIPAddress", "ActorIpAddress", "ipAddress"])),
  }),
  summaries(window, pre) {
    const r = parseM365Audit("", {
      prepared: { normalized: window, undated: { rows: 0, mixedOrders: false } },
      resolver: pre.resolver,
      spraySummary: false, // the streaming import reads spray from the sign-in store instead
    });
    return r.events.slice(r.kept);
  },
  // A collection's privilege paths and mailbox chains: one per collection run, not one per page (#2493);
  // its spray is read from the sign-in store over all of the run's pages (cloudStreamSpray.ts).
  collectionSummaries(window, scope, pre) {
    const r = parseM365Audit("", {
      prepared: { normalized: window, undated: { rows: 0, mixedOrders: false } },
      resolver: pre.resolver,
      spraySummary: false,
      scope,
    });
    return r.events.slice(r.kept);
  },
  undated: (pre) => pre.dateOrder?.undated,
};

const aws: StreamProvider = {
  kind: "aws",
  source: "AWS CloudTrail",
  csvAdapt: cloudTrailConsoleRow,
  prepare: (raw) => raw,
  identities: (records) => records.map((rec) => cloudRecordIdentity("cloudtrail", rec)),
  map(records, ctx) {
    const r = parseCloudTrail("", {
      records,
      recordGate: ctx.gate,
      recordIndexBase: ctx.base,
      sigma: ctx.sigma,
      debug: ctx.debug,
      rowsOnly: true,
    });
    return { ...asMapping(r), signInObservations: [] };
  },
  facts: (rec) => ({
    rule: `${pick(rec, ["eventSource"])}:${pick(rec, ["eventName"])}`,
    actor: pick(rec, [
      "userIdentity.arn",
      "userIdentity.principalId",
      "userIdentity.userName",
      "userIdentity.accessKeyId",
    ]),
    ip: pick(rec, ["sourceIPAddress"]),
    // A failed read (#2481): the console CSV adapter maps "Read-only" / "Error code" to these fields.
    failedRead: isReadOnly(getCI(rec, "readOnly")) && pick(rec, ["errorCode"]) !== "",
  }),
  // The lineage and compute summaries read the raw window only (#2362): no re-mapping.
  summaries: (window) => cloudTrailSummaries(window),
  // A collection's lineage and compute lifecycles: one per collection run, not one per page (#2482).
  collectionSummaries: (window, scope) => cloudTrailSummaries(window, scope),
};

const cloudActivity: StreamProvider = {
  kind: "cloud",
  source: "Cloud Audit",
  prepare: (raw) => raw,
  identities: (records) => records.map((rec) => cloudRecordIdentity(cloudActivityRecordProvider(rec), rec)),
  map(records, ctx) {
    const r = parseCloudActivity("", {
      records,
      recordGate: ctx.gate,
      recordIndexBase: ctx.base,
      // GCP records only — the importer grades no Azure Activity record with Sigma (#2346).
      sigma: ctx.sigma,
      debug: ctx.debug,
      rowsOnly: true,
    });
    return { ...asMapping(r), signInObservations: [] };
  },
  facts: (rec) => ({
    rule: pick(rec, ["protoPayload.methodName", "operationName.value", "operationName"]),
    actor: pick(rec, ["protoPayload.authenticationInfo.principalEmail", "caller", "identity.claims.name"]),
    ip: pick(rec, [
      "protoPayload.requestMetadata.callerIp",
      "callerIpAddress",
      "httpRequest.clientIpAddress",
    ]),
  }),
  summaries(window) {
    const r = parseCloudActivity("", { records: window });
    return r.events.slice(r.kept);
  },
  // A collection's service-account joins and compute lifecycles: one per collection run (#2493).
  collectionSummaries(window, scope) {
    const r = parseCloudActivity("", { records: window, scope });
    return r.events.slice(r.kept);
  },
};

// GuardDuty findings (#2361): a large or gzipped export, and every page the live collector saved.
// `prepare` unwraps a {"Findings":[...]} document the scanner handed over whole (JSON lines of CLI
// outputs); the importer has no whole-export summaries.
const guardDuty: StreamProvider = {
  kind: "guardduty",
  source: GUARDDUTY_SOURCE,
  prepare: (raw) => unwrapGuardDutyRecords(raw),
  identities: (records) => records.map((rec) => cloudRecordIdentity("guardduty", rec)),
  map(records, ctx) {
    const r = parseGuardDuty("", {
      records,
      recordGate: ctx.gate,
      recordIndexBase: ctx.base,
      debug: ctx.debug,
      rowsOnly: true,
    });
    return { ...asMapping(r), signInObservations: [] };
  },
  facts: (rec) => ({
    rule: pick(rec, ["Type"]),
    actor: pick(rec, ["Resource.AccessKeyDetails.UserName", "Resource.AccessKeyDetails.PrincipalId"]),
    ip: guardDutyRemoteIp(rec),
  }),
  summaries: () => [],
};

const PROVIDERS: Record<StreamKind, StreamProvider> = {
  m365,
  aws,
  cloud: cloudActivity,
  guardduty: guardDuty,
};

/** The import kinds that stream (the route dispatches only these). */
export const STREAM_KINDS: readonly StreamKind[] = ["m365", "aws", "cloud", "guardduty"];

export function isStreamKind(kind: string): kind is StreamKind {
  return (STREAM_KINDS as readonly string[]).includes(kind);
}

export function streamProvider(kind: StreamKind): StreamProvider {
  return PROVIDERS[kind];
}

/** Whether a collection builds this kind's whole-export summaries once, over all its pages (#2482). */
export function summarizesPerCollection(kind: StreamKind): boolean {
  return !!PROVIDERS[kind].collectionSummaries;
}
