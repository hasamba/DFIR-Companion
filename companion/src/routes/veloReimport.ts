// Re-importing a Velociraptor hunt or flow (#2700): read only the artifacts that are new, changed or
// were not read in full last time, instead of every artifact of the hunt.
//
// The import-external route asks this gate before it reads any row. The gate reads the artifact list
// and one metadata query (veloArtifactFingerprint.ts), never rows, then compares each artifact with
// the case's ledger (veloImportLedger.ts):
//   - `reimport` absent and the case already holds this source → 409 with the plan: which artifacts
//     need importing and why, which are up to date. A failed lookup still answers the 409, never a 502.
//   - `reimport: "changed"` → import only the plan's artifacts; the plan is recomputed here, never
//     taken from the client. Nothing to import → 200 with no job.
//   - `reimport: true` → every artifact, as before (the analyst's "Re-read everything").
// Every run records each artifact it touches: `pending` before its read, the outcome after.
// Anything unknown plans as "import it" — this can cause extra reading, never a skipped artifact.

import type { ArtifactFingerprint, FlowMeta } from "../integrations/velociraptor/veloArtifactFingerprint.js";
import { fingerprintArtifacts } from "../integrations/velociraptor/veloArtifactFingerprint.js";
import type { ArtifactDone, ArtifactHooks } from "./veloExternalImportJob.js";
import {
  clearVeloImportLedger,
  readVeloLedger,
  recordVeloArtifact,
  veloLedgerKey,
  type LedgerEntry,
  type LedgerRef,
  type LedgerStore,
} from "./veloImportLedger.js";
import { priorVeloImport, type PriorVeloImport } from "./veloPriorImport.js";

export type ReimportReason =
  "no-record" | "failed" | "truncated" | "unread" | "settings" | "unknown" | "live" | "changed";

export interface ReimportPlan {
  toImport: { name: string; reason: ReimportReason }[];
  upToDate: string[];
}

/** What a run imports with; a change of either means the earlier rows landed somewhere else. */
export interface ImportSettings {
  superOnly: boolean;
  minSeverity: string;
}

function reasonFor(
  e: LedgerEntry | undefined,
  fp: ArtifactFingerprint | undefined,
  s: ImportSettings,
): ReimportReason | null {
  if (!e) return "no-record";
  if (e.status === "pending" || e.status === "failed") return "failed";
  if (e.status === "partial") return e.gaps?.[0] ?? "truncated";
  if (e.superOnly !== s.superOnly || e.minSeverity !== s.minSeverity) return "settings";
  if (!fp || !e.fingerprint) return "unknown";
  if (fp.live) return "live";
  return fp.hash === e.fingerprint ? null : "changed";
}

/** Per artifact: import it (and why) or skip it as up to date. */
export function planVeloReimport(
  entries: Record<string, LedgerEntry>,
  artifacts: readonly string[],
  fps: Record<string, ArtifactFingerprint> | undefined,
  settings: ImportSettings,
): ReimportPlan {
  const plan: ReimportPlan = { toImport: [], upToDate: [] };
  for (const name of artifacts) {
    const reason = reasonFor(entries[name], fps?.[name], settings);
    if (reason) plan.toImport.push({ name, reason });
    else plan.upToDate.push(name);
  }
  return plan;
}

type EntryBody = Pick<LedgerEntry, "status" | "rows" | "gaps">;

/**
 * The hooks a run records through. They never throw: a failed ledger write deletes the whole ledger
 * (so nothing it held can claim "up to date") and logs once; the import itself carries on.
 */
export function ledgerTracker(
  store: LedgerStore,
  caseId: string,
  key: string,
  fps: Record<string, ArtifactFingerprint> | undefined,
  settings: ImportSettings,
  logLine: (msg: string) => void,
): ArtifactHooks {
  let broken = false;
  const write = async (artifact: string, body: EntryBody): Promise<void> => {
    if (broken) return;
    const fingerprint = fps?.[artifact]?.hash;
    const entry: LedgerEntry = {
      importedAt: new Date().toISOString(),
      ...body,
      ...(fingerprint ? { fingerprint } : {}),
      ...settings,
    };
    try {
      await recordVeloArtifact(store, caseId, key, artifact, entry);
    } catch (err) {
      broken = true;
      logLine(`[velociraptor] re-import ledger write failed (${(err as Error).message}); forgetting it`);
      await clearVeloImportLedger(store, caseId).catch((e2: Error) =>
        logLine(`[velociraptor] re-import ledger could not be cleared either: ${e2.message}`),
      );
    }
  };
  return {
    onStart: (artifact) => write(artifact, { status: "pending", rows: 0 }),
    onDone: (artifact, d: ArtifactDone) => {
      // An empty read of an artifact the server lists results for is a read that failed quietly.
      const emptyButListed = d.status === "complete" && d.rows === 0 && fps?.[artifact]?.listed === true;
      const status = emptyButListed ? "failed" : d.status;
      return write(artifact, { status, rows: d.rows, ...(d.gaps?.length ? { gaps: d.gaps } : {}) });
    },
  };
}

export interface ReimportClient {
  sourceNamespace(): string;
  huntFlowMeta(huntId: string): Promise<FlowMeta[] | undefined>;
  flowMeta(clientId: string, flowId: string): Promise<FlowMeta[] | undefined>;
}

export interface ReimportGateInput<T> {
  store: LedgerStore & { importsLogPath(caseId: string): string };
  caseId: string;
  ref: LedgerRef;
  reimport: unknown;
  settings: ImportSettings;
  client: ReimportClient;
  /** The artifact lookup the route makes anyway (the hunt's list, or the flow's info). */
  list: () => Promise<T>;
  namesOf: (listed: T) => string[];
  /** The response identity fields (kind, ids, hostname) for the nothing-to-import answer. */
  identity: (listed: T) => Record<string, unknown>;
  /** The 404 error when the lookup finds no artifacts. */
  notFound: string;
  logLine: (msg: string) => void;
}

export type ReimportGate<T> =
  | { answer: { status: number; body: unknown } }
  | {
      listed: T;
      requested: string[];
      artifacts: string[];
      extra: { upToDate?: string[] };
      hooks: ArtifactHooks;
    };

/** The audit log's prior import, widened by what the ledger knows (it can hold sources the log does not). */
function priorOf(
  audit: PriorVeloImport | null,
  entries: Record<string, LedgerEntry>,
  ref: LedgerRef,
): PriorVeloImport {
  const dates = [
    audit?.firstImportedAt,
    audit?.lastImportedAt,
    ...Object.values(entries).map((e) => e.importedAt),
  ]
    .filter((d): d is string => !!d)
    .sort();
  const artifacts = [...new Set([...(audit?.artifacts ?? []), ...Object.keys(entries)])].sort();
  return {
    ...ref,
    firstImportedAt: dates[0] ?? "",
    lastImportedAt: dates[dates.length - 1] ?? "",
    artifacts,
  };
}

async function safely<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

function readMeta(client: ReimportClient, ref: LedgerRef): Promise<FlowMeta[] | undefined> {
  return ref.kind === "hunt" ? client.huntFlowMeta(ref.huntId) : client.flowMeta(ref.clientId, ref.flowId);
}

export async function veloReimportGate<T>(i: ReimportGateInput<T>): Promise<ReimportGate<T>> {
  const mode = i.reimport === true ? "all" : i.reimport === "changed" ? "changed" : "check";
  const key = veloLedgerKey(await safely(async () => i.client.sourceNamespace(), "default"), i.ref);
  const entries = await safely(() => readVeloLedger(i.store, i.caseId, key), {});
  const audit = mode === "check" ? await priorVeloImport(i.store, i.caseId, i.ref) : null;
  const known = mode === "check" && (audit !== null || Object.keys(entries).length > 0);
  let listed: T;
  try {
    listed = await i.list();
  } catch (err) {
    if (known) return { answer: { status: 409, body: { alreadyImported: priorOf(audit, entries, i.ref) } } };
    throw err;
  }
  const requested = i.namesOf(listed);
  if (!requested.length) return { answer: { status: 404, body: { error: i.notFound } } };
  const meta = await safely(() => readMeta(i.client, i.ref), undefined);
  if (!meta)
    i.logLine(
      "[velociraptor] re-import: the server's collection state is unknown; every artifact counts as changed",
    );
  const fps = fingerprintArtifacts(meta, requested);
  const plan = planVeloReimport(entries, requested, fps, i.settings);
  if (known) {
    return {
      answer: {
        status: 409,
        body: { alreadyImported: { ...priorOf(audit, entries, i.ref), requested, ...plan } },
      },
    };
  }
  const hooks = ledgerTracker(i.store, i.caseId, key, fps, i.settings, i.logLine);
  if (mode !== "changed") return { listed, requested, artifacts: requested, extra: {}, hooks };
  const artifacts = plan.toImport.map((t) => t.name);
  if (artifacts.length) return { listed, requested, artifacts, extra: { upToDate: plan.upToDate }, hooks };
  const body = {
    ...i.identity(listed),
    addedEvents: 0,
    addedIocs: 0,
    artifacts: [],
    requestedArtifacts: requested,
    superTimelineOnly: i.settings.superOnly,
    upToDate: plan.upToDate,
    note: `all ${requested.length} artifact(s) are up to date — nothing to import`,
  };
  return { answer: { status: 200, body } };
}

/** The route's side of the gate: what every import-external request carries. */
export interface RouteGateBase {
  store: ReimportGateInput<unknown>["store"];
  caseId: string;
  reimport: unknown;
  superOnly: boolean;
  minSeverity?: string;
  logLine: (msg: string) => void;
}

export interface ListingClient extends ReimportClient {
  getHuntArtifacts(huntId: string): Promise<string[]>;
  getFlowInfo(clientId: string, flowId: string): Promise<{ artifacts: string[]; hostname: string }>;
}

const baseOf = (b: RouteGateBase, client: ListingClient) => ({
  store: b.store,
  caseId: b.caseId,
  reimport: b.reimport,
  settings: { superOnly: b.superOnly, minSeverity: String(b.minSeverity ?? "") },
  client,
  logLine: b.logLine,
});

/** A hunt's gate: its requested artifacts are the list. */
export function huntReimportGate(
  b: RouteGateBase,
  client: ListingClient,
  ref: { kind: "hunt"; huntId: string },
): Promise<ReimportGate<string[]>> {
  return veloReimportGate({
    ...baseOf(b, client),
    ref: { kind: "hunt", huntId: ref.huntId },
    list: () => client.getHuntArtifacts(ref.huntId),
    namesOf: (a) => a,
    identity: () => ({ kind: "hunt", huntId: ref.huntId }),
    notFound: `hunt ${ref.huntId} not found on the server, or it collected no artifacts`,
  });
}

/** A flow's gate: the flow info gives the artifacts and the host. */
export function flowReimportGate(
  b: RouteGateBase,
  client: ListingClient,
  ref: { kind: "flow"; clientId: string; flowId: string },
): Promise<ReimportGate<{ artifacts: string[]; hostname: string }>> {
  const { clientId, flowId } = ref;
  return veloReimportGate({
    ...baseOf(b, client),
    ref: { kind: "flow", clientId, flowId },
    list: () => client.getFlowInfo(clientId, flowId),
    namesOf: (i) => i.artifacts,
    identity: (i) => ({ kind: "flow", clientId, flowId, hostname: i.hostname }),
    notFound: `flow ${flowId} on ${clientId} not found, or it collected no artifacts`,
  });
}
