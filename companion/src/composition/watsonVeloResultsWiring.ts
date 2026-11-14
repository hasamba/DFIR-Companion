import { newWatsonId } from "../analysis/ai/watson/roundProposals.js";
import type { WatsonPaste, WatsonVeloLaunchProposal } from "../analysis/ai/watson/types.js";
import { fillOutcomeByFlow } from "../analysis/huntOutcomes.js";
import {
  sanitizeVqlDurations,
  splitVqlStatements,
  type VelociraptorClient,
} from "../integrations/velociraptor/velociraptorApi.js";
import type { RouteContext } from "../routes/context.js";
import { frozenCaseRefusal } from "../routes/importCaseGuard.js";
import { resolveCaseVelo } from "../routes/veloServers.js";
import { ingestWatsonPaste } from "../routes/watsonPasteIngest.js";
import { warnLine } from "../logging/serverLogger.js";
import { WatsonFlowWatcher, type WatsonFlowRows, type WatsonIngested } from "./watsonVeloResults.js";

// The app's one Watson result watcher, built on the route context: the case's existing Velociraptor
// client (resolveCaseVelo, never a new connection), the chat-paste ingest (routes/watsonPasteIngest.ts:
// held tagger promotions, no synthesis, conclusions marked out of date), and the hunt-outcome ledger.

/** Host columns the Velociraptor importer reads; a row with none gets the collection's host. */
const HOST_KEYS = ["Fqdn", "Hostname", "Computer", "ComputerName", "Host", "ClientName"];

const stampHost = (row: unknown, host: string): unknown => {
  if (!host || !row || typeof row !== "object" || Array.isArray(row)) return row;
  const rec = row as Record<string, unknown>;
  return HOST_KEYS.some((k) => rec[k] !== undefined && rec[k] !== "") ? row : { ...rec, Fqdn: host };
};

/**
 * Every row of a finished Watson collection, as the artifact-map JSON the fleet collect writes.
 * The launched record keeps no artifact name, so it is read back from the flow; an unqualified
 * artifact is read through every source the launch created (Pivot0…, one per VQL statement), since
 * an artifact with only named sources reads EMPTY by its bare name (artifactRefs.ts).
 */
export async function readWatsonFlowRows(
  client: Pick<VelociraptorClient, "getFlowInfo" | "collectionResults">,
  p: WatsonVeloLaunchProposal,
): Promise<WatsonFlowRows> {
  const { flowId = "", clientId = "" } = p.launched ?? {};
  const info = await client.getFlowInfo(clientId, flowId);
  const pivots = splitVqlStatements(sanitizeVqlDurations(p.vql)).map((_, i) => `Pivot${i}`);
  const host = p.hostname ?? info.hostname;
  const map: Record<string, unknown[]> = {};
  let rows = 0;
  let truncated = false;
  for (const artifact of info.artifacts) {
    const sources = artifact.includes("/") ? [] : pivots;
    const read = await client.collectionResults(clientId, flowId, artifact, sources, undefined, true);
    map[artifact] = read.rows.map((r) => stampHost(r, host));
    rows += read.rows.length;
    truncated = truncated || read.truncated;
  }
  return { text: JSON.stringify(map), rows, ...(truncated ? { truncated: true as const } : {}) };
}

const countLines = (text: string): number => (text ? text.split("\n").length : 0);

/** Store the rows as case evidence (like a chat paste), ingest them, and log the import. */
async function ingestFlowRows(
  ctx: RouteContext,
  caseId: string,
  p: WatsonVeloLaunchProposal,
  rows: WatsonFlowRows,
): Promise<WatsonIngested> {
  const { store } = ctx;
  const filename = `velo-flow_${p.launched?.flowId ?? "unknown"}.json`;
  const seq = await store.nextImportSeq(caseId);
  const storedName = `${String(seq).padStart(4, "0")}_${filename}`;
  const at = new Date().toISOString();
  const bytes = Buffer.byteLength(rows.text, "utf8");
  await store.saveImport(caseId, storedName, rows.text, {
    source: "watson-velociraptor",
    trigger: "watson-collection",
    collectedBy: "Watson",
  });
  const paste: WatsonPaste = {
    id: newWatsonId("wf"),
    storedName,
    filename,
    bytes,
    lines: countLines(rows.text),
    at,
  };
  const ingest = await ingestWatsonPaste(ctx, caseId, paste, rows.text);
  await store.appendImport(caseId, {
    caseId,
    sequenceNumber: seq,
    importedAt: at,
    filename: storedName,
    originalName: filename,
    rows: "reason" in ingest ? 0 : ingest.rows,
    bytes,
  });
  return { paste, ingest };
}

/** The app's watcher; undefined without a Watson chat store. */
export function createAppWatsonFlowWatcher(
  ctx: RouteContext,
  wake: (caseId: string) => void,
): WatsonFlowWatcher | undefined {
  const { options, store } = ctx;
  const chatStore = options.watsonChatStore;
  if (!chatStore) return undefined;
  const client = (caseId: string): VelociraptorClient | null => {
    const t = resolveCaseVelo(ctx, caseId);
    return t.ok ? t.vc.client : null;
  };
  return new WatsonFlowWatcher({
    chatStore,
    velo: client,
    readRows: async (caseId, p) => {
      const c = client(caseId);
      if (!c) throw new Error("the case no longer has a Velociraptor server");
      return readWatsonFlowRows(c, p);
    },
    ingest: (caseId, p, rows) => ingestFlowRows(ctx, caseId, p, rows),
    fillOutcome: async (caseId, ref, result) => {
      const outcomes = options.huntOutcomeStore;
      if (!outcomes) return;
      await outcomes.save(caseId, fillOutcomeByFlow(await outcomes.load(caseId), ref, result));
      options.onVeloHunt?.(caseId);
    },
    isFrozen: async (caseId) => (await frozenCaseRefusal(store, caseId)) !== null,
    wake,
    onChanged: (caseId) => options.onWatson?.(caseId),
    log: warnLine,
  });
}
