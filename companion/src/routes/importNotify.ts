import type { RouteContext } from "./context.js";
import { notifyImport, trackImportOutcome, type ImportCounts } from "../analysis/importNotification.js";

// The route side of "import finished" notifications (#2978): one tracker per import attempt, sending
// through the case notifier and logging through the server logger. analysis/importNotification.ts
// says why each import path reports its own outcome.
export function trackRouteImport(
  ctx: Pick<RouteContext, "dispatchNotify" | "serverLogger">,
  caseId: string,
  source: string,
): ReturnType<typeof trackImportOutcome> {
  return trackImportOutcome(ctx.dispatchNotify, caseId, source, (line) => ctx.serverLogger.info(line));
}

/** A cloud collection's gaps — windows it could not read and files it quarantined — as failed items. */
export function collectionGaps(cp: {
  missing: readonly { source: string; reason: string }[];
  quarantined: readonly { file: string; reason: string }[];
}): { failed?: { name: string; reason: string }[] } {
  const failed = [
    ...cp.missing.map((m) => ({ name: `${m.source} window`, reason: m.reason })),
    ...cp.quarantined.map((q) => ({ name: q.file, reason: `quarantined (${q.reason})` })),
  ];
  return failed.length ? { failed } : {};
}

/**
 * A CrowdStrike NG-SIEM search's message. A search that returned nothing added nothing — a known
 * zero — and one cut short by the row cap or the timeout says so as a failed item.
 */
export function notifySiemSearch(
  ctx: Pick<RouteContext, "dispatchNotify" | "serverLogger">,
  spec: { caseId: string; title: string },
  outcome: { failed?: string; truncated: boolean; error?: string; counts?: ImportCounts },
): void {
  const source = `CrowdStrike NG-SIEM search: ${spec.title}`;
  const failed = outcome.truncated
    ? [{ name: "search result", reason: outcome.error ?? "cut short by the row cap or the timeout" }]
    : [];
  notifyImport(
    ctx.dispatchNotify,
    outcome.failed
      ? { caseId: spec.caseId, source, ok: false, reason: outcome.failed }
      : {
          caseId: spec.caseId,
          source,
          ok: true,
          counts: outcome.counts ?? { added: 0, highCritical: 0 },
          ...(failed.length ? { failed } : {}),
        },
    (line) => ctx.serverLogger.info(line),
  );
}
