import type { Express, Request, Response } from "express";
import { clientGone, requestAbortSignal } from "../http/requestAbort.js";
import { caseOpenState } from "./caseOpenState.js";
import { buildTlsCaseGraph, tlsCaseGraphReads } from "../analysis/tlsCaseGraph.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * The TLS relationship graph across every upload and sensor in the case (#997, cross-upload half).
 *   - GET /cases/:id/tls-graph
 *
 * READS forensic ∪ super-timeline: every TLS-graph row is Info, so after the demote it lives in the
 * super-timeline. This is a plain analyst-facing read with no AI synthesis in its call graph — the
 * same recipe routes/resolverEndpointIdentity.ts (#1243) and threatIntel.ts's ioc-provenance routes
 * use, not the AI-boundary promotion pattern viewSummary needs. Recomputed on every call, never
 * persisted; nothing here contacts any observed infrastructure.
 */
export function registerTlsGraphRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  app.get("/cases/:id/tls-graph", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const caseId = req.params.id;
      const signal = requestAbortSignal(res);
      const pick = (e: ForensicEvent): ForensicEvent | undefined => (tlsCaseGraphReads(e) ? e : undefined);
      const [state, superEvents] = await Promise.all([
        caseOpenState(ctx.store, options.stateStore).load(caseId, { signal }),
        // #2128: the scan takes the signal too, so it stops with its sibling load for a gone client.
        options.superTimelineStore
          ? options.superTimelineStore.collect(caseId, pick, undefined, signal)
          : Promise.resolve<ForensicEvent[]>([]),
      ]);
      if (clientGone(res)) return; // #2121
      const graph = buildTlsCaseGraph([...state.forensicTimeline, ...superEvents]);
      return res.status(200).json({ ...graph, generated: new Date().toISOString() });
    } catch (err) {
      return clientGone(res) ? undefined : res.status(500).json({ error: (err as Error).message });
    }
  });
}
