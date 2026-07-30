import type { Express, Request, Response } from "express";
import { deriveCockpit, type CockpitAction, type CockpitSnapshot } from "../analysis/cockpit.js";
import { CockpitStore } from "../analysis/cockpitStore.js";
import { logActivity } from "../analysis/activityLog.js";
import { PinLimitError } from "../analysis/pinnedFindings.js";
import type { RouteContext } from "./context.js";

const CARD_ACTIONS = new Set<CockpitAction>(["pin", "unpin", "dismiss", "restore", "defer", "assign"]);

function allCards(snapshot: CockpitSnapshot) {
  return [
    ...snapshot.sections.leads,
    ...snapshot.sections.hypotheses,
    ...snapshot.sections.contradictions,
    ...snapshot.sections.gaps,
    ...snapshot.sections.changes,
    ...snapshot.sections.activity,
    ...snapshot.sections.blockers,
    ...snapshot.parked,
  ];
}

/**
 * The default Now cockpit (issue #375). The route composes state owned by existing subsystems and
 * adds only cockpit-specific decisions/review timestamps in state/cockpit.json.
 */
export function registerCockpitRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;
  const cockpitStore = new CockpitStore(store);

  async function resolveInvestigator(caseId: string, requested: unknown): Promise<string> {
    const explicit = typeof requested === "string" ? requested.trim() : "";
    if (explicit) return explicit.slice(0, 120);
    const meta = await store.getCaseMeta(caseId);
    return meta?.investigator?.trim().slice(0, 120) || "analyst";
  }

  async function loadSnapshot(caseId: string, requestedInvestigator?: unknown): Promise<CockpitSnapshot | null> {
    if (!(await store.caseExists(caseId))) return null;
    const stateStore = options.stateStore;
    if (!stateStore) throw new Error("state store not configured");
    const investigator = await resolveInvestigator(caseId, requestedInvestigator);
    const [
      state,
      hypotheses,
      workflows,
      pins,
      importMeta,
      synthMeta,
      decisions,
    ] = await Promise.all([
      stateStore.load(caseId),
      options.hypothesisStore?.load(caseId) ?? Promise.resolve([]),
      options.findingWorkflowStore?.load(caseId) ?? Promise.resolve([]),
      options.pinnedFindingsStore?.load(caseId) ?? Promise.resolve([]),
      options.importMetaStore?.load(caseId),
      options.synthMetaStore?.load(caseId),
      cockpitStore.load(caseId),
    ]);
    return deriveCockpit({
      state,
      ...(options.hypothesisStore ? { hypotheses } : {}),
      ...(options.findingWorkflowStore ? { workflows } : {}),
      ...(options.pinnedFindingsStore ? { pinnedFindingIds: pins.map((pin) => pin.findingId) } : {}),
      jobs: options.jobManager?.list(caseId) ?? [],
      importMeta,
      synthMeta,
      decisions,
      investigator,
    });
  }

  app.get("/cases/:id/cockpit", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const snapshot = await loadSnapshot(req.params.id, req.query.investigator);
      if (!snapshot) return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      return res.status(200).json(snapshot);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/cockpit/history", async (req: Request, res: Response) => {
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const rawLimit = Number(req.query.limit);
      const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(1000, Math.floor(rawLimit)) : 200;
      const state = await cockpitStore.load(req.params.id);
      return res.status(200).json({ history: state.history.slice(-limit) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/cockpit/cards/:cardId", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const action = String(req.body?.action ?? "") as CockpitAction;
    if (!CARD_ACTIONS.has(action)) return res.status(400).json({ error: "invalid cockpit action" });
    const requestedActor = req.body?.actor;
    const value = typeof req.body?.value === "string" ? req.body.value.trim().slice(0, 500) : "";
    if (action === "assign" && !value) return res.status(400).json({ error: "assignee is required" });
    if (action === "defer" && !Number.isFinite(Date.parse(value))) {
      return res.status(400).json({ error: "a valid defer timestamp is required" });
    }
    const caseId = req.params.id;
    try {
      const snapshot = await loadSnapshot(caseId, requestedActor);
      if (!snapshot) return res.status(404).json({ error: `case ${caseId} does not exist` });
      const actor = snapshot.investigator;
      const card = allCards(snapshot).find((item) => item.id === req.params.cardId);
      if (!card) return res.status(404).json({ error: "cockpit card not found" });

      const findingId = card.target.findingId;
      const hypothesisId = card.target.hypothesisId;
      if (findingId && action === "pin" && options.pinnedFindingsStore) {
        await options.pinnedFindingsStore.pin(caseId, { findingId, pinnedBy: actor });
        options.onPins?.(caseId);
      } else if (findingId && action === "unpin" && options.pinnedFindingsStore) {
        await options.pinnedFindingsStore.unpin(caseId, findingId);
        options.onPins?.(caseId);
      } else if (findingId && action === "assign" && options.findingWorkflowStore) {
        await options.findingWorkflowStore.patch(caseId, findingId, { assignee: value, updatedBy: actor });
        options.onFindingWorkflow?.(caseId);
      } else if (hypothesisId && action === "assign" && options.hypothesisStore) {
        await options.hypothesisStore.update(caseId, hypothesisId, { assignee: value });
        options.onHypotheses?.(caseId);
      }

      const decisionState = await cockpitStore.recordAction(caseId, card.id, { action, actor, value });
      await logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: action === "assign" ? "collaboration" : "triage",
        action: `cockpit-${action}`,
        actor,
        detail: value ? `${card.title} — ${value}` : card.title,
        targetType: "cockpit-card",
        targetId: card.id,
      });
      const decision = decisionState.cards.find((item) => item.cardId === card.id) ?? null;
      return res.status(200).json({ decision });
    } catch (err) {
      if (err instanceof PinLimitError) {
        return res.status(409).json({ error: `pin limit reached (max ${err.max})`, max: err.max });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/cockpit/review", async (req: Request, res: Response) => {
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const investigator = await resolveInvestigator(req.params.id, req.body?.investigator);
      const review = await cockpitStore.markReviewed(req.params.id, investigator);
      await logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "collaboration",
        action: "cockpit-reviewed",
        actor: investigator,
        detail: "Marked the Now cockpit changes as reviewed",
        targetType: "cockpit",
      });
      return res.status(200).json({ review });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
