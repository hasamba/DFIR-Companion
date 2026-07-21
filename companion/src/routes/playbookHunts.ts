import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import type { NewPlaybookTask, PlaybookTaskPatch } from "../analysis/playbookStore.js";
import { PLAYBOOK_STATUSES, playbookStats, withBlockedState, PlaybookValidationError, type PlaybookStatus, type PlaybookTask } from "../analysis/playbook.js";
import { selectFreshHunts, pendingHuntTasks, mergePersistedHunts, EMPTY_PERSISTED_HUNTS, PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT } from "../analysis/playbookHunt.js";
import { DEFAULT_PLAYBOOK_CONTROL } from "../analysis/playbookControl.js";
import { buildHuntingProfile } from "../analysis/huntOutcomes.js";
import { playbookTaskEvent, type NotificationEvent } from "../analysis/notifications.js";
import type { RouteContext } from "./context.js";

/**
 * Playbook + hunt-suggestion/outcome domain (issues #36, #70, #157). The per-case investigation
 * playbook — a trackable checklist auto-derived from the case's next steps + Critical/High findings,
 * plus analyst-added custom tasks — and the two hunt-feedback surfaces that hang off it:
 *   - GET  /cases/:id/hunt-outcomes        — the per-case hunting profile (what was hunted, what hit /
 *                                            missed / is pending) for the #157 feedback loop; always 200.
 *   - GET/PUT /cases/:id/playbook/control  — toggle severity-based IR templates (Phase 2).
 *   - GET  /cases/:id/playbook             — auto-synced task list + completion stats + persisted AI
 *                                            hunt suggestions filtered to unchanged tasks (#70).
 *   - POST /cases/:id/playbook/sync        — force a re-derive from current state ("Sync from analysis").
 *   - POST /cases/:id/playbook/suggest-hunts — AI-suggest a Velociraptor VQL hunt per endpoint task
 *                                            (#70); EPHEMERAL, incremental, single-task regen supported.
 *   - PATCH /cases/:id/playbook/order      — reorder tasks (registered BEFORE /:taskId).
 *   - POST /cases/:id/playbook             — add a custom task.
 *   - PATCH/DELETE /cases/:id/playbook/:taskId — edit / remove a task.
 * The specific /control, /sync, /suggest-hunts, /order routes are registered BEFORE /:taskId so those
 * literals are never captured as a task id — this module preserves that original registration order.
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). Two helpers are
 * reached through the RouteContext because they are SHARED with createApp code that stays:
 *   - syncPlaybook       — re-derive the checklist against current state honoring the template setting.
 *                          Also called by the STAYING POST /cases/:id/push/iris route, so it was
 *                          graduated onto ctx (a hoisted function in createApp) rather than moved.
 *   - loadPlaybookControl — read the per-case template toggle; graduated alongside syncPlaybook because
 *                          syncPlaybook (which stays) depends on it and two moved routes call it too.
 *   - refreshVeloClients — the client-inventory refresh (already graduated for routes/velociraptor.ts);
 *                          the suggest-hunts route reuses it so a host enrolled mid-investigation is
 *                          resolvable at deploy time.
 * Plus the stable ctx surface (options).
 *
 * Domain-local helpers moved verbatim into the module (used only by these routes):
 *   - loadFreshHunts — load persisted #70 hunt suggestions, dropping any whose task was reworded/deleted.
 *   - logLine / caseLink / dispatchNotify — module-private copies of createApp's notification side
 *     channel (dispatchNotify fires playbook task-added/updated pings). caseLink + dispatchNotify are
 *     pure over stable config (options.notifier / options.dashboardBaseUrl) with no shared in-memory
 *     state, so rebuilding them here is behaviour-identical (same singleton notifier).
 */
export function registerPlaybookHuntsRoutes(app: Express, ctx: RouteContext): void {
  const { options, refreshVeloClients, syncPlaybook, loadPlaybookControl } = ctx;

  // Module-private wrapper mirroring createApp's logLine (serverLogger.info), so the moved handler
  // bodies keep their original `logLine(...)` calls verbatim.
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);

  // Deep link a notification back to the case dashboard (when a public base URL is configured).
  // Module-private copy of createApp's caseLink (pure over options.dashboardBaseUrl).
  const caseLink = (caseId: string): string | undefined =>
    options.dashboardBaseUrl ? `${options.dashboardBaseUrl.replace(/\/+$/, "")}/dashboard?caseId=${encodeURIComponent(caseId)}` : undefined;

  // Fire a notification event to all matching channels. Best-effort, fire-and-forget: a transport
  // failure NEVER bubbles into the request that triggered it (notifications are a side channel).
  // Module-private copy of createApp's dispatchNotify (same singleton options.notifier).
  const dispatchNotify = (event: NotificationEvent): void => {
    if (!options.notifier) return;
    const enriched = event.url ? event : { ...event, url: caseLink(event.caseId) };
    options.notifier.dispatch(enriched).catch((err) => logLine(`[notify] dispatch error: ${(err as Error).message}`));
  };

  // Load the persisted hunt suggestions (#70), dropping any whose task was reworded/deleted since
  // generation, and write the pruned set back so stale ones don't keep returning. Best-effort — a
  // store hiccup never breaks the playbook read (returns []).
  const loadFreshHunts = async (caseId: string, tasks: readonly PlaybookTask[]) => {
    if (!options.playbookHuntStore) return [];
    try {
      const persisted = await options.playbookHuntStore.load(caseId);
      const fresh = selectFreshHunts(persisted, tasks);
      if (fresh.changed) await options.playbookHuntStore.save(caseId, { generatedAt: persisted.generatedAt, suggestions: fresh.suggestions, taskHashes: fresh.taskHashes });
      return fresh.suggestions;
    } catch {
      return [];
    }
  };

  // The per-case hunting profile (what was hunted, what hit / missed / is pending). Always 200 — an
  // empty profile when no store / no outcomes — so the dashboard panel renders without special-casing.
  app.get("/cases/:id/hunt-outcomes", async (req: Request, res: Response) => {
    if (!options.huntOutcomeStore) return res.status(200).json(buildHuntingProfile([]));
    try {
      return res.status(200).json(buildHuntingProfile(await options.huntOutcomeStore.load(req.params.id)));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/playbook/control", async (req: Request, res: Response) => {
    if (!options.playbookControlStore) return res.status(200).json({ ...DEFAULT_PLAYBOOK_CONTROL });
    try {
      return res.status(200).json(await options.playbookControlStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/playbook/control", async (req: Request, res: Response) => {
    if (!options.playbookControlStore) return res.status(501).json({ error: "playbook control not configured" });
    if (typeof req.body?.useTemplates !== "boolean") return res.status(400).json({ error: "useTemplates (boolean) is required" });
    try {
      const control = await options.playbookControlStore.set(req.params.id, { useTemplates: req.body.useTemplates });
      const tasks = await syncPlaybook(req.params.id);   // re-derive immediately under the new mode
      options.onPlaybook?.(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "settings", action: "playbook-control", detail: `IR templates ${control.useTemplates ? "enabled" : "disabled"}`,
      });
      return res.status(200).json({ control, tasks: withBlockedState(tasks), stats: playbookStats(tasks) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/playbook", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    try {
      // Auto-sync against current state so the panel reflects the latest next steps/findings.
      const tasks = options.stateStore ? await syncPlaybook(req.params.id) : await options.playbookStore.load(req.params.id);
      // Persisted AI hunt suggestions, filtered to tasks that are UNCHANGED since generation (#70) —
      // so they survive a page refresh but a reworded/deleted task drops its stale hunt.
      const huntSuggestions = await loadFreshHunts(req.params.id, tasks);
      return res.status(200).json({ tasks: withBlockedState(tasks), stats: playbookStats(tasks), control: await loadPlaybookControl(req.params.id), huntSuggestions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Force a re-derive from the current case state (the "Sync from analysis" button).
  app.post("/cases/:id/playbook/sync", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const tasks = await syncPlaybook(req.params.id);
      options.onPlaybook?.(req.params.id);
      return res.status(200).json({ tasks: withBlockedState(tasks), stats: playbookStats(tasks), control: await loadPlaybookControl(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // AI-suggest a Velociraptor hunt for each ENDPOINT-related playbook task (issue #70). Single
  // text-only AI call, EPHEMERAL (no state change) — the dashboard shows each task's VQL + rationale
  // for review, then deploys it as a fleet HUNT (POST /velociraptor/hunt) or, for a task tied to one
  // endpoint, a single-client COLLECTION (POST /velociraptor/collect-host). Needs an AI provider +
  // the playbook store; does NOT need the Velociraptor API (the VQL is useful to copy even when off).
  // Registered BEFORE /:taskId so "suggest-hunts" is not captured as a task id.
  app.post("/cases/:id/playbook/suggest-hunts", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) return res.status(501).json({ error: "AI provider not configured for hunt suggestions" });
    if (!options.playbookStore || !options.stateStore) return res.status(501).json({ error: "playbook not configured" });
    try {
      const tasks = await syncPlaybook(req.params.id);

      // SINGLE-TASK REGEN: body carries `{ taskId, excludeVql }` — force-regenerate just that one
      // task, passing the existing VQL so the model produces something different.
      const regenTaskId = typeof req.body?.taskId === "string" ? req.body.taskId.trim() : null;
      if (regenTaskId) {
        const task = tasks.find((t) => t.id === regenTaskId);
        if (!task) return res.status(404).json({ error: "task not found" });
        const excludeVql = typeof req.body?.excludeVql === "string" ? req.body.excludeVql.trim() : undefined;
        const [, artifactNames] = await Promise.all([
          refreshVeloClients().catch((e) => { logLine(`[velociraptor] inventory refresh before regen failed: ${(e as Error).message}`); return 0; }),
          options.velociraptorClient
            ? options.velociraptorClient.listClientArtifacts().then((a) => a.map((x) => x.name)).catch(() => [] as string[])
            : Promise.resolve([] as string[]),
        ]);
        const newSuggestions = await options.pipeline.suggestPlaybookHunts(req.params.id, [task], artifactNames, { excludeVql });
        const persisted = options.playbookHuntStore ? await options.playbookHuntStore.load(req.params.id) : { ...EMPTY_PERSISTED_HUNTS };
        // Replace the old suggestion for this task (if any) and keep everything else.
        const kept = (persisted.suggestions ?? []).filter((s) => s.taskId !== regenTaskId);
        const merged: typeof persisted = {
          generatedAt: new Date().toISOString(),
          suggestions: [...kept, ...newSuggestions.filter((s) => s.taskId === regenTaskId)],
          taskHashes: { ...persisted.taskHashes },
        };
        logLine(`[velociraptor] playbook hunt regen for task ${regenTaskId} in ${req.params.id}: ${newSuggestions.length} suggestion(s)`);
        if (options.playbookHuntStore) {
          try { await options.playbookHuntStore.save(req.params.id, merged); }
          catch (e) { logLine(`[velociraptor] could not persist playbook hunts: ${(e as Error).message}`); }
        }
        return res.status(200).json({ suggestions: merged.suggestions, generated: newSuggestions.length, more: false });
      }

      // INCREMENTAL (#70): keep the suggestions whose task is unchanged and only generate for NEW or
      // CHANGED tasks — so adding one task and pressing Generate sends just that task to the model and
      // never re-does the hunts that already exist. `force:true` regenerates everything from scratch.
      const force = req.body?.force === true;
      const persisted = options.playbookHuntStore ? await options.playbookHuntStore.load(req.params.id) : { ...EMPTY_PERSISTED_HUNTS };
      const fresh = force ? { suggestions: [], taskHashes: {} } : selectFreshHunts(persisted, tasks);
      const pending = pendingHuntTasks(tasks, fresh.taskHashes);
      // Concurrently (best-effort, no-op when the API is off): refresh the client inventory so a host
      // enrolled MID-INVESTIGATION is resolvable at deploy time, AND fetch the server's REAL CLIENT
      // artifact names so the model only references artifacts that EXIST. Skip the artifact fetch when
      // nothing is pending (no AI call needed). Both finish before the AI call → no added latency.
      // The artifact list may come from the client's short-TTL catalog cache — fine here: it only steers
      // the model's suggestions (already best-effort, `catch → []`), and run-bundle/deploy re-checks.
      const [, artifactNames] = await Promise.all([
        refreshVeloClients().catch((e) => { logLine(`[velociraptor] inventory refresh before suggestions failed: ${(e as Error).message}`); return 0; }),
        pending.length && options.velociraptorClient
          ? options.velociraptorClient.listClientArtifacts().then((a) => a.map((x) => x.name)).catch(() => [] as string[])
          : Promise.resolve([] as string[]),
      ]);
      // Keep only suggestions FOR the pending tasks — so a model that echoes a wrong taskId can't
      // duplicate or clobber a kept (covered) suggestion. fresh + new then have disjoint task ids.
      const pendingIds = new Set(pending.map((t) => t.id));
      const newSuggestions = (pending.length ? await options.pipeline.suggestPlaybookHunts(req.params.id, pending, artifactNames) : [])
        .filter((s) => pendingIds.has(s.taskId));
      // Which pending tasks to mark "evaluated" (won't be re-sent): if the model hit the per-generation
      // cap there may be MORE pending tasks it never got to — stamp only the ones it actually hunted, so
      // the rest are retried on the next press. Otherwise it saw every pending task → stamp them all
      // (a non-endpoint task it deliberately skipped won't be re-evaluated).
      const cap = Number(process.env.DFIR_PBHUNT_SUGGEST_MAX) || PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT;
      const truncated = newSuggestions.length >= cap;
      const suggestedIds = new Set(newSuggestions.map((s) => s.taskId));
      const evaluatedTasks = truncated ? pending.filter((t) => suggestedIds.has(t.id)) : pending;
      const merged = mergePersistedHunts(fresh, newSuggestions, evaluatedTasks, new Date().toISOString());
      logLine(`[velociraptor] playbook hunts for ${req.params.id}: ${newSuggestions.length} new (of ${pending.length} pending task(s))${truncated ? " [cap hit — press again for more]" : ""}, ${merged.suggestions.length} total`);
      // Persist so the set survives a refresh + future incremental generates. Best-effort.
      if (options.playbookHuntStore) {
        try { await options.playbookHuntStore.save(req.params.id, merged); }
        catch (e) { logLine(`[velociraptor] could not persist playbook hunts: ${(e as Error).message}`); }
      }
      return res.status(200).json({ suggestions: merged.suggestions, generated: newSuggestions.length, more: truncated });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Reorder tasks by a supplied id sequence. Registered BEFORE /:taskId so "order" is not
  // captured as a task id.
  app.patch("/cases/:id/playbook/order", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String) : null;
    if (!ids) return res.status(400).json({ error: "ids array is required" });
    try {
      const tasks = await options.playbookStore.reorder(req.params.id, ids);
      options.onPlaybook?.(req.params.id);
      return res.status(200).json({ tasks: withBlockedState(tasks), stats: playbookStats(tasks) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/playbook", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    const title = typeof req.body?.title === "string" ? req.body.title.trim() : "";
    if (!title) return res.status(400).json({ error: "title is required" });
    const input: NewPlaybookTask = {
      title,
      description: typeof req.body?.description === "string" ? req.body.description : undefined,
      status: PLAYBOOK_STATUSES.includes(req.body?.status as PlaybookStatus) ? (req.body.status as PlaybookStatus) : undefined,
      priority: typeof req.body?.priority === "string" ? req.body.priority : undefined,
      assignee: typeof req.body?.assignee === "string" ? req.body.assignee : undefined,
      dueDate: typeof req.body?.dueDate === "string" ? req.body.dueDate : undefined,
      notes: typeof req.body?.notes === "string" ? req.body.notes : undefined,
      relatedFindingId: typeof req.body?.relatedFindingId === "string" ? req.body.relatedFindingId : undefined,
    };
    try {
      const task = await options.playbookStore.add(req.params.id, input);
      options.onPlaybook?.(req.params.id);
      dispatchNotify(playbookTaskEvent(req.params.id, task, "added", new Date().toISOString()));
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "playbook", action: "task-added",
        detail: `task added: "${task.title}"`, targetType: "playbook-task", targetId: task.id,
      });
      return res.status(201).json(task);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/playbook/:taskId", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    const patch: PlaybookTaskPatch = {};
    if (typeof req.body?.title === "string") patch.title = req.body.title;
    if (typeof req.body?.description === "string") patch.description = req.body.description;
    if (typeof req.body?.status === "string") patch.status = req.body.status as PlaybookStatus;
    if (typeof req.body?.priority === "string") patch.priority = req.body.priority;
    if (typeof req.body?.assignee === "string") patch.assignee = req.body.assignee;
    if (typeof req.body?.dueDate === "string") patch.dueDate = req.body.dueDate;
    if (typeof req.body?.notes === "string") patch.notes = req.body.notes;
    if (Array.isArray(req.body?.dependsOn)) patch.dependsOn = req.body.dependsOn.map(String);
    try {
      const updated = await options.playbookStore.update(req.params.id, req.params.taskId, patch);
      if (!updated) return res.status(404).json({ error: "playbook task not found" });
      options.onPlaybook?.(req.params.id);
      // Notify only on a STATUS change (the meaningful playbook signal) — "completed" when it lands
      // on done, "updated" otherwise. Pure metadata edits (notes/assignee) stay quiet to avoid noise.
      if (patch.status) {
        dispatchNotify(playbookTaskEvent(req.params.id, updated, updated.status === "done" ? "completed" : "updated", new Date().toISOString()));
      }
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "playbook", action: "task-updated",
        detail: `task "${updated.title}" — ${Object.keys(patch).join(", ")} changed${patch.status ? ` (status: ${updated.status})` : ""}`,
        targetType: "playbook-task", targetId: updated.id,
      });
      return res.status(200).json(updated);
    } catch (err) {
      if (err instanceof PlaybookValidationError) return res.status(400).json({ error: err.message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/playbook/:taskId", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    try {
      const removed = await options.playbookStore.remove(req.params.id, req.params.taskId);
      if (!removed) return res.status(404).json({ error: "playbook task not found" });
      options.onPlaybook?.(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "playbook", action: "task-removed", detail: `task ${req.params.taskId} removed`,
        targetType: "playbook-task", targetId: req.params.taskId,
      });
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
