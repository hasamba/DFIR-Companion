import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import { readPublicAsset } from "../serverAssets.js";
import { defaultReportTemplate, isReportSectionEnabled, type ReportSectionKey } from "../reports/reportTemplate.js";
import { HYPOTHESIS_STATUSES, type HypothesisStatus, type HypothesisPatch, type NewHypothesis } from "../analysis/hypothesis.js";
import type { InvestigationQuestion, QuestionStatus } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * AI synthesis / Q&A / summary domain: the large cluster of LLM-backed (and LLM-adjacent) endpoints
 * that read the synthesized case and either derive fresh conclusions, answer questions, or project
 * the case for consumers. Pure structural move out of createApp (see routes/system.ts for the
 * conventions) — no handler logic changed. Groups:
 *   - ai-control (GET/POST) — per-case AI on/off + notebook toggle; POST turning it on kicks a
 *     background backfill of everything captured while off.
 *   - synthesize            — on-demand holistic synthesis (findings / MITRE / attacker path).
 *   - synth-meta / ai-cost  — read-only last-synthesis metadata + per-case token/cost totals.
 *   - second-opinion (POST run / GET last / apply / apply-all) — a second model's independent
 *     re-synthesis, stored as non-destructive deltas applied per-item.
 *   - ask                   — free-form grounded Q&A over the case (single-shot, ephemeral).
 *   - events/:eid/explain   — explain one forensic event in context (ephemeral).
 *   - questions             — pin an analyst key question so synthesis preserves + answers it.
 *   - hypotheses (CRUD)     — status-tracked investigative hypotheses.
 *   - confidence-control (GET/PUT) — the findings min-confidence DISPLAY floor (#226); left here by
 *     the findings domain because it belongs to AI output presentation, not analyst annotations.
 *   - narrative (POST generate / PUT save-edit) — prose narrative timeline.
 *   - executive-summary / remediation-plan — one-shot management/defensive AI generations.
 *   - adversary-hints (GET) + adversary-hints/hunt-technique (POST) — offline ATT&CK-group hints +
 *     an AI VQL-hunt suggestion for a likely-next technique.
 *   - memory/next-steps     — the memory-forensics "next Volatility command" agent; left here by the
 *     velociraptor domain (it's an AI generator, not Velociraptor plumbing).
 *   - mobile-summary        — the phone PWA's read-only case projection.
 *   - presentation / present/export / present — the slide-deck JSON, its standalone-HTML export, and
 *     the static viewer page.
 *
 * Shared surface — reuses already-graduated ctx members; nothing new was invented beyond the two
 * graduated below:
 *   - store, options, hasAiProvider — stable ctx surface.
 *   - getControl / loadPlaybookControl — already-graduated stable methods, reused as-is.
 *   - captureBuffers() — the live accessor for the per-case capture buffer Map; the ai-control POST
 *     handler drops the pending buffer through it when pausing (the ONE non-verbatim rebind: the
 *     original `buffers.set(...)` became `ctx.captureBuffers().set(...)`).
 *   - setControl / backfill — GRADUATED for this domain (see context.ts). setControl is the AI-control
 *     write path (also used by createApp's flush/backfill, so graduated not moved); backfill is the
 *     AI off→on catch-up, used only here but kept in createApp because it's wired to the PRIVATE
 *     synth machinery (scheduleSynthesis + its synthTimers debounce map) that no route reaches.
 *
 * Domain-local state handling (the main correctness risk, recorded explicitly):
 *   - controlCache (the AI-control Map) — NOT moved, NOT graduated. It backs getControl/setControl,
 *     BOTH of which stay in createApp; no moved route touches the cache directly, so it stays fully
 *     private to createApp.
 *   - synthTimers (the debounce timers Map) — NOT moved, NOT graduated. It's private to
 *     scheduleSynthesis, which stays in createApp (fired by flush + the capture-backfill paths); no
 *     moved route touches it. synthInFlight (a ctx live accessor) is likewise untouched here.
 *
 * Module-local, moved verbatim:
 *   - reportSectionEnabled — gates the per-section AI generators (executive-summary, narrative) so a
 *     section disabled in the report template never spends tokens (#168). Depended only on options +
 *     report-template helpers and was used ONLY by these two moved routes, so it moved in wholesale
 *     rather than graduating (a future reportsExport domain can graduate it on demand if it needs it).
 *   - asStringArray — the small hypotheses request coercion helper.
 *   - logLine / errLine — module-private wrappers mirroring createApp's (serverLogger.info/error), so
 *     the moved handler bodies keep their original log calls verbatim.
 */
export function registerAiSynthesisRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, hasAiProvider, getControl, setControl, backfill, loadPlaybookControl } = ctx;

  // Module-private wrappers mirroring createApp's logLine/errLine (serverLogger.info/error), so the
  // moved handler bodies keep their original `logLine(...)` / `errLine(...)` calls verbatim.
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);
  const errLine = (msg: string): void => ctx.serverLogger.error(msg);

  // Resolve the report template selected for a case (mirrors ReportWriter.loadTemplate) and report
  // whether a given canonical section is enabled — used to gate the per-section AI generators so a
  // section the analyst disabled in their report template never spends tokens on content that
  // won't be rendered (issue #168). Conservative: only returns false when we positively know the
  // section is off; an unwired store, a dangling id, or any error never blocks generation.
  const reportSectionEnabled = async (caseId: string, key: ReportSectionKey): Promise<boolean> => {
    if (!options.reportTemplateStore || !options.reportTemplateControlStore) return true;
    try {
      const { templateId } = await options.reportTemplateControlStore.load(caseId);
      const tpl = (await options.reportTemplateStore.get(templateId)) ?? defaultReportTemplate();
      return isReportSectionEnabled(tpl, key);
    } catch {
      return true;
    }
  };

  // AI analysis on/off per case. GET reads it; POST { enabled } sets it. Turning it
  // ON triggers a background backfill of everything captured while it was off.
  app.get("/cases/:id/ai-control", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await getControl(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/ai-control", async (req: Request, res: Response) => {
    try {
      const body = req.body ?? {};
      const enabled = Boolean(body.enabled);
      const patch: Parameters<typeof setControl>[1] = { enabled };
      // Optional: toggle whether the analyst notebook is sent to the synthesis prompt.
      if (typeof body.includeNotebook === "boolean") patch.includeNotebook = body.includeNotebook;
      const prev = await getControl(req.params.id);
      const next = await setControl(req.params.id, patch);
      if (!enabled) {
        ctx.captureBuffers().set(req.params.id, []); // drop pending buffer when pausing
        options.onAiStatus?.(req.params.id, { status: "idle", at: new Date().toISOString(), detail: "AI paused" });
      } else if (!prev.enabled) {
        void backfill(req.params.id); // resumed → analyze the gap
      }
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // On-demand holistic synthesis: derive findings / MITRE / attacker path from the
  // forensic timeline. (Per-window capture builds the timeline; this writes the
  // conclusions.) Broadcasts the updated state to dashboard clients via onState.
  app.post("/cases/:id/synthesize", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for synthesis" });
    const caseId = req.params.id;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed" || caseMeta?.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({ error: `Case "${caseId}" is ${caseMeta.status} — ${action} before running synthesis` });
    }
    // Per-run Chain-of-Thought toggle (#121): "deepReasoning" enables extended thinking for THIS run
    // only (no .env edit + restart) — an optional thinkingTokens overrides the budget. Off otherwise.
    const deepReasoning = (req.body as { deepReasoning?: unknown })?.deepReasoning === true;
    const reqThinking = Number((req.body as { thinkingTokens?: unknown })?.thinkingTokens);
    const thinkingTokens = Number.isFinite(reqThinking) && reqThinking > 0 ? Math.floor(reqThinking) : undefined;
    options.onAiStatus?.(caseId, { status: "analyzing", at: new Date().toISOString(), detail: deepReasoning ? "synthesizing (deep reasoning)" : "synthesizing conclusions" });
    // #225: track this manual synthesis as a cancellable job so the analyst can abort a long run.
    // exclusive: a second re-synthesize for the same case (double-click, or racing the "Generate
    // hypotheses" button / a live auto-synthesis) supersedes rather than running alongside it.
    const job = options.jobManager?.register({ caseId, kind: "synthesis", label: "synthesis", cancellable: true, exclusive: true });
    // Pre-synthesis backup (#180): snapshot state before overwriting conclusions. Best-effort.
    if (options.backupManager) {
      await options.backupManager.createBackup(caseId, "pre-synthesis").catch(() => {});
    }
    try {
      // Explicit user action → force, so it always runs even if inputs are unchanged.
      const state = await options.pipeline.synthesize(caseId, { force: true, deepReasoning, ...(thinkingTokens !== undefined ? { thinkingTokens } : {}), ...(job?.signal ? { signal: job.signal } : {}) });
      if (job) options.jobManager?.finish(job.jobId);
      // Keep the playbook checklist aligned with the fresh next steps/findings (idempotent —
      // preserves analyst status/edits). Best-effort: never fail synthesis on a playbook hiccup.
      if (options.playbookStore) {
        try {
          const { useTemplates } = await loadPlaybookControl(caseId);
          await options.playbookStore.sync(caseId, state, { useTemplates });
          options.onPlaybook?.(caseId);
        } catch { /* non-fatal */ }
      }
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai", action: "synthesis",
        detail: `synthesis ran — ${state.findings.length} finding(s), ${state.mitreTechniques.length} technique(s)${deepReasoning ? " (deep reasoning)" : ""}`,
      });
      return res.status(200).json({
        findings: state.findings.length,
        mitreTechniques: state.mitreTechniques.length,
        forensicEvents: state.forensicTimeline.length,
        attackerPath: Boolean(state.attackerPath),
        narrativeTimeline: Boolean(state.narrativeTimeline),
      });
    } catch (err) {
      const aborted = job?.signal?.aborted === true;
      if (job) options.jobManager?.fail(job.jobId, err); // no-op if a cancel already marked it cancelled
      if (aborted) {
        // A newer exclusive registration may have superseded this run (see above) — if a synthesis
        // job for this case is still active, that newer run owns the status; don't stomp it to idle.
        if (!options.jobManager?.hasActive(caseId, "synthesis")) {
          options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: "synthesis cancelled" });
        }
        return res.status(499).json({ error: "synthesis cancelled" });
      }
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai", action: "synthesis", detail: (err as Error).message, outcome: "error",
      });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Second LLM opinion (issue #116): run a DIFFERENT model over the same case (independent
  // re-synthesis + reconcile) and surface where it disagrees, for analyst QA. On-demand, two
  // text-only AI calls; NON-DESTRUCTIVE — the deltas are stored, not applied, until the analyst
  // accepts them per item. 501 when no second-opinion model is configured (DFIR_AI_SECOND_OPINION_MODEL).
  app.post("/cases/:id/second-opinion", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionEnabled) {
      return res.status(501).json({ error: "second-opinion model not configured — set DFIR_AI_SECOND_OPINION_MODEL" });
    }
    const caseId = req.params.id;
    // Same per-run deep-reasoning toggle (#121) as /synthesize — flows into both model A & B passes.
    const deepReasoning = (req.body as { deepReasoning?: unknown })?.deepReasoning === true;
    options.onAiStatus?.(caseId, { status: "analyzing", at: new Date().toISOString(), detail: deepReasoning ? "running second opinion (deep reasoning)" : "running second opinion" });
    try {
      const record = await options.pipeline.secondOpinion(caseId, { deepReasoning });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      options.onSecondOpinion?.(caseId);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai", action: "second-opinion",
        detail: `second opinion ran — ${record.deltas.length} delta(s)${deepReasoning ? " (deep reasoning)" : ""}`,
      });
      return res.status(200).json(record);
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Fetch the last second-opinion record for a case (or null). Read-only; no AI.
  app.get("/cases/:id/second-opinion", async (req: Request, res: Response) => {
    if (!options.secondOpinionStore) return res.status(200).json(null);
    try {
      return res.status(200).json(await options.secondOpinionStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Accept or reject ONE second-opinion delta. Accept (re-)applies all accepted deltas onto the
  // case (idempotent; durable across re-synthesis); reject only records the decision. The case
  // state is otherwise untouched. Body: { deltaId, accept }.
  app.post("/cases/:id/second-opinion/apply", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionStore) return res.status(501).json({ error: "second opinion not configured" });
    const deltaId = typeof req.body?.deltaId === "string" ? req.body.deltaId.trim() : "";
    const accept = req.body?.accept === true;
    if (!deltaId) return res.status(400).json({ error: "deltaId is required" });
    try {
      const { record } = await options.pipeline.applySecondOpinion(req.params.id, deltaId, accept);
      options.onSecondOpinion?.(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "second-opinion-apply", detail: `delta ${deltaId} — ${accept ? "accepted" : "rejected"}`,
      });
      return res.status(200).json(record);
    } catch (err) {
      const msg = (err as Error).message;
      const code = /unknown second-opinion delta/.test(msg) ? 404 : /no second opinion/.test(msg) ? 409 : 500;
      return res.status(code).json({ error: msg });
    }
  });

  // Bulk accept-all / reject-all over the still-pending second-opinion deltas, in one pass. Body:
  // { accept }. Accept (re-)applies all accepted deltas to the case; reject just records decisions.
  app.post("/cases/:id/second-opinion/apply-all", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionStore) return res.status(501).json({ error: "second opinion not configured" });
    const accept = req.body?.accept === true;
    try {
      const { record } = await options.pipeline.applyAllSecondOpinion(req.params.id, accept);
      options.onSecondOpinion?.(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "second-opinion-apply-all", detail: `all pending deltas — ${accept ? "accepted" : "rejected"}`,
      });
      return res.status(200).json(record);
    } catch (err) {
      const msg = (err as Error).message;
      const code = /no second opinion/.test(msg) ? 409 : 500;
      return res.status(code).json({ error: msg });
    }
  });

  // Ask the LLM a free-form question about the case ("was data exfiltrated?"). Single-shot,
  // no state change — returns a grounded answer + status + collection guidance (`pointer`).
  app.post("/cases/:id/ask", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for case questions" });
    const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
    if (!question) return res.status(400).json({ error: "question is required" });
    try {
      const answer = await options.pipeline.ask(req.params.id, question);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "ask", detail: `asked: "${question.slice(0, 120)}"`,
      });
      return res.status(200).json(answer);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Explain a single forensic event in context (issue #141). EPHEMERAL — no state change.
  // Returns structured analysis: what happened, why it matters, ATT&CK mapping, pivot queries,
  // and evidence for/against maliciousness. Useful for junior analysts and training.
  app.post("/cases/:id/events/:eid/explain", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for event explanation" });
    try {
      const result = await options.pipeline.explainEvent(req.params.id, req.params.eid);
      return res.status(200).json(result);
    } catch (err: unknown) {
      const msg = (err as Error).message;
      if (msg.startsWith("event not found") || msg.startsWith("Case not found")) return res.status(404).json({ error: msg });
      errLine(`[explain] case=${req.params.id} event=${req.params.eid}: ${msg}`);
      return res.status(500).json({ error: msg });
    }
  });

  // Generate a management-facing executive summary over the synthesized case (one text-only AI
  // call). The dashboard shows it and can save it into report-meta.executiveSummary, which then
  // overrides the auto-derived summary in the generated report.
  app.post("/cases/:id/executive-summary", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for executive summary" });
    if (!(await reportSectionEnabled(req.params.id, "executiveSummary")))
      return res.status(409).json({ error: "The Executive summary section is disabled in this case's report template — enable it in Settings → Report template to generate (skipped to save tokens).", sectionDisabled: true, section: "executiveSummary" });
    try {
      const result = await options.pipeline.executiveSummary(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "executive-summary", detail: "executive summary generated",
      });
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Generate an incident-specific remediation plan (#178) — one text-only AI call, grounded in the
  // case's findings + the deterministic ATT&CK mitigations. Ephemeral (no state change); the
  // dashboard renders it under the Mitigation & Defensive Countermeasures panel.
  app.post("/cases/:id/remediation-plan", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for remediation plan" });
    try {
      const result = await options.pipeline.remediationPlan(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "remediation-plan", detail: "remediation plan generated",
      });
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Generate (or regenerate) a prose narrative timeline for the case (one text-only AI call).
  // Saves the result to state.narrativeTimeline so it persists and appears in the report/dashboard.
  app.post("/cases/:id/narrative", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for narrative generation" });
    // The narrative timeline renders under report section 3.2, inside the "Timeline of events"
    // major section — so a disabled `timeline` section means the narrative won't appear; skip its
    // AI call to save tokens (issue #168). The analyst's already-saved narrative is left intact.
    if (!(await reportSectionEnabled(req.params.id, "timeline")))
      return res.status(409).json({ error: "The Timeline section (which contains the narrative) is disabled in this case's report template — enable it in Settings → Report template to generate (skipped to save tokens).", sectionDisabled: true, section: "timeline" });
    try {
      const result = await options.pipeline.generateNarrative(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "narrative", detail: "narrative timeline generated",
      });
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Save an analyst-edited narrative timeline. The analyst may edit the AI-generated narrative
  // before export; this persists the edit to state.narrativeTimeline until the next synthesis.
  app.put("/cases/:id/narrative", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const narrative = typeof req.body?.narrativeTimeline === "string" ? req.body.narrativeTimeline : "";
    try {
      const state = await options.stateStore.load(req.params.id);
      const updated = { ...state, narrativeTimeline: narrative };
      await options.stateStore.save(updated);
      return res.status(200).json({ narrativeTimeline: narrative });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Last-synthesis metadata: when synthesis last actually ran + what changed in the findings.
  // Backs the dashboard's "last synthesized N ago" indicator and the what-changed diff view.
  app.get("/cases/:id/synth-meta", async (req: Request, res: Response) => {
    if (!options.synthMetaStore) return res.status(501).json({ error: "synth metadata not configured" });
    try {
      return res.status(200).json(await options.synthMetaStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Per-case AI cost/token totals (Settings → Diagnostics "AI cost — this case" card).
  app.get("/cases/:id/ai-cost", async (req: Request, res: Response) => {
    if (!options.aiCostStore) return res.status(501).json({ error: "AI cost tracking not configured" });
    try {
      return res.status(200).json(await options.aiCostStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add an analyst question to the case's open key questions (e.g. from Ask, when unknown).
  // It's pinned, so synthesis preserves it and answers it once the evidence supports it.
  app.post("/cases/:id/questions", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
    if (!question) return res.status(400).json({ error: "question is required" });
    const statusIn = String(req.body?.status ?? "unknown");
    const status: QuestionStatus = statusIn === "answered" || statusIn === "partial" ? statusIn : "unknown";
    try {
      const state = await options.stateStore.load(req.params.id);
      const nums = state.keyQuestions.map((q) => Number(/^aq(\d+)$/.exec(q.id)?.[1])).filter((n) => !Number.isNaN(n));
      const newQuestion: InvestigationQuestion = {
        id: `aq${(nums.length ? Math.max(...nums) : 0) + 1}`,
        question,
        status,
        answer: typeof req.body?.answer === "string" ? req.body.answer : "",
        pointer: typeof req.body?.pointer === "string" ? req.body.pointer : "",
        pinned: true,
      };
      const next = { ...state, keyQuestions: [...state.keyQuestions, newQuestion] };
      await options.stateStore.save(next);
      options.onState?.(next);
      return res.status(201).json(newQuestion);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Hypotheses (issue #140) — status-tracked investigative hypotheses (analyst-authored or
  // auto-generated by synthesis). CRUD over the per-case HypothesisStore; each write pings live
  // dashboard clients. A PATCH marks the hypothesis analystTouched, freezing it from synthesis refresh.
  const asStringArray = (v: unknown): string[] | undefined =>
    Array.isArray(v) ? v.map(String) : undefined;

  app.get("/cases/:id/hypotheses", async (req: Request, res: Response) => {
    if (!options.hypothesisStore) return res.status(501).json({ error: "hypotheses not configured" });
    try {
      return res.status(200).json(await options.hypothesisStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/hypotheses", async (req: Request, res: Response) => {
    if (!options.hypothesisStore) return res.status(501).json({ error: "hypotheses not configured" });
    const title = typeof req.body?.title === "string" ? req.body.title.trim() : "";
    if (!title) return res.status(400).json({ error: "title is required" });
    const statusIn = String(req.body?.status ?? "");
    const input: NewHypothesis = {
      title,
      description: typeof req.body?.description === "string" ? req.body.description : undefined,
      expectedOutcome: typeof req.body?.expectedOutcome === "string" ? req.body.expectedOutcome : undefined,
      status: HYPOTHESIS_STATUSES.includes(statusIn as HypothesisStatus) ? (statusIn as HypothesisStatus) : undefined,
      relatedTechniques: asStringArray(req.body?.relatedTechniques),
      relatedEventIds: asStringArray(req.body?.relatedEventIds),
      relatedIocIds: asStringArray(req.body?.relatedIocIds),
      assignee: typeof req.body?.assignee === "string" ? req.body.assignee : undefined,
      notes: typeof req.body?.notes === "string" ? req.body.notes : undefined,
      author: typeof req.body?.author === "string" ? req.body.author : undefined,
    };
    try {
      const hypothesis = await options.hypothesisStore.add(req.params.id, input);
      options.onHypotheses?.(req.params.id);
      return res.status(201).json(hypothesis);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/hypotheses/:hid", async (req: Request, res: Response) => {
    if (!options.hypothesisStore) return res.status(501).json({ error: "hypotheses not configured" });
    const patch: HypothesisPatch = {};
    if (typeof req.body?.title === "string") patch.title = req.body.title;
    if (typeof req.body?.description === "string") patch.description = req.body.description;
    if (typeof req.body?.expectedOutcome === "string") patch.expectedOutcome = req.body.expectedOutcome;
    if (typeof req.body?.status === "string" && HYPOTHESIS_STATUSES.includes(req.body.status as HypothesisStatus)) {
      patch.status = req.body.status as HypothesisStatus;
    }
    if (Array.isArray(req.body?.relatedTechniques)) patch.relatedTechniques = req.body.relatedTechniques.map(String);
    if (Array.isArray(req.body?.relatedEventIds)) patch.relatedEventIds = req.body.relatedEventIds.map(String);
    if (Array.isArray(req.body?.relatedIocIds)) patch.relatedIocIds = req.body.relatedIocIds.map(String);
    if (typeof req.body?.assignee === "string") patch.assignee = req.body.assignee;
    if (typeof req.body?.notes === "string") patch.notes = req.body.notes;
    try {
      const updated = await options.hypothesisStore.update(req.params.id, req.params.hid, patch);
      if (!updated) return res.status(404).json({ error: "hypothesis not found" });
      options.onHypotheses?.(req.params.id);
      return res.status(200).json(updated);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/hypotheses/:hid", async (req: Request, res: Response) => {
    if (!options.hypothesisStore) return res.status(501).json({ error: "hypotheses not configured" });
    try {
      const removed = await options.hypothesisStore.remove(req.params.id, req.params.hid);
      if (!removed) return res.status(404).json({ error: "hypothesis not found" });
      options.onHypotheses?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Findings min-confidence display floor (#226): a per-case setting, persisted so it survives a
  // page reload — purely a display preference (nothing is removed from state). `minConfidence: null`
  // means "show all" (0). GET returns the current value; PUT sets/clears it.
  app.get("/cases/:id/confidence-control", async (req: Request, res: Response) => {
    if (!options.confidenceControlStore) return res.status(501).json({ error: "confidence control not configured" });
    try {
      const minConfidence = (await options.confidenceControlStore.load(req.params.id)).minConfidence ?? null;
      return res.status(200).json({ minConfidence });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/confidence-control", async (req: Request, res: Response) => {
    if (!options.confidenceControlStore) return res.status(501).json({ error: "confidence control not configured" });
    const raw = req.body?.minConfidence;
    const cleared = raw === null || raw === undefined || raw === "";
    if (!cleared && (typeof raw !== "number" || !Number.isFinite(raw) || raw < 0 || raw > 100)) {
      return res.status(400).json({ error: "minConfidence must be a number 0-100, or null" });
    }
    try {
      await options.confidenceControlStore.set(req.params.id, { minConfidence: cleared ? undefined : raw });
      options.onConfidenceControl?.(req.params.id);
      const minConfidence = (await options.confidenceControlStore.load(req.params.id)).minConfidence ?? null;
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "settings", action: "confidence-control", detail: minConfidence === null ? "minConfidence cleared" : `minConfidence set to ${minConfidence}`,
      });
      return res.status(200).json({ minConfidence });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Adversary group hints (#46): known ATT&CK groups ranked by technique overlap with the case —
  // offline hypothesis fuel (NOT attribution), derived on demand from the bundled MITRE Groups
  // dataset with the same scope/legitimate filtering as the report. Powers the dashboard panel.
  app.get("/cases/:id/adversary-hints", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.adversaryHints(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // AI-suggest a Velociraptor VQL hunt for ONE adversary-emulation "likely next technique" (issue
  // #121). The technique hasn't been observed yet; this turns the suggestion into a runnable, fleet-
  // wide hunt to proactively detect it. Single text-only AI call, EPHEMERAL (no state change) — the
  // dashboard shows the VQL + rationale for review, then deploys via POST /velociraptor/hunt.
  app.post("/cases/:id/adversary-hints/hunt-technique", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for hunt suggestions" });
    const techniqueId = String((req.body as { techniqueId?: unknown })?.techniqueId ?? "").trim();
    const techniqueName = String((req.body as { techniqueName?: unknown })?.techniqueName ?? "").trim() || undefined;
    if (!/^T\d{4}(?:\.\d{3})?$/i.test(techniqueId)) return res.status(400).json({ error: "valid ATT&CK techniqueId required" });
    try {
      const suggestions = await options.pipeline.suggestTechniqueHunts(req.params.id, techniqueId, techniqueName);
      logLine(`[adversary] suggested ${suggestions.length} hunt(s) for technique ${techniqueId} (${req.params.id})`);
      return res.status(200).json({ suggestions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Memory-forensics "Next-Step" agent (issue #101). When the case has Volatility 3 / Rekall output
  // imported, this makes ONE text-only AI call that reads the memory evidence (process tree, malfind,
  // connections, command lines), spots anomalies, and proposes the exact next Volatility command to
  // run. EPHEMERAL (no state change). Needs an AI provider; returns [] when the case has no memory
  // evidence (the dashboard hides the panel in that case).
  app.post("/cases/:id/memory/next-steps", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for memory next-step suggestions" });
    try {
      const suggestions = await options.pipeline.suggestMemoryNextSteps(req.params.id);
      logLine(`[memory] suggested ${suggestions.length} next step(s) for ${req.params.id}`);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai", action: "memory-next-steps", detail: `suggested ${suggestions.length} next step(s)`,
      });
      return res.status(200).json({ suggestions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Mobile companion summary (#59): a compact, READ-ONLY projection of the case for the phone PWA
  // (/mobile) — case status, worst findings, most severe/recent events, IOC list with verdicts.
  // Same scope/legitimate filtering as the report, so the phone view agrees with the dashboard.
  app.get("/cases/:id/mobile-summary", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.mobileSummary(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Presentation / timeline-replay deck (#177): the JSON deck the slide viewer (/cases/:id/present)
  // fetches. Same scope/legitimate filtering as the report; an optional ?minSeverity= floors the
  // findings/events so the presenter can tailor the narrative (respecting the severity filter).
  app.get("/cases/:id/presentation", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const minSeverity = parseMinSeverity(req.query.minSeverity);
      return res.status(200).json(await options.reportWriter.presentation(req.params.id, { minSeverity }));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Standalone, self-contained HTML slide deck (#177) — works offline with no server. Embeds the
  // deck JSON into the viewer page so a stakeholder can open it directly. The deck is escaped so
  // case content can never break out of the <script> (no `</script>` injection).
  app.get("/cases/:id/present/export", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const minSeverity = parseMinSeverity(req.query.minSeverity);
      const deck = await options.reportWriter.presentation(req.params.id, { minSeverity });
      const tpl = await readPublicAsset("present.html", "utf8");
      const safeJson = JSON.stringify(deck).replace(/</g, "\\u003c");
      const html = tpl.replace("<!--DECK_INJECT-->", `<script>window.__DECK__=${safeJson};</script>`);
      const filename = `presentation-${req.params.id.replace(/[^a-zA-Z0-9._-]/g, "_")}.html`;
      res
        .type("html")
        .set("Content-Disposition", `attachment; filename="${filename}"`)
        .send(html);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Presentation / timeline-replay mode (#177): a read-only, step-through slide viewer for handoff
  // briefings and executive walkthroughs. The static page reads the case id from its own URL path
  // and fetches GET /cases/:id/presentation. Self-contained (inline CSS+JS), so the same file also
  // backs the offline standalone-HTML export (which just embeds the deck via window.__DECK__).
  app.get("/cases/:id/present", async (_req, res) => {
    const html = await readPublicAsset("present.html", "utf8");
    res.type("html").send(html);
  });
}
