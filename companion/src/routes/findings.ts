import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import {
  FalsePositiveStore, markerId, type FalsePositiveMarker, FALSE_POSITIVE_REASONS,
  applyFalsePositive, falsePositiveEventIds,
} from "../analysis/falsePositive.js";
import { reconsiderKeyQuestions, reconsiderNextSteps } from "../analysis/fpCascade.js";
import { patternKey } from "../analysis/prevalence.js";
import type { LearnedPatternInput } from "../analysis/learnedPatterns.js";
import { DEFAULT_SOURCE_TRUST } from "../analysis/sourceTrust.js";
import { findSimilarEvents, findSimilarFindings } from "../analysis/falsePositiveSimilarity.js";
import { ScopeStore, type ScopeWindow } from "../analysis/scope.js";
import { PinLimitError } from "../analysis/pinnedFindings.js";
import { FINDING_WORKFLOW_STATUSES, type FindingWorkflowStatus } from "../analysis/findingWorkflow.js";
import { type NotebookEntryType, NOTEBOOK_ENTRY_TYPES } from "../analysis/notebookStore.js";
import { mentionEvent } from "../analysis/notifications.js";
import { sanitizeRuleInput } from "../analysis/iocWhitelist.js";
import { STARRED_LABEL } from "../analysis/superTimeline.js";
import type { ForensicEvent, Finding } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * Findings domain: the analyst-annotation & organization layer — the per-case side files that let
 * an analyst curate the AI's output without mutating the underlying InvestigationState. All of it
 * survives synthesis (each is its own on-disk side store, not part of state.json):
 *   - false-positive   — mark/list/batch/remove a finding, IOC, or event as "not a real threat"
 *                        (+ a deterministic/AI "find similar" suggest helper for the mark dialog).
 *   - scope            — the investigation time-window; setting it re-synthesizes so out-of-window
 *                        events (and the findings/IOCs derived from them) drop out.
 *   - correlation-profile — the per-case cross-source event-correlation window.
 *   - comments / tags  — collaboration annotations attached to a (targetType, targetId) entity.
 *   - pinned-findings  — the analyst's ordered shortlist of the findings that matter most (#220).
 *   - finding-workflow — per-finding analyst assignee + workflow status (new/in-progress/…) (#87).
 *   - notebook         — per-case hypotheses/notes/questions the AI pass can optionally read.
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). Nothing here is
 * shared back with createApp beyond one already-graduated member reused via ctx:
 *   - resynthesizeInBackground — the shared post-mutation re-synthesis kick (owned by createApp,
 *     graduated for the import domain); the false-positive + scope mutations reuse it.
 * Plus the stable ctx surface (store, options).
 *
 * Domain-local state is rebuilt in-module from ctx.store:
 *   - falsePositives (FalsePositiveStore) — a stateless disk-backed store that just wraps ctx.store,
 *     so a fresh instance reads/writes the SAME false-positive.json as createApp's (the threatIntel /
 *     anonymization precedent). createApp keeps its OWN `falsePositives` for applyWhitelistToCase /
 *     applyNsrlToCase (which stay), and both instances hit the same file with no in-memory cache or
 *     shared lock — identical construction, safe to duplicate.
 *   - scopeStore (ScopeStore) — likewise stateless disk-backed; rebuilt identically (createApp builds
 *     its own separate ScopeStore instances for the reportWriter/params seams that stay).
 * `buildFalsePositiveMarker` is a pure helper used only by the false-positive routes, moved verbatim
 * into the module. correlation-profile/comments/tags/pinned-findings/notebook read their stores off
 * `options.*`, so nothing there needed graduating.
 *
 * NOTE (boundary): the interleaved NON-findings routes that sat between these handlers in the original
 * createApp were intentionally left in place — POST /cases/:id/events (manual timeline event),
 * the IOC-whitelist + NSRL false-positive auto-sweeps (applyWhitelistToCase/applyNsrlToCase, which own
 * createApp's `falsePositives`), POST /cases/:id/questions, GET /cases/:id/activity-log, the hypotheses
 * CRUD, GET /settings/env, and GET/PUT /cases/:id/confidence-control (the AI confidence-scoring display
 * floor, which belongs to the aiSynthesis domain, not analyst annotations).
 */
export function registerFindingsRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, resynthesizeInBackground, dispatchNotify } = ctx;

  // Domain-local stateless disk-backed stores, rebuilt from ctx.store (see module header).
  const falsePositives = new FalsePositiveStore(store);
  const scopeStore = new ScopeStore(store);

  app.get("/cases/:id/false-positive", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await falsePositives.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Build a marker from one request item (kind/ref/reason/note/label/markedBy). Returns null when
  // ref is empty, or when reason is "other" with no note, so the caller can reject (single) or skip
  // (batch). Shared by the single + batch routes.
  const buildFalsePositiveMarker = (item: {
    kind?: unknown; ref?: unknown; reason?: unknown; note?: unknown; label?: unknown; markedBy?: unknown;
  }): FalsePositiveMarker | null => {
    const rawKind = item?.kind;
    const kind: FalsePositiveMarker["kind"] =
      rawKind === "ioc" ? "ioc" : rawKind === "event" ? "event" : "finding";
    const ref = String(item?.ref ?? "").trim();
    if (!ref) return null;
    const rawReason = item?.reason;
    const reason: FalsePositiveMarker["reason"] =
      (FALSE_POSITIVE_REASONS as readonly string[]).includes(String(rawReason)) ? (rawReason as FalsePositiveMarker["reason"]) : "other";
    const note = String(item?.note ?? "");
    if (reason === "other" && !note.trim()) return null;
    // Optional human-readable label (e.g. a forensic event's description) so the
    // "False Positives" panel can show something meaningful for opaque ids.
    const label = item?.label != null ? String(item.label) : undefined;
    const markedBy = String(item?.markedBy ?? "").trim() || "anonymous";
    return {
      id: markerId(kind, ref), kind, ref, reason, note, markedAt: new Date().toISOString(), markedBy,
      ...(label ? { label } : {}),
    };
  };

  // Immediate FP cascade (investigation-guidance #12): the instant markers are saved, synchronously
  // reconsider the STORED conclusions a background re-synthesis would otherwise leave stale for the
  // seconds it runs — key questions + next-steps that rested on a now-rejected finding (badged "stale —
  // re-synthesis queued"), and hypotheses whose supporting evidence was just rejected. Best-effort: a
  // failure here must never fail the FP marking itself. Runs under the state lock so it can't race the
  // re-synthesis's read-modify-write. The authoritative re-synthesis (kicked right after) clears the flags.
  const cascadeFalsePositive = async (caseId: string, markers: FalsePositiveMarker[]): Promise<void> => {
    try {
      const stateStore = options.stateStore;
      if (stateStore) {
        await ctx.runStateExclusive(caseId, async () => {
          const state = await stateStore.load(caseId);
          const survivingFindingIds = new Set(applyFalsePositive(state, markers).findings.map((f) => f.id));
          const priorFindingIds = state.findings.map((f) => f.id);
          const removedFindingIds = new Set(priorFindingIds.filter((id) => !survivingFindingIds.has(id)));
          const q = reconsiderKeyQuestions(state.keyQuestions, { survivingFindingIds, priorFindingIds, staleReSynth: true });
          const s = reconsiderNextSteps(state.nextSteps, { removedFindingIds, staleReSynth: true });
          if (q.changed || s.changed) {
            await stateStore.save({ ...state, keyQuestions: q.questions, nextSteps: s.steps });
          }
        });
        // Hypotheses (a side store, not InvestigationState): flag/neutralize any whose evidence was
        // just rejected. Map IOC-value markers back to their IOC ids for the intersection test.
        if (options.hypothesisStore) {
          const state = await stateStore.load(caseId);
          const iocIdByValue = new Map(state.iocs.map((i) => [i.value.trim().toLowerCase(), i.id] as const));
          const fpIocIds = new Set(
            markers.filter((m) => m.kind === "ioc")
              .map((m) => iocIdByValue.get(m.ref.trim().toLowerCase()))
              .filter((id): id is string => !!id),
          );
          await options.hypothesisStore.reconsiderForFalsePositive(caseId, {
            fpEventIds: falsePositiveEventIds(markers), fpIocIds,
          });
        }
      }
    } catch (err) {
      console.warn(`[DFIR] FP cascade failed for case ${caseId}: ${(err as Error).message}`);
    }
  };

  // Proactive FP-pattern propagation (#15b): stamp the anchor event's normalized prevalence pattern key
  // onto each EVENT marker, so a later import can recognize the same pattern re-arriving and suggest a
  // bulk-mark. One state load for the whole batch; best-effort (a lookup miss just leaves it unset).
  const stampPatternFingerprints = async (caseId: string, markers: FalsePositiveMarker[]): Promise<void> => {
    const needing = markers.filter((m) => m.kind === "event" && !m.patternFingerprint);
    if (!needing.length || !options.stateStore) return;
    try {
      const state = await options.stateStore.load(caseId);
      const byId = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
      for (const m of needing) {
        const ev = byId.get(m.ref);
        if (!ev) continue;
        const key = patternKey(ev);
        if (key) m.patternFingerprint = key;
      }
    } catch { /* best-effort — leave fingerprints unset */ }
  };

  // Learn from dismissals (#65): distil each finding/event marker into the accumulating learned-patterns
  // ledger, so a recurrence generalizes into a synthesis confidence-lowering block. IOC markers are skipped
  // (a bare IOC value isn't a generalizable prose pattern). Best-effort — a failure must never fail the FP
  // marking. Read the analyst-facing text (a finding's title-ref, or an event's description label).
  const recordLearnedPatterns = async (caseId: string, markers: FalsePositiveMarker[]): Promise<void> => {
    if (!options.learnedPatternStore) return;
    const inputs: LearnedPatternInput[] = markers
      .filter((m) => m.kind === "finding" || m.kind === "event")
      .map((m) => ({ text: m.kind === "event" ? (m.label ?? "") : m.ref, reason: m.reason, example: m.label ?? m.ref }))
      .filter((i) => i.text.trim().length > 0);
    if (!inputs.length) return;
    try {
      for (const input of inputs) await options.learnedPatternStore.record(caseId, input);
      options.onLearnedPatterns?.(caseId);
    } catch (err) {
      console.warn(`[DFIR] learned-pattern record failed for case ${caseId}: ${(err as Error).message}`);
    }
  };

  app.get("/cases/:id/learned-patterns", async (req: Request, res: Response) => {
    if (!options.learnedPatternStore) return res.status(501).json({ error: "learned patterns not configured" });
    try {
      return res.status(200).json(await options.learnedPatternStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/false-positive", async (req: Request, res: Response) => {
    try {
      const marker = buildFalsePositiveMarker(req.body ?? {});
      if (!marker) return res.status(400).json({ error: "ref is required (and note is required when reason is 'other')" });
      await stampPatternFingerprints(req.params.id, [marker]);
      const markers = await falsePositives.load(req.params.id);
      const next = [...markers.filter((m) => m.id !== marker.id), marker];
      await falsePositives.save(req.params.id, next);
      if (marker.kind === "ioc" && req.body?.addToWhitelist && options.iocWhitelistStore) {
        const state = options.stateStore ? await options.stateStore.load(req.params.id) : null;
        const iocType = state?.iocs.find((i) => i.value.toLowerCase() === marker.ref.toLowerCase())?.type;
        const note = marker.note?.trim()
          ? `promoted from false-positive marking (${marker.reason}): ${marker.note}`
          : `promoted from false-positive marking (${marker.reason})`;
        const whitelistInput = sanitizeRuleInput({ match: "exact", pattern: marker.ref, iocType, note });
        // Best-effort side effect: the false-positive marking itself must succeed even when the
        // whitelist promotion is rejected (e.g. an oversized ref) — so skip silently, don't 400/500.
        if (whitelistInput) await options.iocWhitelistStore.add(whitelistInput);
      }
      options.onFalsePositive?.(req.params.id);
      await recordLearnedPatterns(req.params.id, [marker]); // #65 accumulate the reasoned dismissal
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage", action: "mark-false-positive", actor: marker.markedBy ?? "",
        detail: `${marker.kind} ${marker.ref} (${marker.reason})`, targetType: marker.kind, targetId: marker.ref,
      });
      await cascadeFalsePositive(req.params.id, next); // #12: neutralize dependent conclusions NOW
      resynthesizeInBackground(req.params.id); // re-derive conclusions without it
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Mark MANY entities false-positive in one shot — one read-modify-write + a SINGLE
  // re-synthesis, instead of N concurrent /false-positive calls that would race on
  // false-positive.json (last write wins) and each kick off their own re-synthesis. The
  // dashboard's bulk "Mark False Positive" uses this.
  // Body: { items: [{ kind, ref, reason?, note?, label? }, …], reason?, note? } — top-level
  // reason/note are the fallback for items that don't carry their own.
  app.post("/cases/:id/false-positive/batch", async (req: Request, res: Response) => {
    try {
      const rawItems = Array.isArray(req.body?.items) ? req.body.items : [];
      const fallbackReason = req.body?.reason;
      const fallbackNote = req.body?.note != null ? String(req.body.note) : "";
      const fallbackMarkedBy = req.body?.markedBy;
      const built = rawItems
        .map((it: { kind?: unknown; ref?: unknown; reason?: unknown; note?: unknown; label?: unknown; markedBy?: unknown }) =>
          buildFalsePositiveMarker({
            ...it,
            reason: it?.reason ?? fallbackReason,
            note: it?.note ?? fallbackNote,
            markedBy: it?.markedBy ?? fallbackMarkedBy,
          }))
        .filter((m: FalsePositiveMarker | null): m is FalsePositiveMarker => m !== null);
      if (!built.length) return res.status(400).json({ error: "at least one valid item (with a ref) is required" });
      await stampPatternFingerprints(req.params.id, built);   // #15b: capture each event's pattern key
      const markers = await falsePositives.load(req.params.id);
      // De-dupe within the batch and against existing markers (last occurrence wins) by id.
      const byId = new Map<string, FalsePositiveMarker>(markers.map((m) => [m.id, m]));
      for (const m of built) byId.set(m.id, m);
      const next = [...byId.values()];
      await falsePositives.save(req.params.id, next);
      options.onFalsePositive?.(req.params.id);
      await recordLearnedPatterns(req.params.id, built); // #65 accumulate the reasoned dismissals
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage", action: "mark-false-positive-batch", actor: fallbackMarkedBy ?? "",
        detail: `${built.length} item(s) marked false-positive`,
      });
      await cascadeFalsePositive(req.params.id, next); // #12: neutralize dependent conclusions NOW
      resynthesizeInBackground(req.params.id); // ONE re-synthesis for the whole batch
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/false-positive/remove", async (req: Request, res: Response) => {
    try {
      const id = String(req.body?.id ?? "");
      const markers = await falsePositives.load(req.params.id);
      const removedMarker = markers.find((m) => m.id === id);
      const next = markers.filter((m) => m.id !== id);
      await falsePositives.save(req.params.id, next);
      options.onFalsePositive?.(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage", action: "unmark-false-positive",
        actor: typeof req.body?.actor === "string" ? req.body.actor : "",
        detail: removedMarker ? `${removedMarker.kind} ${removedMarker.ref}` : `marker ${id}`,
        ...(removedMarker ? { targetType: removedMarker.kind, targetId: removedMarker.ref } : {}),
      });
      resynthesizeInBackground(req.params.id);
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Deterministic "find similar items" for the mark-FP dialog (#227): given one anchor
  // finding/event, rank other in-case findings/events by shared MITRE technique/process/hash/
  // asset/source (events) or MITRE/related-IOC/title (findings). Suggestions only — nothing here
  // is applied; the analyst checks which candidates to also mark in the /false-positive/batch call.
  app.post("/cases/:id/false-positive/suggest", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const kind = req.body?.kind === "event" ? "event" : req.body?.kind === "finding" ? "finding" : null;
      const ref = String(req.body?.ref ?? "").trim();
      if (!kind || !ref) return res.status(400).json({ error: "kind ('event'|'finding') and ref are required" });
      const state = await options.stateStore.load(req.params.id);
      const anchor = kind === "event" ? state.forensicTimeline.find((e) => e.id === ref) : state.findings.find((f) => f.id === ref);
      if (!anchor) return res.status(404).json({ error: `${kind} ${ref} not found` });

      const deterministic = kind === "event"
        ? findSimilarEvents(anchor as ForensicEvent, state.forensicTimeline)
        : findSimilarFindings(anchor as Finding, state.findings);

      if (!req.body?.ai) return res.status(200).json({ candidates: deterministic });
      if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) {
        return res.status(200).json({ candidates: deterministic, aiUnavailable: true });
      }

      const pool = kind === "event" ? state.forensicTimeline : state.findings;
      const anchorLabel = kind === "event" ? (anchor as ForensicEvent).description : (anchor as Finding).title;
      const seen = new Set(deterministic.map((c) => c.id));
      const rest = pool.filter((item) => item.id !== ref && !seen.has(item.id)).slice(0, 100);
      const aiIds = await options.pipeline.suggestFalsePositiveSimilarAi(
        req.params.id,
        ref,
        anchorLabel,
        rest.map((r) => r.id),
        rest.map((r) => (kind === "event" ? (r as ForensicEvent).description : (r as Finding).title)),
      );
      // Defense-in-depth, not redundant: suggestFalsePositiveSimilarAi already validates aiIds
      // against the candidate list it was given (dropping any hallucinated id), but this is a
      // safety-critical path (feeding a batch false-positive marker), so we re-filter here too
      // rather than trusting the pipeline call's return value unchecked.
      const aiCandidates = rest
        .filter((r) => aiIds.includes(r.id))
        .map((r) => ({
          id: r.id,
          kind,
          label: kind === "event" ? (r as ForensicEvent).description : (r as Finding).title,
          // Pinned to 0, not a "zero-confidence" match — this keeps AI-sourced candidates sorting
          // after every scored deterministic candidate when a UI sorts descending by score.
          // `reasons` (below) is what tells the dashboard this candidate came from the AI pass.
          score: 0,
          reasons: ["suggested by AI"],
        }));
      return res.status(200).json({ candidates: [...deterministic, ...aiCandidates] });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/scope", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await scopeStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/scope", async (req: Request, res: Response) => {
    try {
      const norm = (v: unknown): string | null => {
        const s = String(v ?? "").trim();
        if (!s) return null;
        const t = Date.parse(s);
        return Number.isNaN(t) ? null : new Date(t).toISOString();
      };
      const scope: ScopeWindow = { start: norm(req.body?.start), end: norm(req.body?.end) };
      await scopeStore.save(req.params.id, scope);
      options.onScope?.(req.params.id, scope);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "settings", action: "scope-changed",
        detail: (scope.start || scope.end) ? `scope set: ${scope.start ?? "…"} to ${scope.end ?? "…"}` : "scope cleared",
      });
      resynthesizeInBackground(req.params.id); // re-derive within the window
      return res.status(200).json(scope);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Correlation profile (per-case time window for cross-source event correlation).
  app.get("/cases/:id/correlation-profile", async (req, res) => {
    if (!options.correlationProfileStore) return res.status(501).json({ error: "correlation profile not configured" });
    try {
      return res.status(200).json(await options.correlationProfileStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: String(err) });
    }
  });

  app.put("/cases/:id/correlation-profile", async (req, res) => {
    if (!options.correlationProfileStore) return res.status(501).json({ error: "correlation profile not configured" });
    try {
      const { profileName, windowSeconds } = req.body as { profileName?: string; windowSeconds?: number };
      const validNames = ["strict", "moderate", "aggressive", "custom"];
      if (profileName !== undefined && !validNames.includes(profileName)) {
        return res.status(400).json({ error: "invalid profileName" });
      }
      if (windowSeconds !== undefined && (typeof windowSeconds !== "number" || windowSeconds < 0)) {
        return res.status(400).json({ error: "windowSeconds must be a non-negative number" });
      }
      const current = await options.correlationProfileStore.load(req.params.id);
      const updated = { ...current, ...(profileName ? { profileName: profileName as import("../analysis/correlationProfile.js").CorrelationProfileName } : {}), ...(windowSeconds !== undefined ? { windowSeconds } : {}) };
      await options.correlationProfileStore.save(req.params.id, updated);
      return res.status(200).json(updated);
    } catch (err) {
      return res.status(500).json({ error: String(err) });
    }
  });

  // Per-source trust (#66). GET returns the built-in DEFAULT map + this case's overrides (the dashboard
  // renders defaults, lets the analyst override a noisy source for the case). PUT replaces the overrides
  // (sanitized to [0,1]) and re-synthesizes so the new weights re-apply to merge + confidence.
  app.get("/cases/:id/source-trust", async (req: Request, res: Response) => {
    if (!options.sourceTrustStore) return res.status(501).json({ error: "source trust not configured" });
    try {
      const overrides = await options.sourceTrustStore.load(req.params.id);
      return res.status(200).json({ defaults: DEFAULT_SOURCE_TRUST, overrides });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/source-trust", async (req: Request, res: Response) => {
    if (!options.sourceTrustStore) return res.status(501).json({ error: "source trust not configured" });
    try {
      const saved = await options.sourceTrustStore.save(req.params.id, req.body?.overrides ?? req.body ?? {});
      options.onSourceTrust?.(req.params.id);
      resynthesizeInBackground(req.params.id); // re-apply the new weights to merge + confidence
      return res.status(200).json({ defaults: DEFAULT_SOURCE_TRUST, overrides: saved });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Investigator comments on case entities (collaboration). GET lists them; POST adds one
  // to a `(targetType, targetId)` entity; DELETE removes by id. Add/remove ping live clients.
  app.get("/cases/:id/comments", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    try {
      return res.status(200).json(await options.commentsStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/comments", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    const targetType = typeof req.body?.targetType === "string" ? req.body.targetType.trim() : "";
    const targetId = typeof req.body?.targetId === "string" ? req.body.targetId.trim() : "";
    const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
    if (!targetType || !targetId || !text) return res.status(400).json({ error: "targetType, targetId and text are required" });
    try {
      const comment = await options.commentsStore.add(req.params.id, {
        targetType, targetId, text,
        author: typeof req.body?.author === "string" ? req.body.author : "",
      });
      options.onComments?.(req.params.id);
      // Awaited, like the tag routes below: the dashboard refreshes the activity log as soon as
      // this responds, so a fire-and-forget append can lose the race against that read.
      await logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "collaboration", action: "comment-added", actor: comment.author,
        detail: `comment on ${targetType} ${targetId}`, targetType, targetId,
      });
      if (comment.mentions.length) {
        dispatchNotify(mentionEvent(
          req.params.id, targetType, targetId, comment.author, comment.mentions, comment.text,
          comment.createdAt,
        ));
      }
      return res.status(201).json(comment);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/comments/:commentId", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    try {
      const removed = await options.commentsStore.remove(req.params.id, req.params.commentId);
      if (!removed) return res.status(404).json({ error: "comment not found" });
      options.onComments?.(req.params.id);
      await logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "collaboration", action: "comment-removed", detail: `comment ${req.params.commentId} removed`,
      });
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Analyst triage tags on case entities (hand labels). GET lists them; POST attaches one to a
  // `(targetType, targetId)` entity (label normalized + deduped server-side); DELETE removes by
  // id. Add/remove ping live clients. Survives synthesis (side file, not InvestigationState).
  app.get("/cases/:id/tags", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    try {
      return res.status(200).json(await options.tagsStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/tags", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    const targetType = typeof req.body?.targetType === "string" ? req.body.targetType.trim() : "";
    const targetId = typeof req.body?.targetId === "string" ? req.body.targetId.trim() : "";
    const label = typeof req.body?.label === "string" ? req.body.label.trim() : "";
    if (!targetType || !targetId || !label) return res.status(400).json({ error: "targetType, targetId and label are required" });
    try {
      const tag = await options.tagsStore.add(req.params.id, {
        targetType, targetId, label,
        author: typeof req.body?.author === "string" ? req.body.author : "",
      });
      options.onTags?.(req.params.id);
      // A star is the reserved "starred" tag — a high-frequency triage gesture; don't spam the
      // activity log (it's hidden from every other tag surface too). Check the STORED label
      // (tag.label, already normalized by add()) so a differently-cased "Starred" is caught too —
      // symmetric with the DELETE side, which reads removed.label.
      if (tag.label !== STARRED_LABEL) {
        await logActivity(options.activityLogStore, options.onActivity, req.params.id, {
          category: "collaboration", action: "tag-added", actor: tag.author,
          detail: `tagged ${targetType} ${targetId} "${label}"`, targetType, targetId,
        });
      }
      return res.status(201).json(tag);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/tags/:tagId", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    try {
      const removed = await options.tagsStore.remove(req.params.id, req.params.tagId);
      if (!removed) return res.status(404).json({ error: "tag not found" });
      options.onTags?.(req.params.id);
      // A star is the reserved "starred" tag — a high-frequency triage gesture; don't spam the
      // activity log (it's hidden from every other tag surface too).
      if (removed.label !== STARRED_LABEL) {
        await logActivity(options.activityLogStore, options.onActivity, req.params.id, {
          category: "collaboration", action: "tag-removed", detail: `tag ${req.params.tagId} removed`,
        });
      }
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Analyst-pinned findings (#220). A small ordered shortlist of the findings the analyst cares
  // about most, kept in a per-case side file (survives synthesis). Every mutation returns the
  // full list + the cap so the dashboard can render the pinned strip and hint "N of MAX pinned".
  // GET lists; POST pins one (409 at the cap); PUT /order reorders (drag-to-reorder); DELETE
  // /:findingId unpins. Mutations ping live clients over the WS.
  app.get("/cases/:id/pinned-findings", async (req: Request, res: Response) => {
    if (!options.pinnedFindingsStore) return res.status(501).json({ error: "pinned findings not configured" });
    try {
      const pins = await options.pinnedFindingsStore.load(req.params.id);
      return res.status(200).json({ pins, limit: options.pinnedFindingsStore.limit });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/pinned-findings", async (req: Request, res: Response) => {
    if (!options.pinnedFindingsStore) return res.status(501).json({ error: "pinned findings not configured" });
    const findingId = typeof req.body?.findingId === "string" ? req.body.findingId.trim() : "";
    if (!findingId) return res.status(400).json({ error: "findingId is required" });
    try {
      const pins = await options.pinnedFindingsStore.pin(req.params.id, {
        findingId,
        pinnedBy: typeof req.body?.pinnedBy === "string" ? req.body.pinnedBy : "",
      });
      options.onPins?.(req.params.id);
      return res.status(201).json({ pins, limit: options.pinnedFindingsStore.limit });
    } catch (err) {
      if (err instanceof PinLimitError) return res.status(409).json({ error: err.message, limit: err.max });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/pinned-findings/order", async (req: Request, res: Response) => {
    if (!options.pinnedFindingsStore) return res.status(501).json({ error: "pinned findings not configured" });
    const order = Array.isArray(req.body?.order) ? req.body.order.filter((x: unknown): x is string => typeof x === "string") : null;
    if (!order) return res.status(400).json({ error: "order must be an array of findingId strings" });
    try {
      const pins = await options.pinnedFindingsStore.reorder(req.params.id, order);
      options.onPins?.(req.params.id);
      return res.status(200).json({ pins, limit: options.pinnedFindingsStore.limit });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/pinned-findings/:findingId", async (req: Request, res: Response) => {
    if (!options.pinnedFindingsStore) return res.status(501).json({ error: "pinned findings not configured" });
    try {
      const pins = await options.pinnedFindingsStore.unpin(req.params.id, req.params.findingId);
      options.onPins?.(req.params.id);
      return res.status(200).json({ pins, limit: options.pinnedFindingsStore.limit });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Finding assignment + workflow status (#87). A human owner and an analyst-editable triage status
  // (new/in_progress/in_review/resolved) for each finding, kept in a per-case side file so they
  // survive re-synthesis (the AI never touches them). GET lists every workflow record; PATCH upserts
  // one finding's assignee/status (an empty assignee + null status clears the record). Mirrors the
  // comments/tags/pinned pattern: the dashboard fetches the list and merges it onto the finding cards.
  app.get("/cases/:id/finding-workflow", async (req: Request, res: Response) => {
    if (!options.findingWorkflowStore) return res.status(501).json({ error: "finding workflow not configured" });
    try {
      return res.status(200).json(await options.findingWorkflowStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/findings/:findingId/workflow", async (req: Request, res: Response) => {
    if (!options.findingWorkflowStore) return res.status(501).json({ error: "finding workflow not configured" });
    // Only apply fields the caller actually sent, so a status-only PATCH leaves the assignee intact
    // (and vice versa). `status: ""`/null clears the status; an empty assignee clears the owner.
    const patch: { assignee?: string; status?: FindingWorkflowStatus | null; updatedBy?: string } = {};
    if (req.body?.assignee !== undefined) patch.assignee = String(req.body.assignee);
    if (req.body?.status !== undefined) {
      const raw = req.body.status;
      if (raw === null || raw === "") {
        patch.status = null;
      } else if ((FINDING_WORKFLOW_STATUSES as readonly string[]).includes(String(raw))) {
        patch.status = String(raw) as FindingWorkflowStatus;
      } else {
        return res.status(400).json({ error: `status must be one of ${FINDING_WORKFLOW_STATUSES.join(", ")} (or empty to clear)` });
      }
    }
    if (typeof req.body?.updatedBy === "string") patch.updatedBy = req.body.updatedBy;
    if (patch.assignee === undefined && patch.status === undefined) {
      return res.status(400).json({ error: "provide assignee and/or status to update" });
    }
    try {
      const record = await options.findingWorkflowStore.patch(req.params.id, req.params.findingId, patch);
      options.onFindingWorkflow?.(req.params.id);
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage", action: "finding-workflow", actor: patch.updatedBy ?? "",
        detail: record
          ? `finding ${req.params.findingId}: ${record.status ? `status=${record.status}` : "no status"}${record.assignee ? `, assignee=${record.assignee}` : ""}`
          : `finding ${req.params.findingId}: workflow cleared`,
        targetType: "finding", targetId: req.params.findingId,
      });
      return res.status(200).json({ record });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  // Per-case analyst notebook (hypotheses, notes, open questions). GET lists all entries;
  // POST adds one; PATCH updates text/type/linkedEntityIds; DELETE removes by id.
  // Entries survive synthesis (side file, not InvestigationState). The AI synthesis pass
  // reads notebook entries when ai-control.includeNotebook is true (opt-in).
  app.get("/cases/:id/notebook", async (req: Request, res: Response) => {
    if (!options.notebookStore) return res.status(501).json({ error: "notebook not configured" });
    try {
      return res.status(200).json(await options.notebookStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/notebook", async (req: Request, res: Response) => {
    if (!options.notebookStore) return res.status(501).json({ error: "notebook not configured" });
    const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
    if (!text) return res.status(400).json({ error: "text is required" });
    const typeIn = String(req.body?.type ?? "note");
    const type: NotebookEntryType = NOTEBOOK_ENTRY_TYPES.includes(typeIn as NotebookEntryType)
      ? (typeIn as NotebookEntryType)
      : "note";
    try {
      const entry = await options.notebookStore.add(req.params.id, {
        text,
        type,
        author: typeof req.body?.author === "string" ? req.body.author : undefined,
        linkedEntityIds: Array.isArray(req.body?.linkedEntityIds) ? req.body.linkedEntityIds.map(String) : undefined,
      });
      options.onNotebook?.(req.params.id);
      return res.status(201).json(entry);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/notebook/:entryId", async (req: Request, res: Response) => {
    if (!options.notebookStore) return res.status(501).json({ error: "notebook not configured" });
    const patch: { text?: string; type?: NotebookEntryType; linkedEntityIds?: string[] } = {};
    if (typeof req.body?.text === "string") patch.text = req.body.text;
    if (typeof req.body?.type === "string" && NOTEBOOK_ENTRY_TYPES.includes(req.body.type as NotebookEntryType)) {
      patch.type = req.body.type as NotebookEntryType;
    }
    if (Array.isArray(req.body?.linkedEntityIds)) patch.linkedEntityIds = req.body.linkedEntityIds.map(String);
    try {
      const updated = await options.notebookStore.update(req.params.id, req.params.entryId, patch);
      if (!updated) return res.status(404).json({ error: "notebook entry not found" });
      options.onNotebook?.(req.params.id);
      return res.status(200).json(updated);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/notebook/:entryId", async (req: Request, res: Response) => {
    if (!options.notebookStore) return res.status(501).json({ error: "notebook not configured" });
    try {
      const removed = await options.notebookStore.remove(req.params.id, req.params.entryId);
      if (!removed) return res.status(404).json({ error: "notebook entry not found" });
      options.onNotebook?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
