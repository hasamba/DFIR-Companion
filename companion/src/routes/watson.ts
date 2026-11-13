import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import { WATSON_TURN_TEXT_MAX } from "../analysis/ai/watson/chatStore.js";
import { WATSON_PASTE_MAX_BYTES } from "../analysis/ai/watson/pasteSearch.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
  type WatsonProposalAction,
} from "../analysis/ai/watson/proposals.js";
import type { WatsonRoundDeps } from "../analysis/ai/watson/pipelineRound.js";
import { newWatsonId } from "../analysis/ai/watson/roundProposals.js";
import { WatsonAiOff, WatsonCostLimitReached } from "../analysis/ai/watson/round.js";
import type { WatsonChat, WatsonPaste } from "../analysis/ai/watson/types.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

/**
 * Watson, the per-case AI investigation chat (all under /cases/:id/watson). Team policy needs no code
 * here: GET is a read, every POST a write. A closed or archived case refuses the POSTs by default
 * (composition/caseWriteAllowlist.ts), and this file adds nothing to that allowlist.
 *
 *   GET  /watson                         the chat
 *   POST /watson/message                 one analyst message → one round (a model call)
 *   POST /watson/paste                   store pasted text or a text file as case evidence, then a round
 *   POST /watson/proposals/:pid/:action  apply | reject | undo one question proposal (no model call)
 *
 * A paste is stored and attached only. Nothing parses it into rows (phase 2), and it never starts a
 * synthesis: the case's conclusions are marked out of date instead (#1599).
 */

const PROPOSAL_ACTIONS: readonly string[] = ["apply", "reject", "undo"];
const DEFAULT_PASTE_NAME = "pasted-text.txt";
const FILENAME_MAX = 200;

/** A positive finite number from a setting, else undefined: blank, junk, zero and negatives mean "no limit". */
export function positiveLimit(raw: string | undefined): number | undefined {
  const text = raw?.trim();
  const n = Number(text);
  return text && Number.isFinite(n) && n > 0 ? n : undefined;
}

/** Newline-separated lines, counting a final line with no newline; no array of lines is built. */
export function countLines(text: string): number {
  if (!text) return 0;
  let lines = 0;
  for (let at = text.indexOf("\n"); at !== -1; at = text.indexOf("\n", at + 1)) lines++;
  return text.endsWith("\n") ? lines : lines + 1;
}

/** What a model-calling route needs once its checks pass. */
interface WatsonRun {
  pipeline: NonNullable<RouteContext["options"]["pipeline"]>;
  deps: WatsonRoundDeps;
}

const stringOrEmpty = (v: unknown): string => (typeof v === "string" ? v : "");

function actorName(req: Request): string {
  return requestAuthentication(req)?.identity.displayName ?? "analyst";
}

export function registerWatsonRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  const caseMissing = async (caseId: string): Promise<boolean> =>
    (await store.getCaseMeta(caseId).catch(() => null)) === null;

  /** The model Watson uses and the limits, read per request so a Settings change applies at once. */
  function roundDeps(): WatsonRoundDeps | undefined {
    const provider = options.watsonProvider?.();
    if (!options.watsonChatStore || !provider) return undefined;
    return {
      chatStore: options.watsonChatStore,
      cases: store,
      provider,
      isAiEnabled: async (id) => (await ctx.getControl(id)).enabled,
      costLimitUSD: positiveLimit(process.env.DFIR_AI_WATSON_COST_LIMIT_USD),
      tokenLimit: positiveLimit(process.env.DFIR_AI_WATSON_TOKEN_LIMIT),
    };
  }

  function sendWatsonError(res: Response, err: unknown): Response {
    if (
      err instanceof WatsonAiOff ||
      err instanceof WatsonCostLimitReached ||
      err instanceof WatsonProposalStateError ||
      err instanceof WatsonProposalConflict
    ) {
      return res.status(409).json({ error: err.message });
    }
    if (err instanceof WatsonProposalNotFoundError) return res.status(404).json({ error: err.message });
    return sendPipelineError(res, err); // a Presidio hold answers 409 with its findings; the rest is a 500
  }

  /** The checks every model-calling route makes before it saves anything. Null means "go ahead". */
  async function refuseBeforeWork(res: Response, caseId: string): Promise<WatsonRun | null> {
    if (await caseMissing(caseId)) {
      res.status(404).json({ error: "case not found" });
      return null;
    }
    const deps = roundDeps();
    const pipeline = options.pipeline;
    if (!deps || !pipeline) {
      res.status(501).json({ error: "AI provider not configured for Watson" });
      return null;
    }
    if (!(await deps.isAiEnabled(caseId))) {
      res.status(409).json({ error: new WatsonAiOff().message });
      return null;
    }
    return { pipeline, deps };
  }

  app.get("/cases/:id/watson", async (req: Request, res: Response) => {
    if (!options.watsonChatStore) return res.status(501).json({ error: "Watson is not configured" });
    if (await caseMissing(req.params.id)) return res.status(404).json({ error: "case not found" });
    try {
      return res.status(200).json(await options.watsonChatStore.load(req.params.id));
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });

  app.post("/cases/:id/watson/message", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const text = stringOrEmpty(req.body?.text).trim();
    if (!text) return res.status(400).json({ error: "text is required" });
    if (text.length > WATSON_TURN_TEXT_MAX) {
      return res.status(400).json({
        error: `message is longer than ${WATSON_TURN_TEXT_MAX} characters; send long text with the paste button`,
      });
    }
    const run = await refuseBeforeWork(res, caseId);
    if (!run) return res;
    try {
      const chat = await run.pipeline.watsonRound(caseId, { text, actor: actorName(req) }, run.deps);
      return res.status(200).json(chat);
    } catch (err) {
      return sendWatsonError(res, err);
    } finally {
      options.onWatson?.(caseId); // the round saves the analyst turn (or an error turn) even when it fails
    }
  });

  app.post("/cases/:id/watson/paste", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const text = stringOrEmpty(req.body?.text);
    if (!text.trim()) return res.status(400).json({ error: "text is required" });
    const bytes = Buffer.byteLength(text, "utf8");
    if (bytes > WATSON_PASTE_MAX_BYTES) {
      return res.status(413).json({ error: `pasted text is larger than ${WATSON_PASTE_MAX_BYTES} bytes` });
    }
    const run = await refuseBeforeWork(res, caseId);
    if (!run) return res;
    const filename = stringOrEmpty(req.body?.filename).trim().slice(0, FILENAME_MAX) || DEFAULT_PASTE_NAME;
    const note = stringOrEmpty(req.body?.message)
      .trim()
      .slice(0, WATSON_TURN_TEXT_MAX - 200);
    const actor = actorName(req);
    try {
      const paste = await storePaste(caseId, filename, text, bytes, actor);
      await ctx.markConclusionsOutOfDate(caseId, "Watson paste stored");
      const lead = `Pasted ${paste.filename} (${paste.lines} lines, ${paste.bytes} bytes).`;
      const chat = await run.pipeline.watsonRound(
        caseId,
        { text: note ? `${lead}\n${note}` : lead, actor, pasteId: paste.id },
        run.deps,
      );
      return res.status(200).json(chat);
    } catch (err) {
      return sendWatsonError(res, err);
    } finally {
      options.onWatson?.(caseId);
    }
  });

  /** Save the text as case evidence (imports/ + the import log + custody), then record it on the chat. */
  async function storePaste(
    caseId: string,
    filename: string,
    text: string,
    bytes: number,
    actor: string,
  ): Promise<WatsonPaste> {
    const seq = await store.nextImportSeq(caseId);
    const safeName = filename.replace(/[^\w.-]+/g, "_").slice(0, 80) || DEFAULT_PASTE_NAME;
    const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
    const at = new Date().toISOString();
    await store.saveImport(caseId, storedName, text, {
      source: "watson-chat",
      trigger: "watson-paste",
      collectedBy: actor,
    });
    await store.appendImport(caseId, {
      caseId,
      sequenceNumber: seq,
      importedAt: at,
      filename: storedName,
      originalName: filename,
      rows: 0, // stored, not parsed (phase 2)
      bytes,
    });
    const paste: WatsonPaste = {
      id: newWatsonId("wf"),
      storedName,
      filename,
      bytes,
      lines: countLines(text),
      at,
    };
    await options.watsonChatStore!.update(caseId, (chat: WatsonChat) => ({
      ...chat,
      pastes: [...chat.pastes, paste],
    }));
    return paste;
  }

  app.post("/cases/:id/watson/proposals/:pid/:action", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const action = req.params.action;
    if (!PROPOSAL_ACTIONS.includes(action)) {
      return res.status(400).json({ error: "action must be apply, reject or undo" });
    }
    if (!options.watsonChatStore || !options.stateStore || !options.stateLock || !options.activityLogStore) {
      return res.status(501).json({ error: "Watson is not configured" });
    }
    if (await caseMissing(caseId)) return res.status(404).json({ error: "case not found" });
    try {
      const result = await applyWatsonProposal(
        {
          stateStore: options.stateStore,
          stateLock: options.stateLock,
          chatStore: options.watsonChatStore,
          activity: options.activityLogStore,
        },
        caseId,
        req.params.pid,
        action as WatsonProposalAction,
        actorName(req),
      );
      // The overview state has no forensic timeline, so only the key questions go out.
      if (result.state) options.onStateChanged?.(caseId);
      return res.status(200).json({
        chat: result.chat,
        ...(result.state ? { state: { keyQuestions: result.state.keyQuestions } } : {}),
      });
    } catch (err) {
      return sendWatsonError(res, err);
    } finally {
      options.onWatson?.(caseId);
    }
  });
}
