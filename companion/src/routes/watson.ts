import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import { WATSON_TURN_TEXT_MAX } from "../analysis/ai/watson/chatStore.js";
import { WATSON_PASTE_MAX_BYTES } from "../analysis/ai/watson/pasteSearch.js";
import { addAnswerAsQuestion } from "../analysis/ai/watson/addQuestion.js";
import { startNewThread } from "../analysis/ai/watson/thread.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
  type WatsonProposalAction,
  type WriterDeps,
} from "../analysis/ai/watson/proposals.js";
import type { WatsonRoundDeps } from "../analysis/ai/watson/pipelineRound.js";
import { newWatsonId } from "../analysis/ai/watson/roundProposals.js";
import { WatsonAiOff, WatsonCostLimitReached } from "../analysis/ai/watson/round.js";
import type { WatsonChat, WatsonPaste } from "../analysis/ai/watson/types.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";
import { caseVeloConnected, watsonRoundDeps } from "./watsonDeps.js";
import { ingestWatsonPaste } from "./watsonPasteIngest.js";
import { registerWatsonVeloLaunchRoutes, watsonVeloLaunchDeps } from "./watsonVeloLaunch.js";
import { logActivity } from "../analysis/activityLog.js";
import {
  isWatsonRunMode,
  watsonModeDetail,
  watsonModePatch,
  watsonRunMode,
} from "../analysis/ai/watson/runMode.js";
import { ingestRows, withPasteIngest } from "../analysis/ai/watson/pasteIngestChat.js";

/**
 * Watson, the per-case AI investigation chat (all under /cases/:id/watson). Team policy needs no code
 * here: GET is a read, every POST a write. A closed or archived case refuses the POSTs by default
 * (composition/caseWriteAllowlist.ts), and this file adds nothing to that allowlist.
 *
 *   GET  /watson                         the chat
 *   GET  /watson/history?before=&limit= older turns from the full history file, oldest first: { turns, more }
 *   POST /watson/message                 one analyst message → one round (a model call)
 *   POST /watson/paste                   store pasted text or a text file as case evidence, then a round
 *   POST /watson/proposals/:pid/:action  apply | reject | undo one question proposal (no model call)
 *   POST /watson/turns/:tid/add-question add a turn's free-form answer to the open questions (no model call)
 *   POST /watson/new-thread              start a fresh chat thread; Watson's memory stays (no model call)
 *   POST /watson/mode {mode}             switch the case's run mode, approve | auto → { mode } (no model call)
 *
 * A paste is stored as evidence and, in a format a built-in importer reads, parsed into rows whose
 * tagger promotions wait as Watson proposals (routes/watsonPasteIngest.ts). It never starts a
 * synthesis: the case's conclusions are marked out of date instead (#1599).
 */

const PROPOSAL_ACTIONS: readonly string[] = ["apply", "reject", "undo"];
const HISTORY_PAGE_DEFAULT = 100;
const HISTORY_PAGE_MAX = 200;
const DEFAULT_PASTE_NAME = "pasted-text.txt";
const FILENAME_MAX = 200;
/** Set on a paste response once the text is saved as evidence, so a failed round can say so. */
export const PASTE_STORED_HEADER = "X-Watson-Paste-Stored";

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

type Pipeline = NonNullable<RouteContext["options"]["pipeline"]>;
const promoteVia =
  (pipeline: Pipeline): NonNullable<WriterDeps["promoteEvents"]> =>
  (caseId, events, opts) =>
    pipeline.promoteSuperTimelineWithOutcome(caseId, events, opts);

const stringOrEmpty = (v: unknown): string => (typeof v === "string" ? v : "");

function actorName(req: Request): string {
  return requestAuthentication(req)?.identity.displayName ?? "analyst";
}

export function registerWatsonRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  const caseMissing = async (caseId: string): Promise<boolean> =>
    (await store.getCaseMeta(caseId).catch(() => null)) === null;

  /** The model Watson uses and the limits, read per request so a Settings change applies at once. */
  const roundDeps = (): WatsonRoundDeps | undefined => watsonRoundDeps(ctx);
  registerWatsonVeloLaunchRoutes(app, ctx, sendWatsonError); // before /proposals/:pid/:action

  /** What applying a proposal (or adding an answer as a question) needs; undefined when not wired. */
  function proposalDeps(): WriterDeps | undefined {
    if (!options.watsonChatStore || !options.stateStore || !options.stateLock || !options.activityLogStore) {
      return undefined;
    }
    return {
      stateStore: options.stateStore,
      stateLock: options.stateLock,
      chatStore: options.watsonChatStore,
      activity: options.activityLogStore,
      cases: store,
      markConclusionsOutOfDate: ctx.markConclusionsOutOfDate,
      reportText: options.reportMetaStore,
      ...(options.pipeline ? { promoteEvents: promoteVia(options.pipeline) } : {}),
      veloLaunch: watsonVeloLaunchDeps(ctx),
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
      // providerConfigured: false tells the dashboard to hide the panel; the chat stays readable.
      const chat = await options.watsonChatStore.load(req.params.id);
      const runMode = watsonRunMode(await ctx.getControl(req.params.id));
      const veloConnected = caseVeloConnected(ctx, req.params.id);
      return res
        .status(200)
        .json({ ...chat, providerConfigured: !!roundDeps() && !!options.pipeline, runMode, veloConnected });
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });

  app.get("/cases/:id/watson/history", async (req: Request, res: Response) => {
    if (!options.watsonChatStore) return res.status(501).json({ error: "Watson is not configured" });
    if (await caseMissing(req.params.id)) return res.status(404).json({ error: "case not found" });
    const before = stringOrEmpty(req.query.before);
    const asked = Number.parseInt(stringOrEmpty(req.query.limit), 10);
    const limit = Number.isFinite(asked)
      ? Math.min(HISTORY_PAGE_MAX, Math.max(1, asked))
      : HISTORY_PAGE_DEFAULT;
    try {
      const page = await options.watsonChatStore.history.page(req.params.id, {
        ...(before ? { before } : {}),
        limit,
      });
      return res.status(200).json(page);
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
    // One line: the name is printed in Watson's prompt and in the chat.
    const filename =
      stringOrEmpty(req.body?.filename)
        .replace(/[\r\n]+/g, " ")
        .trim()
        .slice(0, FILENAME_MAX) || DEFAULT_PASTE_NAME;
    const note = stringOrEmpty(req.body?.message)
      .trim()
      .slice(0, WATSON_TURN_TEXT_MAX - 200);
    const actor = actorName(req);
    try {
      const paste = await storePaste(caseId, filename, text, bytes, actor);
      res.setHeader(PASTE_STORED_HEADER, "1");
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

  /**
   * Save the text as case evidence (imports/ + custody), parse it into rows when a built-in importer
   * reads its format (routes/watsonPasteIngest.ts), log the import with the parsed row count, then
   * record the paste on the chat with what parsing did: one update, before the round runs.
   */
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
    const paste: WatsonPaste = {
      id: newWatsonId("wf"),
      storedName,
      filename,
      bytes,
      lines: countLines(text),
      at,
    };
    const ingest = await ingestWatsonPaste(ctx, caseId, paste, text);
    await store.appendImport(caseId, {
      caseId,
      sequenceNumber: seq,
      importedAt: at,
      filename: storedName,
      originalName: filename,
      rows: ingestRows(ingest),
      bytes,
    });
    await options.watsonChatStore!.update(caseId, (chat: WatsonChat) => withPasteIngest(chat, paste, ingest));
    return paste;
  }

  app.post("/cases/:id/watson/proposals/:pid/:action", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const action = req.params.action;
    if (!PROPOSAL_ACTIONS.includes(action)) {
      return res.status(400).json({ error: "action must be apply, reject or undo" });
    }
    const deps = proposalDeps();
    if (!deps) return res.status(501).json({ error: "Watson is not configured" });
    if (await caseMissing(caseId)) return res.status(404).json({ error: "case not found" });
    try {
      const result = await applyWatsonProposal(
        deps,
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

  app.post("/cases/:id/watson/turns/:tid/add-question", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const deps = proposalDeps();
    if (!deps) return res.status(501).json({ error: "Watson is not configured" });
    if (await caseMissing(caseId)) return res.status(404).json({ error: "case not found" });
    try {
      const result = await addAnswerAsQuestion(deps, caseId, req.params.tid, actorName(req));
      options.onStateChanged?.(caseId);
      return res.status(200).json({ chat: result.chat, state: { keyQuestions: result.state.keyQuestions } });
    } catch (err) {
      return sendWatsonError(res, err);
    } finally {
      options.onWatson?.(caseId);
    }
  });

  app.post("/cases/:id/watson/mode", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const mode: unknown = req.body?.mode;
    if (!isWatsonRunMode(mode)) return res.status(400).json({ error: "mode must be approve or auto" });
    if (await caseMissing(caseId)) return res.status(404).json({ error: "case not found" });
    try {
      if (watsonRunMode(await ctx.getControl(caseId)) === mode) return res.status(200).json({ mode });
      const auth = requestAuthentication(req);
      const actor = actorName(req);
      await ctx.setControl(caseId, watsonModePatch(mode, { id: auth?.identity.id, name: actor }));
      await logActivity(options.activityLogStore, options.onActivity, caseId, {
        actor,
        category: "ai",
        action: "watson.mode",
        detail: watsonModeDetail(mode),
      });
      return res.status(200).json({ mode });
    } catch (err) {
      return sendWatsonError(res, err);
    } finally {
      options.onWatson?.(caseId);
    }
  });

  app.post("/cases/:id/watson/new-thread", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!options.watsonChatStore) return res.status(501).json({ error: "Watson is not configured" });
    if (await caseMissing(caseId)) return res.status(404).json({ error: "case not found" });
    try {
      return res.status(200).json(await startNewThread(options.watsonChatStore, caseId));
    } catch (err) {
      return sendWatsonError(res, err);
    } finally {
      options.onWatson?.(caseId);
    }
  });
}
