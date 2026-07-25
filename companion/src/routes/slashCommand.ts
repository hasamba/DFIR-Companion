import express, { type Express, type Request, type Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import {
  parseSlashCommand,
  formatFindingsCommand,
  formatFindingCommand,
  formatIocsCommand,
  formatStatusCommand,
  formatHelpCommand,
  resolveCaseId,
  isAllowed,
  isActionCommand,
  READ_ONLY_COMMANDS,
  type SlashCommandResponse,
} from "../analysis/slashCommand.js";
import { SlashCommandChannelStore, bindingKey } from "../analysis/slashCommandStore.js";
import { verifySlackSignature, verifyTeamsToken } from "../analysis/slashCommandAuth.js";
import { getAiLimiter } from "../http/rateLimiter.js";
import { isValidCaseId } from "../storage/caseStore.js";
import type { RouteContext } from "./context.js";

/**
 * Two-way war-room slash-command bot (#235). Receives Slack/Teams slash commands, authenticates
 * them (Slack HMAC signing secret / Teams bearer token), rate-limits per channel, and dispatches:
 *   - read-only commands (findings, finding, iocs, status, help, bind, unbind) respond synchronously.
 *   - action commands (ask, synthesize) ACK immediately with "working…" and post the result to the
 *     request's response_url when ready (Slack/Teams expect a response within 3s; AI calls take
 *     longer). `hunt` is supported as a route ACK + activity-log entry; full hunt deployment goes
 *     through the dashboard (the velociraptor hunt-deploy surface is too rich for a slash command).
 *
 * Per-channel case binding: `/dfir bind <caseId>` lets a channel omit the caseId from subsequent
 * commands. Access control: action commands are restricted to a configured user-id allowlist
 * (DFIR_SLACK_ACTION_USERS / DFIR_TEAMS_ACTION_USERS, comma-separated); read-only commands are
 * always allowed. When no allowlist is configured, access is open (the default for a localhost
 * tool).
 *
 * Routes:
 *   - POST /integrations/slack/command
 *   - POST /integrations/teams/command
 */
export function registerSlashCommandRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const channelStore = options.slashCommandChannelStore;
  if (!channelStore) return; // not configured — no bot

  // Slack sends application/x-www-form-urlencoded; capture the raw body for HMAC verification via
  // the parser's `verify` hook (called before parsing with the raw buffer).
  app.use(
    "/integrations/slack/command",
    express.urlencoded({
      extended: true,
      limit: "1mb",
      verify: (req: Request, _res: Response, buf: Buffer) => {
        (req as Request & { rawBody?: string }).rawBody = buf.toString("utf8");
      },
    }),
  );

  const limiter = getAiLimiter();
  const actionUsers = (): string[] =>
    (process.env.DFIR_SLACK_ACTION_USERS ?? "").split(",").map((s) => s.trim()).filter(Boolean);

  // ── Slack ───────────────────────────────────────────────────────────────────────────────
  app.post("/integrations/slack/command", async (req: Request, res: Response) => {
    const body = req.body ?? {};
    const channelId = String(body.channel_id ?? "");
    const userId = String(body.user_id ?? "");
    const responseUrl = String(body.response_url ?? "");
    const text = String(body.text ?? "");
    const rawBody = (req as Request & { rawBody?: string }).rawBody ?? "";

    // Rate limit per channel (keyed by "slack:<channelId>") so a runaway script in one war room
    // can't burn the server's AI budget.
    const limitKey = `slack:${channelId}`;
    if (!limiter.tryAcquire(limitKey)) {
      return res.status(429).json({ response_type: "ephemeral", text: "Rate limit exceeded — try again in a minute." });
    }

    const signingSecret = (process.env.DFIR_SLACK_SIGNING_SECRET ?? "").trim();
    const sig = verifySlackSignature({
      signingSecret,
      timestamp: String(req.headers["x-slack-request-timestamp"] ?? ""),
      rawBody,
      signature: String(req.headers["x-slack-signature"] ?? ""),
    });
    if (!sig.ok) {
      return res.status(401).json({ error: sig.error ?? "unauthorized" });
    }

    await dispatchCommand(req, res, {
      platform: "slack",
      channelId,
      userId,
      responseUrl,
      text,
      actionAllowlist: actionUsers(),
      channelStore,
      ctx,
    });
  });

  // ── Teams ───────────────────────────────────────────────────────────────────────────────
  // Teams webhook-based slash commands POST a JSON body with a bearer token in the Authorization
  // header. No raw-body HMAC needed.
  app.post("/integrations/teams/command", async (req: Request, res: Response) => {
    const body = req.body ?? {};
    const channelId = String(body.channel?.id ?? body.channelId ?? "");
    const userId = String(body.from?.id ?? body.userId ?? "");
    const responseUrl = String(body.responseUrl ?? "");
    const text = String(body.text ?? body.command ?? "");

    const limitKey = `teams:${channelId}`;
    if (!limiter.tryAcquire(limitKey)) {
      return res.status(429).json({ response_type: "ephemeral", text: "Rate limit exceeded — try again in a minute." });
    }

    const expectedToken = (process.env.DFIR_TEAMS_TOKEN ?? "").trim();
    const presented = String(req.headers["authorization"] ?? "").replace(/^Bearer\s+/i, "");
    const tok = verifyTeamsToken(presented || undefined, expectedToken);
    if (!tok.ok) {
      return res.status(401).json({ error: tok.error ?? "unauthorized" });
    }

    const teamsActionUsers = (process.env.DFIR_TEAMS_ACTION_USERS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    await dispatchCommand(req, res, {
      platform: "teams",
      channelId,
      userId,
      responseUrl,
      text,
      actionAllowlist: teamsActionUsers,
      channelStore,
      ctx,
    });
  });
}

interface DispatchInput {
  platform: "slack" | "teams";
  channelId: string;
  userId: string;
  responseUrl: string;
  text: string;
  actionAllowlist: readonly string[];
  channelStore: SlashCommandChannelStore;
  ctx: RouteContext;
}

async function dispatchCommand(_req: Request, res: Response, input: DispatchInput): Promise<void> {
  const { platform, channelId, userId, responseUrl, text, actionAllowlist, channelStore, ctx } = input;
  const { options } = ctx;
  const cmd = parseSlashCommand(text);
  const bindKey = bindingKey(platform, channelId);
  const binding = await channelStore.get(bindKey).catch(() => undefined);

  // bind/unbind are handled inline (no caseId needed for unbind; bind takes the caseId arg).
  if (cmd.name === "unbind") {
    await channelStore.unbind(bindKey).catch(() => false);
    res.status(200).json({ response_type: "ephemeral", text: "Channel case binding cleared." });
    return;
  }
  if (cmd.name === "help") {
    const r = formatHelpCommand();
    res.status(200).json(toSlackResponse(r, true));
    return;
  }

  // Access control: action commands require the user to be in the allowlist.
  if (!isAllowed(cmd.name, userId, actionAllowlist)) {
    res.status(403).json({ response_type: "ephemeral", text: `User ${userId} is not permitted to run /dfir ${cmd.name}.` });
    return;
  }

  if (cmd.name === "bind") {
    const caseId = cmd.caseId?.trim() ?? "";
    if (!caseId || !isValidCaseId(caseId)) {
      res.status(400).json({ response_type: "ephemeral", text: "Usage: /dfir bind <caseId>" });
      return;
    }
    await channelStore.bind(bindKey, caseId);
    res.status(200).json({ response_type: "ephemeral", text: `Channel bound to case ${caseId}.` });
    return;
  }

  // Resolve the caseId (explicit arg → channel binding → empty).
  const caseId = resolveCaseId(cmd, binding);
  if (!caseId || !isValidCaseId(caseId)) {
    const hint = binding ? `This channel is bound to case "${binding.caseId}".` : "Bind this channel first with `/dfir bind <caseId>`.";
    res.status(400).json({ response_type: "ephemeral", text: `A valid caseId is required. ${hint}` });
    return;
  }
  if (!options.stateStore) {
    res.status(501).json({ response_type: "ephemeral", text: "State store not configured." });
    return;
  }

  // Read-only commands respond synchronously.
  if (READ_ONLY_COMMANDS.includes(cmd.name)) {
    try {
      const state = await options.stateStore.load(caseId);
      let r: SlashCommandResponse;
      switch (cmd.name) {
        case "findings":
          r = formatFindingsCommand(state);
          break;
        case "finding":
          r = formatFindingCommand(state, cmd.arg ?? "");
          break;
        case "iocs":
          r = formatIocsCommand(state, cmd.iocFilter);
          break;
        case "status":
          r = formatStatusCommand(state);
          break;
        default:
          r = formatHelpCommand();
      }
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "collaboration",
        action: "slash-command",
        detail: `/dfir ${cmd.name} (user ${userId}, ${platform} channel ${channelId})`,
      });
      res.status(200).json(toSlackResponse(r, false));
      return;
    } catch (err) {
      res.status(500).json({ response_type: "ephemeral", text: `Error loading case ${caseId}: ${(err as Error).message}` });
      return;
    }
  }

  // Action commands: ACK immediately, then run async and post the result to response_url.
  if (isActionCommand(cmd.name)) {
    if (!responseUrl) {
      res.status(202).json({ response_type: "ephemeral", text: `Working on /dfir ${cmd.name}… (no response_url — result will appear in the activity log.)` });
      return;
    }
    res.status(202).json({ response_type: "ephemeral", text: `Working on /dfir ${cmd.name} for case ${caseId}…` });
    void runActionCommand(cmd.name, caseId, cmd.arg ?? "", responseUrl, input).catch((err) => {
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "collaboration",
        action: "slash-command-error",
        detail: `/dfir ${cmd.name} failed: ${(err as Error).message}`,
      });
    });
    return;
  }

  // Unreachable (parseSlashCommand only returns known names), but keep a safe fallback.
  res.status(200).json(toSlackResponse(formatHelpCommand(), true));
}

async function runActionCommand(
  name: string,
  caseId: string,
  arg: string,
  responseUrl: string,
  input: DispatchInput,
): Promise<void> {
  const { options } = input.ctx;
  if (name === "synthesize") {
    input.ctx.resynthesizeInBackground(caseId);
    logActivity(options.activityLogStore, options.onActivity, caseId, {
      category: "ai",
      action: "slash-command-synthesize",
      detail: `/dfir synthesize triggered by user ${input.userId}`,
    });
    await postToResponseUrl(responseUrl, { response_type: "ephemeral", text: `Re-synthesis started for case ${caseId}. The diff summary will appear in the dashboard and activity log when done.` });
    return;
  }
  if (name === "ask") {
    if (!arg.trim()) {
      await postToResponseUrl(responseUrl, { response_type: "ephemeral", text: "Usage: /dfir ask <question>" });
      return;
    }
    if (!options.pipeline) {
      await postToResponseUrl(responseUrl, { response_type: "ephemeral", text: "AI pipeline not configured." });
      return;
    }
    try {
      const answer = await options.pipeline.ask(caseId, arg);
      const lines = [answer.answer || "(no answer)", ...(answer.pointer ? [`Next: ${answer.pointer}`] : [])];
      await postToResponseUrl(responseUrl, toSlackResponse({ title: `Q: ${arg}`, lines }, false));
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "slash-command-ask",
        detail: `/dfir ask "${arg.slice(0, 120)}" → ${answer.status}`,
      });
    } catch (err) {
      await postToResponseUrl(responseUrl, { response_type: "ephemeral", text: `AI ask failed: ${(err as Error).message}` });
    }
    return;
  }
  if (name === "hunt") {
    // Hunt deployment via the bot is ACK-only — the velociraptor hunt-deploy surface (per-client
    // targeting, artifact selection, bundle resolution) is too rich for a slash command. The
    // dashboard's hunt panel is the deploy surface; the bot surfaces the technique to hunt.
    await postToResponseUrl(responseUrl, {
      response_type: "ephemeral",
      text: `Hunt technique "${arg || "(none specified)"}" noted for case ${caseId}. Deploy the hunt from the dashboard's Velociraptor hunt panel.`,
    });
    logActivity(options.activityLogStore, options.onActivity, caseId, {
      category: "hunt",
      action: "slash-command-hunt",
      detail: `/dfir hunt ${arg} (user ${input.userId}) — deploy via dashboard`,
    });
    return;
  }
}

function toSlackResponse(r: SlashCommandResponse, ephemeral: boolean): { response_type: string; text: string } {
  const body = r.lines.filter(Boolean).map((l) => `• ${l}`).join("\n");
  return {
    response_type: ephemeral ? "ephemeral" : "in_channel",
    text: `${r.title}${body ? `\n${body}` : ""}`,
  };
}

async function postToResponseUrl(url: string, payload: unknown): Promise<void> {
  if (!url) return;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    // best-effort — a failure to post the async result is logged via the action-command catch.
  }
}