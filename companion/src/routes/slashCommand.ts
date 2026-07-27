import express, { type Express, type Request, type Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { redactPaths } from "../analysis/redactPaths.js";
import {
  parseSlashCommand,
  resolveCommand,
  formatFindingsCommand,
  formatFindingCommand,
  formatIocsCommand,
  formatStatusCommand,
  formatHelpCommand,
  isAllowed,
  isCaseAccessAllowed,
  isAsyncCommand,
  READ_ONLY_COMMANDS,
  type ResolvedSlashCommand,
  type SlashCommandResponse,
} from "../analysis/slashCommand.js";
import { SlashCommandChannelStore, bindingKey, type ChatPlatform } from "../analysis/slashCommandStore.js";
import {
  verifySlackSignature,
  verifyTeamsToken,
  verifyTelegramSecret,
  isAllowedResponseUrl,
  parseHostList,
} from "../analysis/slashCommandAuth.js";
import { getAiLimiter } from "../http/rateLimiter.js";
import { isValidCaseId } from "../storage/caseStore.js";
import type { RouteContext } from "./context.js";

/**
 * Two-way war-room slash-command bot (#235). Receives Slack / Teams / Telegram slash commands,
 * authenticates them, rate-limits per channel, and dispatches:
 *   - read-only commands (findings, finding, iocs, status, help, unbind) respond synchronously.
 *   - async commands (ask, hunt, synthesize) ACK immediately with "working…" and deliver the
 *     result out of band when ready (chat platforms want a response within ~3s; AI calls take
 *     longer). `hunt` records the technique and points at the dashboard — the Velociraptor
 *     hunt-deploy surface (per-client targeting, artifact selection) is too rich for a slash
 *     command.
 *
 * Per-channel case binding: `/dfir bind <caseId>` lets a channel omit the caseId from subsequent
 * commands.
 *
 * ── Access control ──────────────────────────────────────────────────────────────────────
 * Privileged commands (ask, hunt, synthesize, and bind — it decides which case the whole room can
 * read) are restricted to a configured user-id allowlist: DFIR_SLACK_ACTION_USERS /
 * DFIR_TEAMS_ACTION_USERS / DFIR_TELEGRAM_ACTION_USERS, comma-separated. Once an allowlist IS
 * configured, everyone else is also confined to the channel's bound case, so an ordinary chat
 * member cannot read an unrelated case just by naming it. With no allowlist the bot is open,
 * matching the rest of this localhost-first tool.
 *
 * Password-protected cases are refused over chat entirely: the case-password gate lives on
 * `/cases/:id` and a chat message carries no unlock cookie, so serving a locked case's state from
 * here would be a way around it.
 *
 * ── Status codes ────────────────────────────────────────────────────────────────────────
 * Only pre-authentication failures use error statuses (401 unauthenticated, 429 rate-limited) —
 * those replies are for an impostor, not a person. Everything after a request authenticates
 * answers 200 with the message in the platform's own envelope, because all three platforms
 * discard the body of a non-2xx reply and show the user a generic failure instead. Telegram in
 * particular RETRIES a non-2xx webhook delivery, which would re-run the command.
 *
 * Routes:
 *   - POST /integrations/slack/command
 *   - POST /integrations/teams/command
 *   - POST /integrations/telegram/command
 *
 * Note these endpoints are reached from the internet (via a tunnel or reverse proxy), so the
 * hostname they arrive under must be named in DFIR_ALLOWED_HOSTS — the DNS-rebinding host guard
 * (#280) rejects unknown Host headers before any route runs. See companion/.env.example.
 */
export function registerSlashCommandRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const channelStore = options.slashCommandChannelStore;
  if (!channelStore) return; // not configured — no bot

  // Slack sends application/x-www-form-urlencoded; capture the raw body for HMAC verification via
  // the parser's `verify` hook (called before parsing, with the raw buffer). Teams and Telegram
  // send JSON, which the app-wide express.json() already handles.
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
  const envList = (name: string): string[] => parseHostList(process.env[name]);

  // ── Slack ───────────────────────────────────────────────────────────────────────────────
  app.post("/integrations/slack/command", async (req: Request, res: Response) => {
    const body = req.body ?? {};
    const channelId = String(body.channel_id ?? "");

    // Authenticate BEFORE spending the channel's rate-limit budget: the key comes from the request
    // body, so limiting first would let an unauthenticated caller burn a real war room's quota.
    const sig = verifySlackSignature({
      signingSecret: (process.env.DFIR_SLACK_SIGNING_SECRET ?? "").trim(),
      timestamp: String(req.headers["x-slack-request-timestamp"] ?? ""),
      rawBody: (req as Request & { rawBody?: string }).rawBody ?? "",
      signature: String(req.headers["x-slack-signature"] ?? ""),
    });
    if (!sig.ok) return void res.status(401).json({ error: sig.error ?? "unauthorized" });
    if (!limiter.tryAcquire(`slack:${channelId}`)) {
      return void res.status(429).json({ error: "rate limit exceeded — try again in a minute" });
    }

    await dispatchCommand(res, {
      platform: "slack",
      channelId,
      userId: String(body.user_id ?? ""),
      responseUrl: String(body.response_url ?? ""),
      text: String(body.text ?? ""),
      actionAllowlist: envList("DFIR_SLACK_ACTION_USERS"),
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

    const tok = verifyTeamsToken(
      String(req.headers["authorization"] ?? "") || undefined,
      (process.env.DFIR_TEAMS_TOKEN ?? "").trim(),
    );
    if (!tok.ok) return void res.status(401).json({ error: tok.error ?? "unauthorized" });
    if (!limiter.tryAcquire(`teams:${channelId}`)) {
      return void res.status(429).json({ error: "rate limit exceeded — try again in a minute" });
    }

    await dispatchCommand(res, {
      platform: "teams",
      channelId,
      userId: String(body.from?.id ?? body.userId ?? ""),
      responseUrl: String(body.responseUrl ?? ""),
      text: String(body.text ?? body.command ?? ""),
      actionAllowlist: envList("DFIR_TEAMS_ACTION_USERS"),
      channelStore,
      ctx,
    });
  });

  // ── Telegram ────────────────────────────────────────────────────────────────────────────
  // Telegram POSTs an Update object and authenticates with the secret_token given to setWebhook,
  // echoed back in X-Telegram-Bot-Api-Secret-Token. There is no response_url: the synchronous
  // reply carries a `method` field that Telegram executes, and async results go to the Bot API
  // directly (see deliverAsyncResult).
  app.post("/integrations/telegram/command", async (req: Request, res: Response) => {
    const body = req.body ?? {};
    const message = body.message ?? body.edited_message ?? body.channel_post ?? {};
    const channelId = String(message.chat?.id ?? "");

    const tok = verifyTelegramSecret(
      String(req.headers["x-telegram-bot-api-secret-token"] ?? "") || undefined,
      (process.env.DFIR_TELEGRAM_SECRET_TOKEN ?? "").trim(),
    );
    if (!tok.ok) return void res.status(401).json({ error: tok.error ?? "unauthorized" });
    if (!limiter.tryAcquire(`telegram:${channelId}`)) {
      return void res.status(429).json({ error: "rate limit exceeded — try again in a minute" });
    }

    await dispatchCommand(res, {
      platform: "telegram",
      channelId,
      userId: String(message.from?.id ?? ""),
      responseUrl: "", // Telegram delivers through the Bot API, not a per-request URL
      text: String(message.text ?? message.caption ?? ""),
      actionAllowlist: envList("DFIR_TELEGRAM_ACTION_USERS"),
      channelStore,
      ctx,
    });
  });
}

interface DispatchInput {
  platform: ChatPlatform;
  channelId: string;
  userId: string;
  responseUrl: string;
  text: string;
  actionAllowlist: readonly string[];
  channelStore: SlashCommandChannelStore;
  ctx: RouteContext;
}

async function dispatchCommand(res: Response, input: DispatchInput): Promise<void> {
  const { platform, channelId, userId, text, actionAllowlist, channelStore, ctx } = input;
  const { options, store } = ctx;
  const reply = (r: SlashCommandResponse | string, ephemeral = true): void => {
    res.status(200).json(chatResponse(input, typeof r === "string" ? { title: r, lines: [] } : r, ephemeral));
  };
  const audit = (caseId: string, entry: Parameters<typeof logActivity>[3]): void => {
    void logActivity(options.activityLogStore, options.onActivity, caseId, { actor: `${platform}:${userId}`, ...entry });
  };

  const parsed = parseSlashCommand(text);
  const bindKey = bindingKey(platform, channelId);
  const binding = await channelStore.get(bindKey).catch(() => undefined);

  // Is the first token the name of a real case, or the first word of the argument? Only the store
  // knows — see resolveCommand's docblock for why guessing positionally is wrong.
  const firstToken = parsed.tokens[0];
  const firstTokenIsKnownCase =
    !!firstToken && isValidCaseId(firstToken) && (await store.caseExists(firstToken).catch(() => false));
  const cmd = resolveCommand(parsed, binding, firstTokenIsKnownCase);

  if (cmd.name === "help") return reply(formatHelpCommand());

  if (cmd.name === "unbind") {
    const previous = binding?.caseId;
    await channelStore.unbind(bindKey).catch(() => false);
    if (previous) {
      audit(previous, {
        category: "collaboration",
        action: "slash-command-unbind",
        detail: `${platform} channel ${channelId} unbound from case ${previous}`,
      });
    }
    return reply(previous ? `Channel case binding cleared (was ${previous}).` : "This channel was not bound to a case.");
  }

  // Permission gate before anything touches case data. Audited against the resolved case when that
  // case really exists, so a denial is visible in the case's own activity log.
  if (!isAllowed(cmd.name, userId, actionAllowlist)) {
    await auditDenial(input, cmd, `not permitted to run /dfir ${cmd.name}`);
    return reply(`User ${userId || "(unknown)"} is not permitted to run /dfir ${cmd.name}.`);
  }

  if (cmd.name === "bind") {
    if (!cmd.caseId || !isValidCaseId(cmd.caseId)) return reply("Usage: /dfir bind <caseId>");
    const bindGuard = await guardCase(ctx, cmd.caseId);
    if (bindGuard) return reply(bindGuard);
    // An unreadable bindings file (hand-edited into invalid JSON) must answer the analyst, not
    // reject into the terminal error handler with a bare 500 the chat client won't render.
    const bound = await channelStore.bind(bindKey, cmd.caseId).then(() => true).catch(() => false);
    if (!bound) return reply("Could not save the channel binding — check notifications/slash-command-bindings.json.");
    audit(cmd.caseId, {
      category: "collaboration",
      action: "slash-command-bind",
      detail: `${platform} channel ${channelId} bound to case ${cmd.caseId} by user ${userId}`,
    });
    return reply(`Channel bound to case ${cmd.caseId}.`);
  }

  if (!cmd.caseId || !isValidCaseId(cmd.caseId)) {
    const hint = binding
      ? `This channel is bound to case "${binding.caseId}".`
      : "Bind this channel first with `/dfir bind <caseId>`.";
    return reply(`A valid caseId is required. ${hint}`);
  }
  if (!isCaseAccessAllowed({ userId, caseId: cmd.caseId, boundCaseId: binding?.caseId, actionAllowlist })) {
    await auditDenial(input, cmd, `not permitted to reach case ${cmd.caseId} from this channel`);
    return reply(
      `User ${userId || "(unknown)"} may only use this channel's bound case` +
        `${binding ? ` (${binding.caseId})` : " — this channel has no binding"}.`,
    );
  }
  const guard = await guardCase(ctx, cmd.caseId);
  if (guard) return reply(guard);
  if (!options.stateStore) return reply("State store not configured.");

  // Read-only commands respond synchronously.
  if (READ_ONLY_COMMANDS.includes(cmd.name)) {
    let r: SlashCommandResponse;
    try {
      const state = await options.stateStore.load(cmd.caseId);
      switch (cmd.name) {
        case "findings": r = formatFindingsCommand(state); break;
        case "finding":  r = formatFindingCommand(state, cmd.arg); break;
        case "iocs":     r = formatIocsCommand(state, cmd.iocFilter); break;
        case "status":   r = formatStatusCommand(state); break;
        default:         r = formatHelpCommand();
      }
    } catch (err) {
      // Path-redacted: the app-wide res.json redaction only rewrites an `error` field, and this
      // message goes out as chat `text` — an fs error carries the full cases-root path.
      return reply(`Error loading case ${cmd.caseId}: ${redactPaths((err as Error).message, [store.casesRoot])}`);
    }
    audit(cmd.caseId, {
      category: "collaboration",
      action: "slash-command",
      detail: `/dfir ${cmd.name} (user ${userId}, ${platform} channel ${channelId})`,
    });
    return reply(r, false);
  }

  // Async commands: ACK immediately, then run and deliver the result out of band.
  if (isAsyncCommand(cmd.name)) {
    reply(`Working on /dfir ${cmd.name} for case ${cmd.caseId}…`);
    void runActionCommand(cmd, input).catch((err) => {
      audit(cmd.caseId, {
        category: "collaboration",
        action: "slash-command-error",
        detail: `/dfir ${cmd.name} failed: ${(err as Error).message}`,
        outcome: "error",
      });
    });
    return;
  }

  reply(formatHelpCommand());
}

/** Refuse a case the bot must not serve: one that doesn't exist, or one behind a password (chat
 *  carries no unlock — see the module docblock). Returns the message to send, or "" when fine. */
async function guardCase(ctx: RouteContext, caseId: string): Promise<string> {
  let meta;
  try {
    meta = await ctx.store.getCaseMeta(caseId);
  } catch {
    // Fail closed, exactly like the case-lock gate does on an unexpected metadata read failure.
    return `Case ${caseId} could not be read.`;
  }
  if (!meta) return `No such case: ${caseId}.`;
  if (meta.password) return `Case ${caseId} is password-protected and is not available over chat — use the dashboard.`;
  return "";
}

async function auditDenial(input: DispatchInput, cmd: ResolvedSlashCommand, reason: string): Promise<void> {
  const { ctx, platform, channelId, userId } = input;
  // Only write into a case's log when that case actually exists — a denial naming a bogus id must
  // not create a case directory.
  if (!cmd.caseId || !isValidCaseId(cmd.caseId)) return;
  if (!(await ctx.store.caseExists(cmd.caseId).catch(() => false))) return;
  await logActivity(ctx.options.activityLogStore, ctx.options.onActivity, cmd.caseId, {
    actor: `${platform}:${userId}`,
    category: "collaboration",
    action: "slash-command-denied",
    detail: `/dfir ${cmd.name} from ${platform} channel ${channelId}: ${reason}`,
    outcome: "error",
  });
}

async function runActionCommand(cmd: ResolvedSlashCommand, input: DispatchInput): Promise<void> {
  const { ctx, platform, userId } = input;
  const { options } = ctx;
  const audit = (entry: Parameters<typeof logActivity>[3]): void => {
    void logActivity(options.activityLogStore, options.onActivity, cmd.caseId, { actor: `${platform}:${userId}`, ...entry });
  };
  const send = (r: SlashCommandResponse, ephemeral = true): Promise<void> => deliverAsyncResult(input, r, ephemeral);

  if (cmd.name === "synthesize") {
    ctx.resynthesizeInBackground(cmd.caseId);
    audit({
      category: "ai",
      action: "slash-command-synthesize",
      detail: `/dfir synthesize triggered by user ${userId}`,
    });
    await send({
      title: `Re-synthesis started for case ${cmd.caseId}.`,
      lines: ["The diff summary will appear in the dashboard and activity log when it finishes."],
    });
    return;
  }

  if (cmd.name === "ask") {
    if (!cmd.arg.trim()) return void (await send({ title: "Usage: /dfir ask <question>", lines: [] }));
    if (!options.pipeline) return void (await send({ title: "AI pipeline not configured.", lines: [] }));
    try {
      const answer = await options.pipeline.ask(cmd.caseId, cmd.arg);
      await send(
        {
          title: `Q: ${cmd.arg}`,
          lines: [answer.answer || "(no answer)", ...(answer.pointer ? [`Next: ${answer.pointer}`] : [])],
        },
        false,
      );
      audit({
        category: "ai",
        action: "slash-command-ask",
        detail: `/dfir ask "${cmd.arg.slice(0, 120)}" → ${answer.status}`,
      });
    } catch (err) {
      await send({ title: `AI ask failed: ${redactPaths((err as Error).message, [ctx.store.casesRoot])}`, lines: [] });
      audit({
        category: "ai",
        action: "slash-command-ask",
        detail: `/dfir ask "${cmd.arg.slice(0, 120)}" failed: ${(err as Error).message}`,
        outcome: "error",
      });
    }
    return;
  }

  if (cmd.name === "hunt") {
    await send({
      title: `Hunt technique "${cmd.arg || "(none specified)"}" noted for case ${cmd.caseId}.`,
      lines: ["Deploy the hunt from the dashboard's Velociraptor hunt panel."],
    });
    audit({
      category: "hunt",
      action: "slash-command-hunt",
      detail: `/dfir hunt ${cmd.arg} (user ${userId}) — deploy via dashboard`,
    });
  }
}

// ── Platform envelopes + delivery ───────────────────────────────────────────────────────

function renderText(r: SlashCommandResponse): string {
  const body = r.lines.filter(Boolean).map((l) => `• ${l}`).join("\n");
  return `${r.title}${body ? `\n${body}` : ""}`;
}

/** Wrap a card in the response envelope the platform expects for a synchronous reply. */
function chatResponse(input: DispatchInput, r: SlashCommandResponse, ephemeral: boolean): unknown {
  const text = renderText(r);
  switch (input.platform) {
    case "slack":
      return { response_type: ephemeral ? "ephemeral" : "in_channel", text };
    case "teams":
      return { type: "message", text };
    case "telegram":
      // Telegram executes a Bot API method named in the webhook reply body — that is how you answer
      // an update without a second HTTP call.
      return { method: "sendMessage", chat_id: input.channelId, text };
  }
}

/** Deliver a result that wasn't ready in time for the synchronous reply. */
async function deliverAsyncResult(input: DispatchInput, r: SlashCommandResponse, ephemeral: boolean): Promise<void> {
  const { ctx, platform } = input;
  if (platform === "telegram") {
    const token = (process.env.DFIR_TELEGRAM_BOT_TOKEN ?? "").trim();
    if (!token) {
      ctx.serverLogger.warn("[slash] telegram result dropped: DFIR_TELEGRAM_BOT_TOKEN is not set");
      return;
    }
    const base = (process.env.DFIR_TELEGRAM_API_BASE ?? "https://api.telegram.org").replace(/\/+$/, "");
    await postJson(input, `${base}/bot${token}/sendMessage`, { chat_id: input.channelId, text: renderText(r) });
    return;
  }

  const url = input.responseUrl;
  if (!url) {
    ctx.serverLogger.warn(`[slash] ${platform} result dropped: the request carried no response_url`);
    return;
  }
  const extraHosts = parseHostList(
    platform === "slack" ? process.env.DFIR_SLACK_RESPONSE_HOSTS : process.env.DFIR_TEAMS_RESPONSE_HOSTS,
  );
  // The response_url is caller-supplied, so it is pinned to the hosts the platform delivers on
  // before we make a server-side request to it.
  if (!isAllowedResponseUrl(platform, url, extraHosts)) {
    ctx.serverLogger.warn(
      `[slash] refused to deliver to response_url "${url}" — not an allowed ${platform} host` +
        ` (extend with DFIR_${platform.toUpperCase()}_RESPONSE_HOSTS)`,
    );
    return;
  }
  await postJson(input, url, chatResponse(input, r, ephemeral));
}

async function postJson(input: DispatchInput, url: string, payload: unknown): Promise<void> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) input.ctx.serverLogger.warn(`[slash] result delivery to ${input.platform} returned ${res.status}`);
  } catch (err) {
    input.ctx.serverLogger.warn(`[slash] result delivery to ${input.platform} failed: ${(err as Error).message}`);
  }
}
