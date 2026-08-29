import { z } from "zod";
import type { Finding, Severity, StepPriority } from "./stateTypes.js";
import type { FindingsDiff } from "./findingsDiff.js";
import type { PlaybookTask } from "./playbook.js";

// Notification channels (issue #58). The Companion can push three classes of investigation
// signal — (1) new/escalated findings, (2) playbook updates, (3) lifecycle milestones — to
// Slack webhooks, MS Teams webhooks, and SMTP email, with a per-channel severity threshold and
// per-event-kind toggles. This module is the PURE core: the channel/event model, the filtering
// rule (`shouldNotify`), and the deterministic builders that turn case changes into events. It
// has NO I/O — the store (notificationStore.ts), formatters, and senders (integrations/notify/)
// build on top and are tested with mocks.
//
// OPSEC: notifications send case CONTENT (finding titles, task titles) to a third party. Like
// enrichment, this is OFF by default — the channel list starts empty and each channel is created
// + enabled explicitly by the analyst (opt-in). Nothing leaves the box until then.

export const NOTIFICATION_CHANNEL_TYPES = [
  "slack",
  "teams",
  "mattermost",
  "discord",
  "email",
  "telegram",
] as const;
export type NotificationChannelType = (typeof NOTIFICATION_CHANNEL_TYPES)[number];

// slack/teams/mattermost/discord are all incoming-webhook channels — they carry only a `webhookUrl`
// (no other transport config) and share the same validation, secret-redaction, and update path.
// email (SMTP) and telegram (bot token) are not webhook channels.
export const WEBHOOK_CHANNEL_TYPES: readonly NotificationChannelType[] = [
  "slack",
  "teams",
  "mattermost",
  "discord",
];

export function isWebhookChannelType(type: NotificationChannelType): boolean {
  return WEBHOOK_CHANNEL_TYPES.includes(type);
}

// The signal classes from the issue, plus `mention` (issue #88 — an @name in a case comment). The
// kind is also the per-channel toggle key.
export const NOTIFICATION_EVENT_KINDS = [
  "critical_finding",
  "playbook_update",
  "milestone",
  "mention",
] as const;
export type NotificationEventKind = (typeof NOTIFICATION_EVENT_KINDS)[number];

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;

// Higher = more severe. Used both to filter against a channel's minSeverity and to colour the
// formatted message.
export const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
};

// A playbook task's priority maps onto the finding severity scale so the same per-channel
// threshold can gate "this high-priority task changed" the same way it gates a High finding.
const PRIORITY_TO_SEVERITY: Record<StepPriority, Severity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export function severityForPriority(priority: StepPriority): Severity {
  return PRIORITY_TO_SEVERITY[priority] ?? "Medium";
}

// One thing worth telling someone about. `severity` drives the threshold filter (except for
// milestones, which bypass it — see shouldNotify). `lines` are short detail rows rendered as a
// bullet list / fact table by each formatter.
export interface NotificationEvent {
  kind: NotificationEventKind;
  caseId: string;
  title: string; // headline, already human-readable (e.g. "New finding: Cobalt Strike beacon")
  severity: Severity; // event severity for threshold filtering + message colour
  lines: string[]; // detail rows
  at: string; // ISO timestamp
  url?: string; // optional deep link back to the dashboard/case
}

// Telegram bot config. botToken is stored but never echoed back to the browser (the route redacts it).
// It may be EMPTY: an operator who already set the war-room bot's DFIR_TELEGRAM_BOT_TOKEN in .env
// does not type it again here, and the sender resolves it at send time (resolveTelegramBotToken).
export interface TelegramChannelConfig {
  botToken: string; // secret — never echoed to the browser. Empty = use the env token.
  chatId: string; // chat/channel/group ID (e.g., "@channelname" or "-1001234567890")
}

// The war-room bot's token, passed in by whichever caller sits at the env boundary (the route, the
// notifier). This module reads NO env of its own — that is what keeps it pure and its tests
// order-independent.
export interface TelegramEnvOpts {
  envTelegramBotToken?: string;
}

/**
 * Which bot token actually sends for this channel: the channel's own if it has one, else the
 * war-room bot's env token. Resolved at SEND time rather than copied into the store at save time,
 * so .env stays the single source of truth and rotating it rotates the channel too.
 */
export function resolveTelegramBotToken(
  channel: Pick<NotificationChannel, "telegram">,
  envBotToken?: string,
): string {
  return (channel.telegram?.botToken ?? "").trim() || (envBotToken ?? "").trim();
}

// SMTP transport config for an email channel. Secrets (password) are stored but never echoed back
// to the browser (the route redacts them).
export interface SmtpChannelConfig {
  host: string;
  port: number;
  secure: boolean; // implicit TLS (port 465). Otherwise plain + opportunistic STARTTLS.
  username?: string;
  password?: string;
  from: string; // From: address
  to: string[]; // recipient addresses
  rejectUnauthorized?: boolean; // verify the server cert (default true) — set false for self-signed
}

// A configured destination. Webhook channels (slack/teams/mattermost/discord) use `webhookUrl`;
// email uses `smtp`; Telegram uses `telegram`.
export interface NotificationChannel {
  id: string;
  type: NotificationChannelType;
  name: string; // analyst label
  enabled: boolean;
  minSeverity: Severity; // only events at or above this fire (findings/playbook)
  events: Record<NotificationEventKind, boolean>; // which signal classes this channel wants
  webhookUrl?: string; // slack / teams / mattermost / discord incoming-webhook URL
  smtp?: SmtpChannelConfig; // email transport
  telegram?: TelegramChannelConfig; // telegram bot transport
  createdAt: string;
  updatedAt: string;
}

// ── Filtering ──────────────────────────────────────────────────────────────────────────────

// Does this channel want this event? Gates on: enabled, the per-kind toggle, and — for
// severity-bearing events (findings/playbook) — the channel's minSeverity. Milestones and mentions
// are not severity-ranked (a mention has no "how bad" axis), so both bypass the threshold and are
// gated only by their own toggle.
export function shouldNotify(channel: NotificationChannel, event: NotificationEvent): boolean {
  if (!channel.enabled) return false;
  if (!channel.events[event.kind]) return false;
  if (event.kind === "milestone" || event.kind === "mention") return true;
  return SEVERITY_RANK[event.severity] >= SEVERITY_RANK[channel.minSeverity];
}

// ── Event builders (case change → notification events) ──────────────────────────────────────

const normTitle = (t: string): string => String(t).trim().toLowerCase().replace(/\s+/g, " ");

// Derive notification events from a synthesis findings diff. Emits a `critical_finding` event for
// each NEWLY ADDED finding (severity = the finding's own, so the channel threshold decides what
// pages) and for each ESCALATION (severity raised on an existing finding). Removals and
// de-escalations are intentionally silent. The diff is by title (synthesis re-ids findings every
// run), so a finding that persists across runs is not re-announced — natural dedup.
export function findingEventsFromDiff(
  caseId: string,
  diff: FindingsDiff,
  findings: readonly Finding[],
  at: string,
): NotificationEvent[] {
  const byTitle = new Map<string, Finding>();
  for (const f of findings) {
    const key = normTitle(f.title);
    if (!byTitle.has(key)) byTitle.set(key, f);
  }
  const events: NotificationEvent[] = [];

  for (const title of diff.added) {
    const f = byTitle.get(normTitle(title));
    const severity: Severity = f?.severity ?? "Info";
    const lines = [`Severity: ${severity}`, `Case: ${caseId}`];
    if (f?.description) lines.push(truncate(f.description, 300));
    events.push({ kind: "critical_finding", caseId, title: `New finding: ${title}`, severity, lines, at });
  }

  for (const ch of diff.severityChanged) {
    // Only ESCALATIONS are worth paging on.
    if (SEVERITY_RANK[ch.to] <= SEVERITY_RANK[ch.from]) continue;
    events.push({
      kind: "critical_finding",
      caseId,
      title: `Finding escalated: ${ch.title}`,
      severity: ch.to,
      lines: [`Severity raised ${ch.from} → ${ch.to}`, `Case: ${caseId}`],
      at,
    });
  }

  return events;
}

export type PlaybookAction = "added" | "completed" | "updated";

const PLAYBOOK_ACTION_VERB: Record<PlaybookAction, string> = {
  added: "Playbook task added",
  completed: "Playbook task completed",
  updated: "Playbook task updated",
};

// Build a `playbook_update` event for a single task change. Severity = the task's priority on the
// finding scale, so the channel threshold gates low-priority churn the same way it gates findings.
export function playbookTaskEvent(
  caseId: string,
  task: PlaybookTask,
  action: PlaybookAction,
  at: string,
): NotificationEvent {
  const severity = severityForPriority(task.priority);
  const lines = [
    `${PLAYBOOK_ACTION_VERB[action]} (${task.priority})`,
    `Status: ${task.status}`,
    `Case: ${caseId}`,
  ];
  if (task.assignee) lines.push(`Assignee: ${task.assignee}`);
  return {
    kind: "playbook_update",
    caseId,
    title: `${PLAYBOOK_ACTION_VERB[action]}: ${task.title}`,
    severity,
    lines,
    at,
  };
}

// Build a `milestone` lifecycle event. Severity is Info (milestones bypass the threshold), so the
// `milestone` per-channel toggle is the only gate.
export function milestoneEvent(
  caseId: string,
  title: string,
  lines: string[],
  at: string,
): NotificationEvent {
  return { kind: "milestone", caseId, title, severity: "Info", lines: [...lines, `Case: ${caseId}`], at };
}

// Build a `mention` event for a comment that @mentioned one or more investigators (issue #88).
// Severity is Info (mentions bypass the threshold — see shouldNotify), so the per-channel
// `mention` toggle is the only gate.
export function mentionEvent(
  caseId: string,
  targetType: string,
  targetId: string,
  author: string,
  mentions: readonly string[],
  text: string,
  at: string,
): NotificationEvent {
  const who = mentions.map((m) => `@${m}`).join(", ");
  return {
    kind: "mention",
    caseId,
    title: `${author} mentioned ${who} in a comment`,
    severity: "Info",
    lines: [`On ${targetType} ${targetId}`, truncate(text, 300), `Case: ${caseId}`],
    at,
  };
}

// A generic test event so the analyst can verify a channel end-to-end from Settings.
export function testEvent(at: string): NotificationEvent {
  return {
    kind: "milestone",
    caseId: "—",
    title: "DFIR Companion test notification",
    severity: "Info",
    lines: [
      "This is a test message confirming the channel is wired up correctly.",
      "If you received this, notifications work.",
    ],
    at,
  };
}

// ── Channel input validation + secret-preserving updates ────────────────────────────────────

const telegramInputSchema = z.object({
  botToken: z.string().optional(),
  chatId: z.string().min(1),
});

const smtpInputSchema = z.object({
  host: z.string().min(1),
  port: z.coerce.number().int().min(1).max(65535),
  secure: z.boolean().optional().default(false),
  username: z.string().optional(),
  password: z.string().optional(),
  from: z.string().min(1),
  to: z
    .union([z.array(z.string()), z.string()])
    .transform((v) =>
      (Array.isArray(v) ? v : String(v).split(/[,;\s]+/)).map((s) => s.trim()).filter(Boolean),
    ),
  rejectUnauthorized: z.boolean().optional(),
});

// z.coerce.boolean() applies JavaScript truthiness, so the string "false" — what an HTML form, a
// curl one-liner and most non-JSON clients send for an unchecked box — coerces to TRUE (#684). A
// caller switching a channel or a `critical_finding` toggle OFF would switch it ON instead, and
// start pushing case detail to an external destination. Accept real booleans and the exact strings
// "true"/"false" (trimmed, case-insensitive); reject everything else — numbers, null, "yes", "" —
// with a 400 rather than guessing, because a wrong guess here leaks an investigation.
const strictBoolean = z.preprocess((v) => {
  if (typeof v !== "string") return v;
  const s = v.trim().toLowerCase();
  if (s === "true") return true;
  if (s === "false") return false;
  return v; // falls through to z.boolean(), which reports "expected boolean"
}, z.boolean());

const eventsInputSchema = z
  .object({
    critical_finding: strictBoolean.optional(),
    playbook_update: strictBoolean.optional(),
    milestone: strictBoolean.optional(),
    mention: strictBoolean.optional(),
  })
  .optional();

// Raw create/update payload from the route. type/severity are validated against the enums;
// transport fields are shape-checked per type by parseChannelInput.
export const channelInputSchema = z.object({
  type: z.enum(NOTIFICATION_CHANNEL_TYPES),
  name: z.string().optional(),
  enabled: strictBoolean.optional(),
  minSeverity: z.enum(SEVERITIES).optional(),
  events: eventsInputSchema,
  webhookUrl: z.string().optional(),
  smtp: smtpInputSchema.optional(),
  telegram: telegramInputSchema.optional(),
});

export type ChannelInput = z.infer<typeof channelInputSchema>;

export interface ChannelDraft {
  type: NotificationChannelType;
  name: string;
  enabled: boolean;
  minSeverity: Severity;
  events: Record<NotificationEventKind, boolean>;
  webhookUrl?: string;
  smtp?: SmtpChannelConfig;
  telegram?: TelegramChannelConfig;
}

export interface ParsedChannelInput {
  ok: boolean;
  draft?: ChannelDraft;
  error?: string;
}

// Milestones default ON. They were off because they are lifecycle chatter — case opened, report
// generated, drop import finished — and a channel that wanted findings did not want a feed. The
// class changed when a milestone became the only push an analyst gets for a case that is BLOCKED:
// the host near-duplicate gate stops synthesis and, with this off, said so to nobody. Defaulting
// off made the quietest choice for the noisiest events and the loudest choice for the one that
// matters. A channel that wants findings only still opts out per-kind, which is the point of the
// toggle; what it no longer does is silently withhold "this case is on hold".
//
// This also reaches EXISTING channels: the default fills any kind a stored config never set, so a
// channel saved before this change starts receiving milestones. That is intended — it is the same
// upgrade every user would otherwise have to perform by hand — but it belongs in the release note.
const defaultEvents = (): Record<NotificationEventKind, boolean> => ({
  critical_finding: true,
  playbook_update: true,
  milestone: true,
  mention: true,
});

// Validate + normalize a create/update payload into a full channel draft. Webhook channels require
// a (http/https) URL; email requires host/port/from/to. On an UPDATE the UI never re-sends the
// redacted secret (webhook URL / SMTP password), so pass the `existing` channel: a blank webhook
// URL then falls back to the saved one for validation (the same redacted-round-trip the env
// password fields use). `opts.envTelegramBotToken` lets a telegram channel leave its token blank
// when the war-room bot already has one in .env. Returns a structured error instead of throwing so
// the route can answer 400.
export function parseChannelInput(
  raw: unknown,
  existing?: NotificationChannel,
  opts?: TelegramEnvOpts,
): ParsedChannelInput {
  const parsed = channelInputSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      error: parsed.error.issues.map((i) => `${i.path.join(".") || "input"}: ${i.message}`).join("; "),
    };
  }
  const v = parsed.data;
  const events = { ...defaultEvents(), ...(v.events ?? {}) } as Record<NotificationEventKind, boolean>;
  const draft: ChannelDraft = {
    type: v.type,
    name: (v.name ?? "").trim() || defaultName(v.type),
    enabled: v.enabled ?? true,
    minSeverity: v.minSeverity ?? "High",
    events,
  };

  if (isWebhookChannelType(v.type)) {
    // Blank URL on update → keep the saved one, but ONLY when the provider type is unchanged
    // (#683). Slack/Discord/Teams/Mattermost share one `webhookUrl` FIELD, never one endpoint: an
    // edit that switches a saved Slack channel to Discord and leaves the redacted URL box blank
    // used to inherit the Slack endpoint, and the dispatcher then posted Discord's payload shape
    // to Slack. A provider change must carry the new provider's URL.
    const sameTypeExisting = existing?.type === v.type ? existing.webhookUrl : undefined;
    const url = (v.webhookUrl ?? "").trim() || (sameTypeExisting ?? "");
    if (!/^https?:\/\//i.test(url)) {
      const retyped = existing && existing.type !== v.type;
      return {
        ok: false,
        error: retyped
          ? `changing this channel from ${existing.type} to ${v.type} requires a new ${v.type} webhook URL`
          : `${v.type} channel requires an http(s) webhook URL`,
      };
    }
    draft.webhookUrl = url;
  } else if (v.type === "telegram") {
    // Blank token on update → keep the saved one (same redacted-round-trip pattern as webhookUrl).
    const sameTypeExisting = existing?.type === "telegram" ? existing.telegram : undefined;
    const token = (v.telegram?.botToken ?? "").trim() || (sameTypeExisting?.botToken ?? "");
    // Nothing typed and nothing saved is still fine when the war-room bot has a token in .env. The
    // draft keeps an EMPTY token in that case — deliberately NOT a copy of the env value, so .env
    // remains the only place it lives and a rotation there takes effect without re-saving here.
    //
    // The token is required to CREATE the channel, never to keep editing one. An env-backed channel
    // stores an empty token, so if DFIR_TELEGRAM_BOT_TOKEN later goes away, demanding one here would
    // 400 every subsequent edit — including the dashboard's enable/disable toggle, which PUTs a
    // blank token and ignores a non-2xx. The channel would read "off" in the browser while staying
    // ON in the store, and would resume sending the moment the token came back. A tokenless channel
    // simply cannot send (the dispatcher says so, and the list shows it in red), which is the honest
    // state to leave it in — being unable to turn it off is not.
    if (!token && !(opts?.envTelegramBotToken ?? "").trim() && !sameTypeExisting)
      return { ok: false, error: "telegram channel requires a bot token" };
    const chatId = (v.telegram?.chatId ?? "").trim();
    if (!chatId) return { ok: false, error: "telegram channel requires a chat ID" };
    draft.telegram = { botToken: token, chatId };
  } else {
    if (!v.smtp) return { ok: false, error: "email channel requires smtp { host, port, from, to }" };
    if (!v.smtp.to.length) return { ok: false, error: "email channel requires at least one recipient (to)" };
    draft.smtp = {
      host: v.smtp.host.trim(),
      port: v.smtp.port,
      secure: v.smtp.secure ?? false,
      from: v.smtp.from.trim(),
      to: v.smtp.to,
      ...(v.smtp.username ? { username: v.smtp.username } : {}),
      ...(v.smtp.password ? { password: v.smtp.password } : {}),
      ...(v.smtp.rejectUnauthorized !== undefined ? { rejectUnauthorized: v.smtp.rejectUnauthorized } : {}),
    };
  }
  return { ok: true, draft };
}

function defaultName(type: NotificationChannelType): string {
  if (type === "slack") return "Slack";
  if (type === "teams") return "MS Teams";
  if (type === "mattermost") return "Mattermost";
  if (type === "discord") return "Discord";
  if (type === "telegram") return "Telegram";
  return "Email";
}

// Apply a parsed draft onto an existing channel for an UPDATE, PRESERVING secrets the UI didn't
// resend (a blank webhookUrl / smtp.password means "keep the current one" — the GET response
// redacts them, so the browser never has the value to echo back). This is the same
// don't-wipe-the-secret-on-edit pattern as the env settings password fields.
export function applyChannelPatch(
  existing: NotificationChannel,
  draft: ChannelDraft,
  at: string,
): NotificationChannel {
  const next: NotificationChannel = {
    ...existing,
    type: draft.type,
    name: draft.name,
    enabled: draft.enabled,
    minSeverity: draft.minSeverity,
    events: draft.events,
    updatedAt: at,
  };

  if (isWebhookChannelType(draft.type)) {
    // Second gate on #683: parseChannelInput already refuses a blank URL across a provider change,
    // and this fallback never inherits across one either — so no caller can reach the old endpoint.
    const inherited = existing.type === draft.type ? existing.webhookUrl : undefined;
    next.webhookUrl = draft.webhookUrl || inherited || "";
    delete next.smtp;
    delete next.telegram;
  } else if (draft.type === "telegram") {
    const prev = existing.telegram;
    next.telegram = {
      chatId: draft.telegram!.chatId,
      // Preserve the saved token when the edit left it blank (redacted round-trip).
      botToken: draft.telegram!.botToken || prev?.botToken || "",
    };
    delete next.webhookUrl;
    delete next.smtp;
  } else if (draft.smtp) {
    const prev = existing.smtp;
    next.smtp = {
      ...draft.smtp,
      // Preserve the saved password when the edit left it blank (redacted round-trip).
      password: draft.smtp.password || prev?.password || undefined,
    };
    delete next.webhookUrl;
    delete next.telegram;
  }
  return next;
}

// Strip secrets for a client-facing view: webhook URLs, SMTP passwords, and Telegram bot tokens
// never leave the server. The browser learns only whether each is set.
export interface RedactedChannel extends Omit<NotificationChannel, "webhookUrl" | "smtp" | "telegram"> {
  hasWebhookUrl: boolean;
  smtp?: Omit<SmtpChannelConfig, "password"> & { hasPassword: boolean };
  // hasBotToken answers "will this channel be able to send" — true whether the token is the
  // channel's own or the war-room bot's. usesEnvBotToken says WHICH, so the UI can name the source
  // instead of implying the analyst typed one here.
  telegram?: { chatId: string; hasBotToken: boolean; usesEnvBotToken: boolean };
}

export function redactChannel(channel: NotificationChannel, opts?: TelegramEnvOpts): RedactedChannel {
  const { webhookUrl, smtp, telegram, ...rest } = channel;
  const out: RedactedChannel = { ...rest, hasWebhookUrl: Boolean(webhookUrl) };
  if (smtp) {
    const { password, ...smtpRest } = smtp;
    out.smtp = { ...smtpRest, hasPassword: Boolean(password) };
  }
  if (telegram) {
    const own = Boolean(telegram.botToken?.trim());
    const fromEnv = !own && Boolean((opts?.envTelegramBotToken ?? "").trim());
    out.telegram = {
      chatId: telegram.chatId,
      hasBotToken: own || fromEnv,
      usesEnvBotToken: fromEnv,
    };
  }
  return out;
}

function truncate(s: string, max: number): string {
  const t = String(s).trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
