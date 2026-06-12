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

export const NOTIFICATION_CHANNEL_TYPES = ["slack", "teams", "email"] as const;
export type NotificationChannelType = (typeof NOTIFICATION_CHANNEL_TYPES)[number];

// The three signal classes from the issue. The kind is also the per-channel toggle key.
export const NOTIFICATION_EVENT_KINDS = ["critical_finding", "playbook_update", "milestone"] as const;
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
  title: string;          // headline, already human-readable (e.g. "New finding: Cobalt Strike beacon")
  severity: Severity;     // event severity for threshold filtering + message colour
  lines: string[];        // detail rows
  at: string;             // ISO timestamp
  url?: string;           // optional deep link back to the dashboard/case
}

// SMTP transport config for an email channel. Secrets (password) are stored but never echoed back
// to the browser (the route redacts them).
export interface SmtpChannelConfig {
  host: string;
  port: number;
  secure: boolean;        // implicit TLS (port 465). Otherwise plain + opportunistic STARTTLS.
  username?: string;
  password?: string;
  from: string;           // From: address
  to: string[];           // recipient addresses
  rejectUnauthorized?: boolean;  // verify the server cert (default true) — set false for self-signed
}

// A configured destination. Webhook channels (slack/teams) use `webhookUrl`; email uses `smtp`.
export interface NotificationChannel {
  id: string;
  type: NotificationChannelType;
  name: string;                                   // analyst label
  enabled: boolean;
  minSeverity: Severity;                          // only events at or above this fire (findings/playbook)
  events: Record<NotificationEventKind, boolean>; // which signal classes this channel wants
  webhookUrl?: string;                            // slack / teams incoming-webhook URL
  smtp?: SmtpChannelConfig;                        // email transport
  createdAt: string;
  updatedAt: string;
}

// ── Filtering ──────────────────────────────────────────────────────────────────────────────

// Does this channel want this event? Gates on: enabled, the per-kind toggle, and — for
// severity-bearing events (findings/playbook) — the channel's minSeverity. Milestones are
// lifecycle pings and bypass the threshold (gated only by the `milestone` toggle), so a
// "critical-only" channel still doesn't get spammed but a milestone-opted channel always does.
export function shouldNotify(channel: NotificationChannel, event: NotificationEvent): boolean {
  if (!channel.enabled) return false;
  if (!channel.events[event.kind]) return false;
  if (event.kind === "milestone") return true;
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
  return { kind: "playbook_update", caseId, title: `${PLAYBOOK_ACTION_VERB[action]}: ${task.title}`, severity, lines, at };
}

// Build a `milestone` lifecycle event. Severity is Info (milestones bypass the threshold), so the
// `milestone` per-channel toggle is the only gate.
export function milestoneEvent(caseId: string, title: string, lines: string[], at: string): NotificationEvent {
  return { kind: "milestone", caseId, title, severity: "Info", lines: [...lines, `Case: ${caseId}`], at };
}

// A generic test event so the analyst can verify a channel end-to-end from Settings.
export function testEvent(at: string): NotificationEvent {
  return {
    kind: "milestone",
    caseId: "—",
    title: "DFIR Companion test notification",
    severity: "Info",
    lines: ["This is a test message confirming the channel is wired up correctly.", "If you received this, notifications work."],
    at,
  };
}

// ── Channel input validation + secret-preserving updates ────────────────────────────────────

const smtpInputSchema = z.object({
  host: z.string().min(1),
  port: z.coerce.number().int().min(1).max(65535),
  secure: z.boolean().optional().default(false),
  username: z.string().optional(),
  password: z.string().optional(),
  from: z.string().min(1),
  to: z.union([z.array(z.string()), z.string()]).transform((v) =>
    (Array.isArray(v) ? v : String(v).split(/[,;\s]+/)).map((s) => s.trim()).filter(Boolean),
  ),
  rejectUnauthorized: z.boolean().optional(),
});

const eventsInputSchema = z
  .object({
    critical_finding: z.coerce.boolean().optional(),
    playbook_update: z.coerce.boolean().optional(),
    milestone: z.coerce.boolean().optional(),
  })
  .optional();

// Raw create/update payload from the route. type/severity are validated against the enums;
// transport fields are shape-checked per type by parseChannelInput.
export const channelInputSchema = z.object({
  type: z.enum(NOTIFICATION_CHANNEL_TYPES),
  name: z.string().optional(),
  enabled: z.coerce.boolean().optional(),
  minSeverity: z.enum(SEVERITIES).optional(),
  events: eventsInputSchema,
  webhookUrl: z.string().optional(),
  smtp: smtpInputSchema.optional(),
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
}

export interface ParsedChannelInput {
  ok: boolean;
  draft?: ChannelDraft;
  error?: string;
}

const defaultEvents = (): Record<NotificationEventKind, boolean> => ({
  critical_finding: true,
  playbook_update: true,
  milestone: false,
});

// Validate + normalize a create/update payload into a full channel draft. Webhook channels require
// a (http/https) URL; email requires host/port/from/to. On an UPDATE the UI never re-sends the
// redacted secret (webhook URL / SMTP password), so pass the `existing` channel: a blank webhook
// URL then falls back to the saved one for validation (the same redacted-round-trip the env
// password fields use). Returns a structured error instead of throwing so the route can answer 400.
export function parseChannelInput(raw: unknown, existing?: NotificationChannel): ParsedChannelInput {
  const parsed = channelInputSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues.map((i) => `${i.path.join(".") || "input"}: ${i.message}`).join("; ") };
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

  if (v.type === "slack" || v.type === "teams") {
    // Blank URL on update → keep the saved one (only valid when the existing channel is the same
    // webhook type and already has a URL).
    const sameTypeExisting = existing && (existing.type === "slack" || existing.type === "teams") ? existing.webhookUrl : undefined;
    const url = (v.webhookUrl ?? "").trim() || (sameTypeExisting ?? "");
    if (!/^https?:\/\//i.test(url)) return { ok: false, error: `${v.type} channel requires an http(s) webhook URL` };
    draft.webhookUrl = url;
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
  return type === "slack" ? "Slack" : type === "teams" ? "MS Teams" : "Email";
}

// Apply a parsed draft onto an existing channel for an UPDATE, PRESERVING secrets the UI didn't
// resend (a blank webhookUrl / smtp.password means "keep the current one" — the GET response
// redacts them, so the browser never has the value to echo back). This is the same
// don't-wipe-the-secret-on-edit pattern as the env settings password fields.
export function applyChannelPatch(existing: NotificationChannel, draft: ChannelDraft, at: string): NotificationChannel {
  const next: NotificationChannel = {
    ...existing,
    type: draft.type,
    name: draft.name,
    enabled: draft.enabled,
    minSeverity: draft.minSeverity,
    events: draft.events,
    updatedAt: at,
  };

  if (draft.type === "slack" || draft.type === "teams") {
    next.webhookUrl = draft.webhookUrl || existing.webhookUrl || "";
    delete next.smtp;
  } else if (draft.smtp) {
    const prev = existing.smtp;
    next.smtp = {
      ...draft.smtp,
      // Preserve the saved password when the edit left it blank (redacted round-trip).
      password: draft.smtp.password || prev?.password || undefined,
    };
    delete next.webhookUrl;
  }
  return next;
}

// Strip secrets for a client-facing view: webhook URLs and SMTP passwords never leave the server.
// The browser learns only whether each is set (so the UI can show "configured" + a blank field).
export interface RedactedChannel extends Omit<NotificationChannel, "webhookUrl" | "smtp"> {
  hasWebhookUrl: boolean;
  smtp?: Omit<SmtpChannelConfig, "password"> & { hasPassword: boolean };
}

export function redactChannel(channel: NotificationChannel): RedactedChannel {
  const { webhookUrl, smtp, ...rest } = channel;
  const out: RedactedChannel = { ...rest, hasWebhookUrl: Boolean(webhookUrl) };
  if (smtp) {
    const { password, ...smtpRest } = smtp;
    out.smtp = { ...smtpRest, hasPassword: Boolean(password) };
  }
  return out;
}

function truncate(s: string, max: number): string {
  const t = String(s).trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
