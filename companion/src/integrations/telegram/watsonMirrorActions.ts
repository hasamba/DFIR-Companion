import { randomBytes } from "node:crypto";
import type { WatsonProposal } from "../../analysis/ai/watson/types.js";

// #2712: Apply / Reject buttons under mirrored Watson proposals. Pure, no I/O.
//
// Only low-risk case writes get buttons (user decision 2026-11-25): a new finding, a new next step,
// report text, and a key question added or answered. Everything else — launches, hunts, CrowdStrike
// searches, held-row and super-timeline promotions, finding demote/dismiss, finding and next-step
// changes — keeps its text line and is decided in the dashboard. No Undo from Telegram.
//
// The button labels carry NO case content ("Apply 2"): they skip the mirror's masking and workstation
// path replacement, so the proposal itself is named only in the (masked) message text, by number.

/** Proposal kinds a Telegram press may decide. Default deny: a kind not listed here never gets a button. */
export const TELEGRAM_APPROVABLE_KINDS: ReadonlySet<WatsonProposal["kind"]> = new Set<WatsonProposal["kind"]>(
  ["finding_new", "next_step_new", "report_text", "question_new", "question_update"],
);

/** At most this many proposals of one batch get buttons (two each); the rest keep the text line. */
export const MIRROR_BUTTONS_MAX = 10;

/** A preview longer than this is not shown in full, so its proposal gets no button. */
export const MIRROR_PREVIEW_MAX = 1500;

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/**
 * What the analyst approves, as text: the actual change, not only its title. undefined = nothing
 * beyond the proposal line itself.
 */
export function proposalPreview(p: WatsonProposal): string | undefined {
  switch (p.kind) {
    case "finding_new":
      return `Severity ${str(p.after?.severity)}. ${str(p.after?.description)}`.trim();
    case "next_step_new":
      return p.after?.priority ? `Priority ${str(p.after.priority)}.` : undefined;
    case "report_text":
      return str(p.after) || "(empty)";
    case "question_new":
    case "question_update": {
      const answer = str(p.after?.answer);
      return [`Status ${str(p.after?.status)}.`, answer ? `Answer: ${answer}` : ""].filter(Boolean).join(" ");
    }
    default:
      return undefined;
  }
}

/** A finding that cites pasted lines adds those lines to the forensic timeline on apply: dashboard only. */
const promotesPasteLines = (p: WatsonProposal): boolean =>
  p.kind === "finding_new" &&
  ((Array.isArray(p.pasteLineEvents) && p.pasteLineEvents.length > 0) ||
    (Array.isArray(p.after?.citedPasteLines) && p.after.citedPasteLines.length > 0));

/**
 * May a Telegram press decide this STORED proposal now? Read from the chat store on every press —
 * never from the callback data. Pending only; an allowed kind; no paste-line promotion; a preview
 * short enough to be shown in full.
 */
export function telegramApprovable(p: WatsonProposal | undefined): p is WatsonProposal {
  if (!p || p.status !== "pending" || !TELEGRAM_APPROVABLE_KINDS.has(p.kind)) return false;
  if (promotesPasteLines(p)) return false;
  return (proposalPreview(p) ?? "").length <= MIRROR_PREVIEW_MAX;
}

// ── Callback data ─────────────────────────────────────────────────────────────────────

/** The two decisions a button can carry. Never "undo". */
export type MirrorButtonAction = "apply" | "reject";

const TOKEN_BYTES = 12; // 16 base64url characters, 96 random bits
const CALLBACK_RE = /^wm:([ar]):([A-Za-z0-9_-]{16})$/;

/** A fresh opaque token. It maps to (chat, proposal) in the mirror store; it carries no ids itself. */
export const newActionToken = (): string => randomBytes(TOKEN_BYTES).toString("base64url");

/** `wm:a:<token>` / `wm:r:<token>`: 21 bytes, inside Telegram's 64-byte callback_data limit. */
export const encodeMirrorCallback = (action: MirrorButtonAction, token: string): string =>
  `wm:${action === "apply" ? "a" : "r"}:${token}`;

/** The decision and token in a button's data, or undefined for anything else (forged, garbled, old). */
export function parseMirrorCallback(
  data: unknown,
): { action: MirrorButtonAction; token: string } | undefined {
  if (typeof data !== "string") return undefined;
  const m = CALLBACK_RE.exec(data);
  if (!m) return undefined;
  return { action: m[1] === "a" ? "apply" : "reject", token: m[2] };
}

export interface InlineKeyboard {
  inline_keyboard: Array<Array<{ text: string; callback_data: string }>>;
}

/** One row per numbered proposal: "Apply n" and "Reject n". undefined when there is nothing to press. */
export function buildMirrorKeyboard(
  buttons: ReadonlyArray<{ n: number; token: string }>,
): InlineKeyboard | undefined {
  if (buttons.length === 0) return undefined;
  return {
    inline_keyboard: buttons.map(({ n, token }) => [
      { text: `Apply ${n}`, callback_data: encodeMirrorCallback("apply", token) },
      { text: `Reject ${n}`, callback_data: encodeMirrorCallback("reject", token) },
    ]),
  };
}

// ── The approver ──────────────────────────────────────────────────────────────────────

/** The Telegram user behind a press, as Telegram sends it. Every field is untrusted input. */
export interface TelegramPresser {
  id?: unknown;
  username?: unknown;
  first_name?: unknown;
  last_name?: unknown;
}

const ACTOR_NAME_MAX = 48;
const USERNAME_RE = /^[A-Za-z0-9_]{4,32}$/;
// Control, format (bidi, zero-width), line/paragraph separators and private-use characters.
const UNSAFE_CHARS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}]/gu;

/** The presser's numeric Telegram id as a string, or undefined when it is not a safe integer. */
export function presserId(from: TelegramPresser | undefined): string | undefined {
  const id = from?.id;
  if (typeof id === "number" && Number.isSafeInteger(id)) return String(id);
  if (typeof id === "string" && /^-?\d{1,20}$/.test(id)) return id;
  return undefined;
}

const cleanName = (v: unknown): string =>
  typeof v === "string" ? v.replace(UNSAFE_CHARS, " ").replace(/\s+/g, " ").trim() : "";

/**
 * The actor a Telegram decision is recorded under — the badge, the report line and the activity log
 * read "approved by <name> (via Telegram)". The @username when Telegram has one (unique at the time),
 * else the cleaned display name, else the numeric id. The suffix is always added, so the actor can
 * never equal "Watson", "Watson (Auto)" or a dashboard analyst's plain name.
 */
export function telegramActor(from: TelegramPresser | undefined): string {
  const username = typeof from?.username === "string" && USERNAME_RE.test(from.username) ? from.username : "";
  const display = [cleanName(from?.first_name), cleanName(from?.last_name)].filter(Boolean).join(" ");
  const name = username
    ? `@${username}`
    : Array.from(display).slice(0, ACTOR_NAME_MAX).join("").trim() || presserId(from) || "unknown";
  return `${name} (via Telegram)`;
}
