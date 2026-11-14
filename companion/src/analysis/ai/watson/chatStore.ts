import { copyFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../../storage/caseStore.js";
import { atomicWrite } from "../../../storage/atomicWrite.js";
import { WatsonHistoryStore } from "./historyStore.js";
import { proposalSchema } from "./proposalSchema.js";
import { turnSchema } from "./turnSchema.js";
import {
  emptyWatsonChat,
  type WatsonCaseEvent,
  type WatsonChat,
  type WatsonProposal,
  type WatsonReactionsPaused,
  type WatsonTurn,
} from "./types.js";

// Per-case persistence for the Watson chat (state/watson-chat.json). A side file like
// hunt-outcomes.json: not part of InvestigationState, in SNAPSHOT_STATE_FILES so the chat travels
// with an exported case. Every writer goes through update(), which serializes per case.

export const WATSON_MAX_TURNS = 400;
export const WATSON_TURN_TEXT_MAX = 8000;

const pasteSchema = z.object({
  id: z.string(),
  storedName: z.string(),
  filename: z.string(),
  bytes: z.number(),
  lines: z.number(),
  at: z.string(),
  parsed: z
    .union([
      z.object({ kind: z.literal("text"), reason: z.string() }),
      z.object({ kind: z.string(), rows: z.number(), held: z.number() }),
    ])
    .optional()
    .catch(undefined),
});

const caseEventSchema = z.object({
  kind: z.enum(["import", "notebook", "star", "other"]).catch("other"),
  text: z.string(),
  at: z.string().catch(""),
});

/** A phase-1 chat stored each case event as a bare line: it loads as kind "other", time unknown. */
const caseEventItem = z.union([
  z.string().transform((text): WatsonCaseEvent => ({ kind: "other", text, at: "" })),
  caseEventSchema,
]);

function lenientList<T>(raw: unknown, schema: z.ZodType<T, z.ZodTypeDef, unknown>): T[] {
  if (!Array.isArray(raw)) return [];
  const out: T[] = [];
  for (const item of raw) {
    const r = schema.safeParse(item);
    if (r.success) out.push(r.data);
  }
  return out;
}

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((e): e is string => typeof e === "string") : [];

const PAUSES: readonly string[] = ["presidio", "limit", "errors"];

/**
 * The reaction bookkeeping of a stored chat. A chat written before `analystEngaged` existed counts as
 * engaged when it still holds an analyst turn (the flag is then saved with it, so it survives the cap).
 */
function reactionFields(
  o: Record<string, unknown>,
  turns: readonly WatsonTurn[],
): Pick<WatsonChat, "reactionsPaused" | "reactionFailures" | "analystEngaged"> {
  const failures = o.reactionFailures;
  return {
    ...(typeof o.reactionsPaused === "string" && PAUSES.includes(o.reactionsPaused)
      ? { reactionsPaused: o.reactionsPaused as WatsonReactionsPaused }
      : {}),
    ...(typeof failures === "number" && Number.isInteger(failures) && failures > 0
      ? { reactionFailures: failures }
      : {}),
    ...(o.analystEngaged === true || turns.some((t) => t.role === "analyst") ? { analystEngaged: true } : {}),
  };
}

function parseChat(raw: unknown): WatsonChat {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return emptyWatsonChat();
  const o = raw as Record<string, unknown>;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  const turns = lenientList<WatsonTurn>(o.turns, turnSchema);
  return {
    turns,
    proposals: lenientList<WatsonProposal>(o.proposals, proposalSchema),
    pastes: lenientList(o.pastes, pasteSchema),
    unreadPasteIds: strings(o.unreadPasteIds),
    memory: typeof o.memory === "string" ? o.memory : "",
    pendingCaseEvents: lenientList<WatsonCaseEvent>(o.pendingCaseEvents, caseEventItem),
    ...reactionFields(o, turns),
    costUSD: num(o.costUSD),
    tokens: num(o.tokens),
    calls: num(o.calls),
    ...(typeof o.threadStartAt === "string" && o.threadStartAt ? { threadStartAt: o.threadStartAt } : {}),
  };
}

// A decided-against proposal (rejected, undone) whose turn left the chat is dropped; every pending and
// applied proposal stays, since apply and undo need them.
const SETTLED: ReadonlySet<WatsonProposal["status"]> = new Set(["rejected", "undone"]);

// New object: oldest turns dropped past the cap, over-long text trimmed, settled proposals of dropped
// turns removed. The input is not mutated.
function normalize(chat: WatsonChat): WatsonChat {
  const turns = chat.turns
    .slice(-WATSON_MAX_TURNS)
    .map((t) =>
      t.text.length > WATSON_TURN_TEXT_MAX ? { ...t, text: t.text.slice(0, WATSON_TURN_TEXT_MAX) } : t,
    );
  const kept = new Set(turns.map((t) => t.id));
  const proposals = chat.proposals.filter((p) => !SETTLED.has(p.status) || kept.has(p.turnId));
  return { ...chat, turns, proposals };
}

export class WatsonChatStore {
  private readonly chains = new Map<string, Promise<unknown>>();

  /** Every turn ever, append-only; update() is its only writer. */
  readonly history: WatsonHistoryStore;

  constructor(private readonly cases: CaseStore) {
    this.history = new WatsonHistoryStore(cases);
  }

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "watson-chat.json");
  }

  // Empty chat when the file is absent or malformed, so a corrupt side file never sinks a request.
  async load(caseId: string): Promise<WatsonChat> {
    return (await this.read(caseId)).chat;
  }

  /** The chat, and whether a file exists that is not a chat at all (bad JSON or the wrong shape). */
  private async read(caseId: string): Promise<{ chat: WatsonChat; corrupt: boolean }> {
    let raw: unknown;
    try {
      raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT")
        return { chat: emptyWatsonChat(), corrupt: false };
      if (err instanceof SyntaxError) return { chat: emptyWatsonChat(), corrupt: true };
      throw err;
    }
    return { chat: parseChat(raw), corrupt: typeof raw !== "object" || raw === null || Array.isArray(raw) };
  }

  /** Keep a corrupt chat file beside the new one before the first write replaces it. No colons: Windows. */
  private async backUpCorrupt(caseId: string): Promise<void> {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    await copyFile(this.path(caseId), `${this.path(caseId)}.corrupt-${stamp}`);
  }

  async save(caseId: string, chat: WatsonChat): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(normalize(chat), null, 2));
  }

  // Every turn the update added goes to the history file first, so a failed append fails the update
  // and the chat file never holds a turn the history lacks. A chat that has no history file yet
  // (it predates the history) seeds it with the turns it already holds.
  private async keepHistory(caseId: string, before: WatsonChat, after: WatsonChat): Promise<void> {
    const known = new Set(before.turns.map((t) => t.id));
    const added = after.turns.filter((t) => !known.has(t.id));
    const seed = (await this.history.exists(caseId)) ? [] : before.turns;
    await this.history.append(caseId, [...seed, ...added]);
  }

  // Load, apply fn, save, return the saved chat. Calls for one case run one at a time, so
  // concurrent writers never lose each other's writes. A throwing fn rejects only its own call.
  update(caseId: string, fn: (chat: WatsonChat) => WatsonChat | Promise<WatsonChat>): Promise<WatsonChat> {
    const prev = this.chains.get(caseId) ?? Promise.resolve();
    const run = prev.then(async () => {
      const { chat, corrupt } = await this.read(caseId);
      const changed = await fn(chat);
      await this.keepHistory(caseId, chat, changed);
      const next = normalize(changed);
      if (corrupt) await this.backUpCorrupt(caseId);
      await this.save(caseId, next);
      return next;
    });
    const tail = run.catch(() => undefined);
    this.chains.set(caseId, tail);
    void tail.then(() => {
      if (this.chains.get(caseId) === tail) this.chains.delete(caseId);
    });
    return run;
  }
}
