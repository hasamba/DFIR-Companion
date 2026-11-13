import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../../storage/caseStore.js";
import { atomicWrite } from "../../../storage/atomicWrite.js";
import type { InvestigationQuestion } from "../../stateTypes.js";
import { emptyWatsonChat, type WatsonChat, type WatsonProposal, type WatsonTurn } from "./types.js";

// Per-case persistence for the Watson chat (state/watson-chat.json). A side file like
// hunt-outcomes.json: not part of InvestigationState, in SNAPSHOT_STATE_FILES so the chat travels
// with an exported case. Every writer goes through update(), which serializes per case.

export const WATSON_MAX_TURNS = 400;
export const WATSON_TURN_TEXT_MAX = 8000;

const requestSchema = z.union([
  z.object({ kind: z.literal("query"), language: z.string(), query: z.string(), why: z.string() }),
  z.object({ kind: z.literal("import"), what: z.string(), why: z.string() }),
]);

const turnSchema = z.object({
  id: z.string(),
  at: z.string(),
  role: z.enum(["analyst", "watson", "system"]),
  text: z.string(),
  actor: z.string().optional(),
  workingOn: z.string().optional(),
  learned: z.string().optional(),
  request: requestSchema.optional(),
  proposalIds: z.array(z.string()).optional(),
  pasteId: z.string().optional(),
  error: z.boolean().optional(),
  costUSD: z.number().optional(),
});

const question = z.custom<InvestigationQuestion>(
  (v) => typeof v === "object" && v !== null && typeof (v as { id?: unknown }).id === "string",
);

const proposalSchema = z.object({
  id: z.string(),
  turnId: z.string(),
  kind: z.enum(["question_update", "question_new"]),
  questionId: z.string(),
  before: question.optional(),
  after: question,
  status: z.enum(["pending", "applied", "rejected", "undone"]),
});

const pasteSchema = z.object({
  id: z.string(),
  storedName: z.string(),
  filename: z.string(),
  bytes: z.number(),
  lines: z.number(),
  at: z.string(),
});

function lenientList<T>(raw: unknown, schema: z.ZodType<T, z.ZodTypeDef, unknown>): T[] {
  if (!Array.isArray(raw)) return [];
  const out: T[] = [];
  for (const item of raw) {
    const r = schema.safeParse(item);
    if (r.success) out.push(r.data);
  }
  return out;
}

function parseChat(raw: unknown): WatsonChat {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return emptyWatsonChat();
  const o = raw as Record<string, unknown>;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  return {
    turns: lenientList<WatsonTurn>(o.turns, turnSchema),
    proposals: lenientList<WatsonProposal>(o.proposals, proposalSchema),
    pastes: lenientList(o.pastes, pasteSchema),
    memory: typeof o.memory === "string" ? o.memory : "",
    pendingCaseEvents: Array.isArray(o.pendingCaseEvents)
      ? o.pendingCaseEvents.filter((e): e is string => typeof e === "string")
      : [],
    costUSD: num(o.costUSD),
    tokens: num(o.tokens),
    calls: num(o.calls),
  };
}

// New object: oldest turns dropped past the cap, over-long text trimmed. The input is not mutated.
function normalize(chat: WatsonChat): WatsonChat {
  const turns = chat.turns
    .slice(-WATSON_MAX_TURNS)
    .map((t) =>
      t.text.length > WATSON_TURN_TEXT_MAX ? { ...t, text: t.text.slice(0, WATSON_TURN_TEXT_MAX) } : t,
    );
  return { ...chat, turns };
}

export class WatsonChatStore {
  private readonly chains = new Map<string, Promise<unknown>>();

  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "watson-chat.json");
  }

  // Empty chat when the file is absent or malformed, so a corrupt side file never sinks a request.
  async load(caseId: string): Promise<WatsonChat> {
    try {
      return parseChat(JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyWatsonChat();
      if (err instanceof SyntaxError) return emptyWatsonChat();
      throw err;
    }
  }

  async save(caseId: string, chat: WatsonChat): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(normalize(chat), null, 2));
  }

  // Load, apply fn, save, return the saved chat. Calls for one case run one at a time, so
  // concurrent writers never lose each other's writes. A throwing fn rejects only its own call.
  update(caseId: string, fn: (chat: WatsonChat) => WatsonChat | Promise<WatsonChat>): Promise<WatsonChat> {
    const prev = this.chains.get(caseId) ?? Promise.resolve();
    const run = prev.then(async () => {
      const next = normalize(await fn(await this.load(caseId)));
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
