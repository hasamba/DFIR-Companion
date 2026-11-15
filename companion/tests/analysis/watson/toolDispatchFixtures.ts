import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import type { WatsonRoundContext } from "../../../src/analysis/ai/watson/roundContext.js";
import type { ToolRunOptions } from "../../../src/analysis/ai/watson/toolDispatch.js";
import { WATSON_TOOL } from "../../../src/analysis/ai/watson/toolSpecs.js";
import type { WatsonRawSearchDeps } from "../../../src/analysis/ai/watson/superTimelineSearch.js";
import { emptyWatsonChat, type WatsonChat, type WatsonTurn } from "../../../src/analysis/ai/watson/types.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../../src/analysis/superTimelineStore.js";
import type { Logger } from "../../../src/logging/logger.js";
import type { ToolCall } from "../../../src/providers/toolCalling.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// Shared harness for the Watson tool dispatcher tests (phase 5, Task 5): a real case on disk, a real
// super-timeline store behind a spying reader, and a chat with stored pastes.

export const CASE = "c1";
const logInto = (warnings: string[]): Logger => ({
  debug: () => undefined,
  info: () => undefined,
  warn: (...args: unknown[]) => void warnings.push(args.map((a) => JSON.stringify(a)).join(" ")),
  error: () => undefined,
  getLevel: () => "debug",
  setLevel: () => undefined,
  close: async () => undefined,
});

/** Options for a live analyst round that offers every tool and has super searches left. */
export const opts = (over: Partial<ToolRunOptions> = {}): ToolRunOptions => ({
  reaction: false,
  superLeft: 2,
  offered: Object.values(WATSON_TOOL),
  ...over,
});

export const ev = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T15:00:00Z",
  description: `quiet event ${id}`,
  severity: "Low",
  sources: ["Hayabusa"],
  asset: "HOST-A",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

export const raw = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev(id, { severity: "Info", description: `rclone copy ${id}`, ...over });

let callNo = 0;
export const call = (name: string, input: Record<string, unknown>): ToolCall => ({
  id: `call-${++callNo}`,
  name,
  input,
});

export interface Harness {
  ctx: WatsonRoundContext;
  state: InvestigationState;
  chat: WatsonChat;
  queries: unknown[];
  chatStore: WatsonChatStore;
  /** Everything the dispatcher logged at warn level. */
  warnings: string[];
}

export interface HarnessOpts {
  raw?: ForensicEvent[];
  noRawSearch?: boolean;
  anonymize?: boolean;
  /** Paste id → text, stored on disk and listed in the chat. */
  pastes?: Record<string, string>;
  /** The reader throws this on every query. */
  readerThrows?: Error;
}

export async function harness(o: HarnessOpts = {}): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-tools-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const state: InvestigationState = {
    ...emptyState(CASE),
    forensicTimeline: [ev("e1", { description: "rclone forensic e1" }), ev("e2")],
  };
  await stateStore.save(state);
  const anonStore = new AnonControlStore(cases);
  await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: o.anonymize ?? false });
  const store = new SuperTimelineStore(cases);
  await store.append(CASE, o.raw ?? [raw("raw1")]);
  const queries: unknown[] = [];
  const rawSearch: WatsonRawSearchDeps = {
    reader: {
      query: (id, q) => {
        queries.push(q);
        return o.readerThrows ? Promise.reject(o.readerThrows) : store.query(id, q);
      },
      meta: (id) => store.meta(id),
    },
    writer: {} as never,
    writable: async () => true,
  };
  const chat = { ...emptyWatsonChat(), pastes: await storePastes(cases, o.pastes ?? {}) };
  const chatStore = new WatsonChatStore(cases);
  const warnings: string[] = [];
  const ctx = {
    opts: { stateStore, anonStore },
    log: logInto(warnings),
    chatStore,
    stateStore,
    cases,
    ...(o.noRawSearch ? {} : { rawSearch }),
  } as unknown as WatsonRoundContext;
  return { ctx, state, chat, queries, chatStore, warnings };
}

async function storePastes(cases: CaseStore, pastes: Record<string, string>) {
  const out: WatsonChat["pastes"] = [];
  for (const [id, text] of Object.entries(pastes)) {
    const storedName = `${id}.txt`;
    await writeFile(join(cases.importsDir(CASE), storedName), text, "utf8");
    const lines = text.split("\n").length;
    out.push({
      id,
      storedName,
      filename: `${id}.log`,
      bytes: text.length,
      lines,
      at: "2026-11-01T00:00:00Z",
    });
  }
  return out;
}

export const turn = (text: string, at: string): WatsonTurn =>
  ({ id: `t-${at}`, role: "analyst", text, at }) as unknown as WatsonTurn;
