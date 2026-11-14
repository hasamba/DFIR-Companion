import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { noteWatsonCaseEvent, WATSON_PENDING_EVENTS_MAX } from "../../src/composition/watsonCaseEvents.js";
import { buildWatsonProvider } from "../../src/composition/watsonProvider.js";
import { CaseStore } from "../../src/storage/caseStore.js";

async function chatStore(): Promise<WatsonChatStore> {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-events-")));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return new WatsonChatStore(store);
}

// The notes are fire-and-forget; an update queued behind them runs after all of them.
const settle = (chats: WatsonChatStore) => chats.update("c1", (c) => c);

describe("noteWatsonCaseEvent", () => {
  it("appends through the shared store, skips a repeat of the last line, and caps at 50", async () => {
    const chats = await chatStore();
    const notebook = { kind: "notebook" as const, text: "Analyst edited the notebook" };
    noteWatsonCaseEvent(chats, "c1", notebook);
    noteWatsonCaseEvent(chats, "c1", notebook);
    await settle(chats);
    const once = (await chats.load("c1")).pendingCaseEvents;
    expect(once).toMatchObject([notebook]);
    expect(Number.isNaN(Date.parse(once[0].at))).toBe(false);

    for (let i = 0; i < WATSON_PENDING_EVENTS_MAX + 10; i++) {
      noteWatsonCaseEvent(chats, "c1", { kind: "import", text: `event ${i}` });
    }
    await settle(chats);
    const events = (await chats.load("c1")).pendingCaseEvents;
    expect(events).toHaveLength(WATSON_PENDING_EVENTS_MAX);
    expect(events.at(-1)?.text).toBe(`event ${WATSON_PENDING_EVENTS_MAX + 9}`);
  });

  it("makes no model call and leaves the turns alone", async () => {
    const chats = await chatStore();
    noteWatsonCaseEvent(chats, "c1", { kind: "import", text: "An import finished" });
    await settle(chats);
    const chat = await chats.load("c1");
    expect(chat.turns).toEqual([]);
    expect(chat.calls).toBe(0);
  });
});

describe("buildWatsonProvider", () => {
  const base = {
    DFIR_AI_SYNTH_PROVIDER: "openai",
    DFIR_AI_SYNTH_KEY: "key-example",
    DFIR_AI_SYNTH_MODEL: "synth-model",
  };

  it("uses the synthesis model when DFIR_AI_WATSON_MODEL is blank", () => {
    expect(buildWatsonProvider({ ...base, DFIR_AI_WATSON_MODEL: "  " })?.model).toBe("synth-model");
    expect(buildWatsonProvider(base)?.model).toBe("synth-model");
  });

  it("keeps the synthesis provider but swaps the model when DFIR_AI_WATSON_MODEL is set", () => {
    const p = buildWatsonProvider({ ...base, DFIR_AI_WATSON_MODEL: "watson-model" });
    expect(p?.model).toBe("watson-model");
    expect(p?.name).toBe(buildWatsonProvider(base)?.name);
  });

  it("is undefined when no provider is configured", () => {
    expect(buildWatsonProvider({})).toBeUndefined();
  });
});
