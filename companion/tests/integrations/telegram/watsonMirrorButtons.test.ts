import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { WatsonMirror } from "../../../src/integrations/telegram/watsonMirror.js";
import { WatsonMirrorStore } from "../../../src/integrations/telegram/watsonMirrorStore.js";
import type { InlineKeyboard } from "../../../src/integrations/telegram/watsonMirrorActions.js";
import {
  MIRROR_BUTTONS_MAX,
  parseMirrorCallback,
} from "../../../src/integrations/telegram/watsonMirrorActions.js";
import {
  emptyWatsonChat,
  type WatsonProposal,
  type WatsonTurn,
} from "../../../src/analysis/ai/watson/types.js";

// #2712: the mirror arms Apply / Reject buttons only under proposals a Telegram press may decide, on
// the last message of a batch, with labels that carry no case content.

const AT = "2026-11-25T10:00:00.000Z";
const ENABLED = "2026-11-25T09:00:00.000Z";

interface Sent {
  text: string;
  markup?: InlineKeyboard;
}

let store: WatsonMirrorStore;
let sends: Sent[];
let turns: WatsonTurn[];
let proposals: WatsonProposal[];
let mirror: WatsonMirror;

const proposal = (id: string, kind: string, extra: Record<string, unknown> = {}): WatsonProposal =>
  ({
    id,
    turnId: "wt-w",
    status: "pending",
    kind,
    targetId: `t-${id}`,
    ...extra,
  }) as unknown as WatsonProposal;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-mirror-buttons-"));
  store = new WatsonMirrorStore(join(root, "watson-mirror.json"));
  sends = [];
  turns = [];
  proposals = [];
  mirror = new WatsonMirror({
    store,
    loadChat: async () => ({ ...emptyWatsonChat(), turns, proposals }),
    loadHistory: async () => ({ turns, more: false }),
    liveness: async () => ({ ok: true }),
    masking: async (_c, raw) => ({ ok: true, text: raw.replace(/HOST-REAL/g, "HOST_1") }),
    send: async (_chatId, text, _bot, markup) => {
      sends.push({ text, ...(markup ? { markup } : {}) });
      return { kind: "sent", messageId: 100 + sends.length };
    },
    audit: () => {},
    roots: [],
    publicUrl: () => undefined,
    log: { warn: () => {}, info: () => {}, error: () => {}, debug: () => {} } as never,
    setTimer: (fn, ms) => {
      if (ms === 0) setImmediate(fn);
      return () => {};
    },
    sleep: async () => {},
  });
  await store.enable("100", { caseId: "c1", chatType: "private", by: "42", boundAt: "b1", at: ENABLED });
});

async function flush(): Promise<void> {
  await mirror.notify("c1");
  for (let i = 0; i < 5; i++) {
    await new Promise((r) => setImmediate(r));
    await mirror.idle();
  }
}

const watsonTurn = (ids: string[], text = "Here is what I found"): WatsonTurn => ({
  id: "wt-w",
  at: AT,
  role: "watson",
  text,
  proposalIds: ids,
});

describe("mirror buttons (#2712)", () => {
  it("arms buttons only under the eligible proposals, numbered, with a preview", async () => {
    proposals = [
      proposal("wp-f", "finding_new", {
        after: { title: "Beacon on HOST-REAL", severity: "High", description: "C2 from HOST-REAL" },
        pasteLineEvents: [],
      }),
      proposal("wp-v", "velo_launch", { title: "Collect", mode: "collect" }),
      proposal("wp-r", "finding_review", { action: "dismiss", before: { title: "Old" } }),
      proposal("wp-s", "next_step_new", { after: { action: "Pull logs", priority: "high" } }),
      proposal("wp-done", "report_text", { status: "applied", field: "conclusions", after: "x" }),
    ];
    turns = [watsonTurn(["wp-f", "wp-v", "wp-r", "wp-s", "wp-done"])];
    await flush();

    expect(sends).toHaveLength(1);
    const { text, markup } = sends[0];
    expect(text).toContain("Watson proposes [1]: new finding: Beacon on HOST_1");
    expect(text).toContain("Severity High. C2 from HOST_1"); // the preview is masked too
    expect(text).toContain("Watson proposes [2]: new next step: Pull logs");
    expect(text).toContain("Watson proposes: Velociraptor collection: Collect");
    expect(text).toContain("Watson proposes: dismiss finding: Old");
    expect(text).not.toContain("HOST-REAL");
    expect(markup?.inline_keyboard.map((r) => r.map((b) => b.text))).toEqual([
      ["Apply 1", "Reject 1"],
      ["Apply 2", "Reject 2"],
    ]);

    // Each token maps back to its own proposal and this chat.
    const [first, second] = markup!.inline_keyboard.map(
      (r) => parseMirrorCallback(r[0].callback_data)!.token,
    );
    expect((await store.findAction(first))?.proposalId).toBe("wp-f");
    expect((await store.findAction(second))?.proposalId).toBe("wp-s");
    expect(JSON.stringify(markup)).not.toMatch(/Beacon|HOST|Pull logs/);
  });

  it("sends no keyboard when nothing in the batch is eligible", async () => {
    proposals = [proposal("wp-v", "velo_launch", { title: "Collect", mode: "hunt" })];
    turns = [watsonTurn(["wp-v"])];
    await flush();
    expect(sends).toHaveLength(1);
    expect(sends[0].markup).toBeUndefined();
    expect(sends[0].text).not.toContain("[1]");
  });

  it("puts the keyboard on the last message of a split batch only", async () => {
    proposals = [proposal("wp-s", "next_step_new", { after: { action: "Pull logs", priority: "high" } })];
    turns = [watsonTurn(["wp-s"], "long line\n".repeat(900))];
    await flush();
    expect(sends.length).toBeGreaterThan(1);
    expect(sends.slice(0, -1).every((s) => !s.markup)).toBe(true);
    expect(sends.at(-1)?.markup?.inline_keyboard).toHaveLength(1);
  });

  it("caps the buttons and numbers each proposal once", async () => {
    const ids = Array.from({ length: MIRROR_BUTTONS_MAX + 3 }, (_, i) => `wp-${i}`);
    proposals = ids.map((id) =>
      proposal(id, "next_step_new", { after: { action: `step ${id}`, priority: "low" } }),
    );
    turns = [watsonTurn([...ids, ids[0]])];
    await flush();
    expect(sends.at(-1)?.markup?.inline_keyboard).toHaveLength(MIRROR_BUTTONS_MAX);
    expect(sends.map((s) => s.text).join("")).toContain(
      `Watson proposes: new next step: step wp-${MIRROR_BUTTONS_MAX}`,
    );
  });
});
