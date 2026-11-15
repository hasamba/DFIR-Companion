import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runAiPreview } from "../../../src/analysis/ai/aiPreviewScope.js";
import { previewWatsonRound } from "../../../src/analysis/ai/watson/preview.js";
import type { WatsonRoundContext } from "../../../src/analysis/ai/watson/roundContext.js";
import { WATSON_MASK_ROSTER_MAX } from "../../../src/analysis/ai/watson/superRoster.js";
import { ROSTER_FULL_WHY } from "../../../src/analysis/ai/watson/toolDispatch.js";
import { PresidioApprovalRequired } from "../../../src/analysis/presidio.js";
import type { AnalyzeRequest } from "../../../src/providers/provider.js";
import type { ConverseRequest } from "../../../src/providers/toolCalling.js";
import {
  CASE,
  Scripted,
  call,
  calls,
  final,
  reply,
  resultsIn,
  superSearch,
  toolHarness,
} from "./roundToolsFixtures.js";
import { raw } from "./superPromoteFixtures.js";

// Task 3: a host named only in a raw row's or a paste's free text is masked on every send and saved
// on the chat's roster, in tool mode, in the one-step hop and in the AI preview.

const rawRow = raw("raw1", { description: "Logon from WS-FAKE01 by fake.user" });
const PASTE = "Logon from SRV-FAKE-02\n";

const wire = (p: Scripted): string =>
  JSON.stringify([...p.sent, ...p.analyzed] as (ConverseRequest | AnalyzeRequest)[]);

/** A stored paste: unread (its head is attached on its own) or already read (only a search reads it). */
async function storedPaste(ctx: WatsonRoundContext, unread: boolean): Promise<void> {
  const dir = ctx.cases.importsDir(CASE);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "watson-paste-p1.txt"), PASTE);
  const paste = {
    id: "p1",
    storedName: "watson-paste-p1.txt",
    filename: "notes.txt",
    bytes: PASTE.length,
    lines: 1,
    at: "2026-01-01T00:00:00Z",
  };
  await ctx.chatStore.update(CASE, (c) => ({
    ...c,
    pastes: [...c.pastes, paste],
    unreadPasteIds: unread ? ["p1"] : [],
  }));
}

const pasteSearch = { search: { pasteId: "p1", terms: ["logon"] } };
const superLookupLogon = { lookup: { source: "supertimeline", text: "logon" } };

describe("a host named only in a raw row's description", () => {
  it("tool mode: the description host is masked on every send and saved on the roster", async () => {
    const p = new Scripted([calls(superSearch({ text: "logon" })), final()]);
    const h = await toolHarness(p, { anonymize: true, raw: [rawRow] });
    const chat = await h.run("who logged on?");
    expect(resultsIn(p.sent[1]).length).toBeGreaterThan(0);
    expect(wire(p)).not.toContain("WS-FAKE01");
    expect(chat.maskRoster?.hosts).toContain("ws-fake01");
  });

  it("one-step hop (maxToolCalls 0): the description host is masked and saved", async () => {
    const p = new Scripted([], { hop: [reply(superLookupLogon), reply()] });
    const h = await toolHarness(p, { anonymize: true, raw: [rawRow], maxToolCalls: 0 });
    const chat = await h.run("who logged on?");
    expect(p.analyzed).toHaveLength(2);
    expect(wire(p)).not.toContain("WS-FAKE01");
    expect(chat.maskRoster?.hosts).toContain("ws-fake01");
  });

  it("a full roster refuses the search instead of dropping names (H5)", async () => {
    const fill = Array.from({ length: WATSON_MASK_ROSTER_MAX - 1 }, (_, i) => `oldhost${i}`);
    const row = raw("raw1", { asset: "HOST-A", description: "Logon from WS-FAKE09" });
    const p = new Scripted([calls(superSearch({ text: "logon" })), final()]);
    const h = await toolHarness(p, { anonymize: true, raw: [row] });
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      maskRoster: { hosts: ["host-a", ...fill], users: [], ips: [] },
    }));
    const chat = await h.run("who logged on?");
    expect(
      resultsIn(p.sent[1])
        .map((r) => r.content)
        .join("\n"),
    ).toContain(ROSTER_FULL_WHY);
    expect(wire(p)).not.toContain("WS-FAKE09");
    expect(chat.maskRoster?.hosts).not.toContain("ws-fake09");
  });
});

describe("a host named only in a paste's free text", () => {
  it("tool mode: a paste_search result's bare host is masked and persisted", async () => {
    const p = new Scripted([calls(call("paste_search", { pasteId: "p1", terms: ["logon"] })), final()]);
    const h = await toolHarness(p, { anonymize: true });
    await storedPaste(h.ctx, false);
    const chat = await h.run();
    expect(wire(p)).toContain("paste_search");
    expect(wire(p)).not.toContain("SRV-FAKE-02");
    expect(chat.maskRoster?.hosts).toContain("srv-fake-02");
  });

  it("tool mode: an unread paste head's bare host is masked and persisted", async () => {
    const p = new Scripted([final()]);
    const h = await toolHarness(p, { anonymize: true });
    await storedPaste(h.ctx, true);
    const chat = await h.run();
    expect(p.sent).toHaveLength(1);
    expect(wire(p)).not.toContain("SRV-FAKE-02");
    expect(chat.maskRoster?.hosts).toContain("srv-fake-02");
  });

  it("one-step hop: an unread paste head's bare host is masked and persisted", async () => {
    const p = new Scripted([], { hop: [reply()] });
    const h = await toolHarness(p, { anonymize: true, maxToolCalls: 0 });
    await storedPaste(h.ctx, true);
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(1);
    expect(wire(p)).not.toContain("SRV-FAKE-02");
    expect(chat.maskRoster?.hosts).toContain("srv-fake-02");
  });

  it("one-step search hop: the searched paste's bare host is masked and persisted", async () => {
    const p = new Scripted([], { hop: [reply(pasteSearch), reply()] });
    const h = await toolHarness(p, { anonymize: true, maxToolCalls: 0 });
    await storedPaste(h.ctx, false);
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(2);
    expect(wire(p)).not.toContain("SRV-FAKE-02");
    expect(chat.maskRoster?.hosts).toContain("srv-fake-02");
  });

  const failures: Record<string, () => Promise<string>> = {
    transport: async () => {
      throw new Error("network down");
    },
    unreadable: async () => "this is not JSON at all",
    presidio: async () => {
      throw new PresidioApprovalRequired([]);
    },
    stop: async () => {
      throw new DOMException("The operation was aborted.", "AbortError");
    },
  };

  it.each(Object.keys(failures))(
    "one-step search hop: a %s failure after the excerpt was sent still saves its names (Codex #6)",
    async (kind) => {
      const p = new Scripted([], { hop: [reply(pasteSearch)] });
      const first = p.analyze.bind(p);
      p.analyze = async (req) => {
        if (p.analyzed.length === 0) return first(req);
        p.analyzed.push(req);
        return { rawText: await failures[kind](), usage: { inputTokens: 10 } };
      };
      const h = await toolHarness(p, { anonymize: true, maxToolCalls: 0 });
      await storedPaste(h.ctx, false);
      await h.run().catch(() => undefined);
      expect(p.analyzed).toHaveLength(2);
      expect(wire(p)).not.toContain("SRV-FAKE-02");
      expect((await h.ctx.chatStore.loadRoster(CASE))?.hosts).toContain("srv-fake-02");
    },
  );

  it("tool-mode preview masks an unread paste head's bare host exactly like the first real send (Codex #10)", async () => {
    const p = new Scripted([final()]);
    const h = await toolHarness(p, { anonymize: true, maxToolCalls: 4 });
    await storedPaste(h.ctx, true);
    const before = await h.chatStore.load(CASE);
    const draft = "who logged on?";
    const res = await runAiPreview(() => previewWatsonRound(h.ctx, CASE, draft));
    expect(res.outcome).toBe("captured");
    if (res.outcome !== "captured") return;
    expect(res.call.clearPrompt).toContain("SRV-FAKE-02");
    expect(res.call.maskedPrompt).not.toContain("SRV-FAKE-02");
    expect(p.sent).toHaveLength(0);
    expect(await h.chatStore.load(CASE)).toEqual(before);
    await h.run(draft);
    expect(p.sent).toHaveLength(1);
    expect(p.sent[0].userPrompt).not.toContain("SRV-FAKE-02");
    expect(p.sent[0].userPrompt).toBe(res.call.maskedPrompt);
  });
});
