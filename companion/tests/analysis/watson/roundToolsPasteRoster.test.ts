import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { WatsonRoundContext } from "../../../src/analysis/ai/watson/roundContext.js";
import { Scripted, call, calls, final, toolHarness } from "./roundToolsFixtures.js";

// Final review F7: the names a paste or history tool showed the model join the chat's mask roster,
// like a super-timeline search's names, so a later question masks them too.

const LINE = "rclone copy by CORP\\jdoe.smith from ws-fin-0042.corp.local\n";

/** A stored paste the round does not attach on its own: only the paste tool reads it. */
async function storedPaste(ctx: WatsonRoundContext): Promise<void> {
  const dir = ctx.cases.importsDir("c1");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "watson-paste-p1.txt"), LINE);
  const paste = {
    id: "p1",
    storedName: "watson-paste-p1.txt",
    filename: "notes.txt",
    bytes: LINE.length,
    lines: 1,
    at: "2026-01-01T00:00:00Z",
  };
  await ctx.chatStore.update("c1", (c) => ({ ...c, pastes: [...c.pastes, paste], unreadPasteIds: [] }));
}

describe("paste and history tool names join the chat's mask roster (F7)", () => {
  it("a paste_search result's host and account are on chat.maskRoster after the round", async () => {
    const p = new Scripted([calls(call("paste_search", { pasteId: "p1", terms: ["rclone"] })), final()]);
    const h = await toolHarness(p);
    await storedPaste(h.ctx);
    const chat = await h.run();
    expect(chat.maskRoster?.hosts).toContain("ws-fin-0042.corp.local");
    expect(chat.maskRoster?.users).toContain("jdoe.smith");
  });
});
