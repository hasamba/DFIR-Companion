import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { WatsonPromptInput } from "../../../src/analysis/ai/watson/promptBuilder.js";
import type { WatsonRoundContext } from "../../../src/analysis/ai/watson/roundContext.js";
import { ThinkingBindingError } from "../../../src/providers/toolCalling.js";
import { CASE, Scripted, calls, reply, superSearch, toolHarness } from "./roundToolsFixtures.js";
import { raw } from "./superPromoteFixtures.js";

// Task 3 review M4: after a tool-mode fallback that carries a roster, the hop's first call still
// masks with the paste head's names in base.rawRoster: the carried roster is merged in, never
// swapped for it.

const seen = vi.hoisted(() => ({ rosters: [] as (string[] | undefined)[] }));

vi.mock("../../../src/analysis/ai/watson/requestBuild.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../../src/analysis/ai/watson/requestBuild.js")>();
  return {
    ...real,
    callWatson: (...args: Parameters<typeof real.callWatson>) => {
      const input: WatsonPromptInput = args[4];
      seen.rosters.push(input.rawRoster?.hosts);
      return real.callWatson(...args);
    },
  };
});

const PASTE = "Logon from SRV-FAKE-02\n";

async function unreadPaste(ctx: WatsonRoundContext): Promise<void> {
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
  await ctx.chatStore.update(CASE, (c) => ({ ...c, pastes: [...c.pastes, paste], unreadPasteIds: ["p1"] }));
}

describe("a tool-mode fallback keeps the paste head's names in rawRoster (M4)", () => {
  it("the hop's first call masks with the head's names and the loop's carried names", async () => {
    const refused = new ThinkingBindingError("must start with a thinking block");
    const p = new Scripted([calls(superSearch({ text: "rclone" })), refused], { hop: [reply()] });
    const h = await toolHarness(p, { anonymize: true, raw: [raw("raw1", { asset: "HOST-B" })] });
    await unreadPaste(h.ctx);
    seen.rosters.length = 0;
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(1);
    expect(seen.rosters).toHaveLength(1);
    expect(seen.rosters[0]).toEqual(expect.arrayContaining(["srv-fake-02", "host-b"]));
    expect(chat.maskRoster?.hosts).toEqual(expect.arrayContaining(["srv-fake-02", "host-b"]));
  });
});
