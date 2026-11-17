import { rm } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { searchKey } from "../../../src/analysis/ai/watson/autoProgress.js";
import { WATSON_HISTORY_ID } from "../../../src/analysis/ai/watson/historyStore.js";
import { runWatsonTool } from "../../../src/analysis/ai/watson/toolDispatch.js";
import { clipRows } from "../../../src/analysis/ai/watson/toolPaste.js";
import { WATSON_TOOL } from "../../../src/analysis/ai/watson/toolSpecs.js";
import { CASE, call, harness, opts, turn } from "./toolDispatchFixtures.js";

// Watson phase 5, Task 5: the paste and history tools. The server checks the arguments itself (the
// Gemini adapter strips schema limits), and the counts say what was really sent (Codex P2-6).

const NOT_RUN = /^Lookup not run: /;
const live = opts();

describe("runWatsonTool: paste_search and history_search", () => {
  it("paste_search of an unknown paste id is not run; history_search reads the history and sets no readPasteId", async () => {
    const h = await harness({ pastes: { p1: "a\nrclone here\nb" } });
    const unknown = await runWatsonTool(
      h.ctx,
      CASE,
      h.chat,
      h.state,
      call(WATSON_TOOL.paste, { pasteId: "nope", terms: ["rclone"] }),
      live,
    );
    expect(unknown.result).toMatchObject({ isError: true, content: expect.stringMatching(NOT_RUN) });
    expect(unknown.lookedUp).toBeUndefined();
    expect(unknown.key).toBeUndefined(); // #2652: a search that did not run is not progress

    const known = await runWatsonTool(
      h.ctx,
      CASE,
      h.chat,
      h.state,
      call(WATSON_TOOL.paste, { pasteId: "p1", terms: ["rclone"] }),
      live,
    );
    expect(known.result.isError).toBeFalsy();
    expect(known.result.content).toContain("<<<PASTE id=p1>>>");
    expect(known.result.content).toContain("2: rclone here");
    expect(known.readPasteId).toBe("p1");
    expect(known.lookedUp).toMatchObject({ source: "paste", shown: 1, matched: 1 });
    expect(known.key).toBe(searchKey("p1", ["rclone"])); // #2652: the hop's key for the same search

    await h.chatStore.history.append(CASE, [turn("we saw rclone on HOST-A", "2026-11-01T00:00:00Z")]);
    const hist = await runWatsonTool(
      h.ctx,
      CASE,
      h.chat,
      h.state,
      call(WATSON_TOOL.history, { terms: ["rclone"] }),
      live,
    );
    expect(hist.result.isError).toBeFalsy();
    expect(hist.result.content).toContain("<<<HISTORY id=history>>>");
    expect(hist.result.content).toContain("rclone on HOST-A");
    expect(hist.readPasteId).toBeUndefined();
    expect(hist.lookedUp).toMatchObject({ source: "history", shown: 1, matched: 1 });
    expect(hist.key).toBe(searchKey(WATSON_HISTORY_ID, ["rclone"]));
  });

  it("the server checks the arguments: bad terms, the history id and unknown keys are not run", async () => {
    const h = await harness({ pastes: { p1: "rclone" } });
    const bad: [string, Record<string, unknown>][] = [
      [WATSON_TOOL.paste, { pasteId: "p1", terms: [] }],
      [WATSON_TOOL.paste, { pasteId: "p1", terms: ["  "] }],
      [WATSON_TOOL.paste, { pasteId: "p1", terms: "rclone" }],
      [WATSON_TOOL.paste, { pasteId: "p1", terms: [1] }],
      [WATSON_TOOL.paste, { pasteId: "p1", terms: Array.from({ length: 9 }, (_, i) => `t${i}`) }],
      [WATSON_TOOL.paste, { pasteId: "p1", terms: ["x".repeat(201)] }],
      [WATSON_TOOL.paste, { pasteId: "history", terms: ["rclone"] }],
      [WATSON_TOOL.paste, { pasteId: "", terms: ["rclone"] }],
      [WATSON_TOOL.paste, { terms: ["rclone"] }],
      [WATSON_TOOL.paste, { pasteId: "p1", terms: ["rclone"], context: 9 }],
      [WATSON_TOOL.history, { terms: ["rclone"], pasteId: "p1" }],
      [WATSON_TOOL.history, {}],
    ];
    for (const [name, input] of bad) {
      const r = await runWatsonTool(h.ctx, CASE, h.chat, h.state, call(name, input), live);
      expect(r.result.isError, JSON.stringify(input)).toBe(true);
      expect(r.result.content).toMatch(NOT_RUN);
      expect(r.readPasteId).toBeUndefined();
      expect(r.lookedUp).toBeUndefined();
    }
  });

  it("paste counts are real: with context lines, a clipped long line and a prompt clip, shown = matching rows actually sent, matched = total", async () => {
    // Odd lines match, even lines are context; line 1 is long and clipped. The 200-row cap stops the
    // excerpt at row 200, so 100 matching rows are sent of 300.
    const lines = Array.from({ length: 600 }, (_, i) =>
      i % 2 === 0 ? `hit ${i + 1}${i === 0 ? " " + "z".repeat(5000) : ""}` : `ctx ${i + 1}`,
    );
    const h = await harness({ pastes: { p1: lines.join("\n") } });
    const r = await runWatsonTool(
      h.ctx,
      CASE,
      h.chat,
      h.state,
      call(WATSON_TOOL.paste, { pasteId: "p1", terms: ["hit"] }),
      live,
    );
    expect(r.lookedUp).toMatchObject({ source: "paste", matched: 300, shown: 100 });
    expect(r.result.content).toContain("…[clipped]");
    expect(r.result.content).toContain("(truncated: ask for a search)");
  });

  it("history_search counts the same way on a real history file", async () => {
    const h = await harness();
    const turns = Array.from({ length: 30 }, (_, i) =>
      turn(
        i % 3 === 0 ? `rclone seen ${i}` : `other ${i}`,
        `2026-11-01T00:00:${String(i).padStart(2, "0")}Z`,
      ),
    );
    await h.chatStore.history.append(CASE, turns);
    const r = await runWatsonTool(
      h.ctx,
      CASE,
      h.chat,
      h.state,
      call(WATSON_TOOL.history, { terms: ["rclone"] }),
      live,
    );
    expect(r.lookedUp).toMatchObject({ source: "history", matched: 10, shown: 10 });
    const none = await runWatsonTool(
      h.ctx,
      CASE,
      h.chat,
      h.state,
      call(WATSON_TOOL.history, { terms: ["zzz"] }),
      live,
    );
    expect(none.lookedUp).toMatchObject({ source: "history", matched: 0, shown: 0 });
    expect(none.result.content).toContain("(no line matched: zzz)");
  });
});

describe("clipRows", () => {
  it("keeps whole numbered rows within the limit", () => {
    expect(clipRows("1: aaa\n2: bbb\n3: ccc", 14)).toBe("1: aaa\n2: bbb");
    expect(clipRows("1: aaa\n2: bbb", 100)).toBe("1: aaa\n2: bbb");
    expect(clipRows("1: aaaaaaaa", 4)).toBe("");
  });
});

describe("paste tools: fix round 1", () => {
  it("a paste file that cannot be read gives a fixed failure line; the real error is only logged", async () => {
    const h = await harness({ pastes: { p1: "rclone" } });
    await rm(join(h.ctx.cases.importsDir(CASE), "p1.txt"));
    const r = await runWatsonTool(
      h.ctx,
      CASE,
      h.chat,
      h.state,
      call(WATSON_TOOL.paste, { pasteId: "p1", terms: ["rclone"] }),
      live,
    );
    expect(r.result).toEqual({
      content: "Lookup failed: The lookup failed. Try a different lookup.",
      isError: true,
    });
    expect(r.readPasteId).toBeUndefined();
    expect(h.warnings.join("\n")).toContain("ENOENT");
  });

  it("the stored 'what' is capped", async () => {
    const h = await harness({ pastes: { p1: "rclone" } });
    const terms = Array.from({ length: 8 }, (_, i) => `${i}${"t".repeat(199)}`);
    const r = await runWatsonTool(h.ctx, CASE, h.chat, h.state, call(WATSON_TOOL.history, { terms }), live);
    expect(r.lookedUp!.what.length).toBeLessThanOrEqual(201);
    expect(r.lookedUp!.what.endsWith("…")).toBe(true);
  });
});
