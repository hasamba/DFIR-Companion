import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

/**
 * `.env.example` once set five keys twice as active lines — the documented copy in its own section
 * and a stale second copy under "UI LIMITS" (#2777). The values agreed, but an edit to one copy
 * would have been silently overridden by the other. Every key may be set by at most one active
 * (uncommented) line; mention it elsewhere in a comment instead.
 */

const ACTIVE_KEY = /^([A-Z][A-Z0-9_]*)=/;

async function envExample(): Promise<string> {
  return readFile(new URL("../../.env.example", import.meta.url), "utf8");
}

function duplicateActiveKeys(text: string): string[] {
  const lines = new Map<string, number[]>();
  text.split(/\r?\n/).forEach((line, i) => {
    const key = ACTIVE_KEY.exec(line)?.[1];
    if (key) lines.set(key, [...(lines.get(key) ?? []), i + 1]);
  });
  return [...lines.entries()]
    .filter(([, at]) => at.length > 1)
    .map(([key, at]) => `${key} (lines ${at.join(", ")})`);
}

describe(".env.example", () => {
  it("sets every key on at most one active line", async () => {
    expect(duplicateActiveKeys(await envExample())).toEqual([]);
  });

  it("detects a key set twice", () => {
    expect(duplicateActiveKeys("A_KEY=1\n# A_KEY=2\nB_KEY=x\nA_KEY=3\n")).toEqual(["A_KEY (lines 1, 4)"]);
  });
});
