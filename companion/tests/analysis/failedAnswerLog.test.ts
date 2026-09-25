import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFailedAnswer, FAILED_ANSWER_MAX_CHARS } from "../../src/analysis/ai/failedAnswerLog.js";

async function tempCaseDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dfir-failedanswer-"));
}

describe("writeFailedAnswer (#1602)", () => {
  it("writes the error and the raw text into <caseDir>/logs", async () => {
    const dir = await tempCaseDir();
    const path = await writeFailedAnswer(dir, {
      kind: "synthesis",
      attempt: 1,
      error: "summary: Required",
      text: '{"findings":[]}',
    });
    expect(path.startsWith(join(dir, "logs", "ai-failed-synthesis-"))).toBe(true);
    expect(path.endsWith(".txt")).toBe(true);
    const body = await readFile(path, "utf8");
    expect(body).toContain("summary: Required");
    expect(body).toContain('{"findings":[]}');
  });

  it("caps the raw text and says how much was cut", async () => {
    const dir = await tempCaseDir();
    const text = "x".repeat(FAILED_ANSWER_MAX_CHARS + 500);
    const body = await readFile(
      await writeFailedAnswer(dir, { kind: "synthesis", attempt: 1, error: "e", text }),
      "utf8",
    );
    expect(body).toContain("[truncated 500 chars]");
    expect(body.length).toBeLessThan(FAILED_ANSWER_MAX_CHARS + 1000);
  });

  it("never overwrites: two saves at the same clock give two files", async () => {
    const dir = await tempCaseDir();
    const now = new Date("2026-09-24T20:26:00.000Z");
    const a = await writeFailedAnswer(dir, { kind: "synthesis", attempt: 1, error: "e", text: "a" }, now);
    const b = await writeFailedAnswer(dir, { kind: "synthesis", attempt: 1, error: "e", text: "b" }, now);
    expect(a).not.toBe(b);
    expect(await readdir(join(dir, "logs"))).toHaveLength(2);
  });

  it("keeps a hostile kind inside the logs folder", async () => {
    const dir = await tempCaseDir();
    const path = await writeFailedAnswer(dir, { kind: "../../x/Y", attempt: 2, error: "e", text: "t" });
    expect(path.startsWith(join(dir, "logs") + "/") || path.startsWith(join(dir, "logs") + "\\")).toBe(true);
    expect(path).toMatch(/ai-failed-[a-z0-9-]+-/);
  });
});
