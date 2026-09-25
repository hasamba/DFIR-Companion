import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Keep a model answer that failed parsing or validation (#1602), so an analyst can see WHY a
 * synthesis gave up. Before this, nothing in the case folder or the log showed what the model
 * returned.
 *
 * The file goes in `<caseDir>/logs`, next to the case session log. It is never overwritten: four
 * fast retries, or two runs at once, can share a millisecond, so the name carries the attempt and a
 * random suffix and the write refuses an existing file.
 */

/** Characters of answer text kept per file. A 40k-token synthesis answer is ~160k characters. */
export const FAILED_ANSWER_MAX_CHARS = 1_000_000;

export interface FailedAnswer {
  kind: string; // the AI call label, e.g. "synthesis"
  attempt: number; // 1-based
  error: string;
  text: string;
}

function safeKind(kind: string): string {
  return (
    kind
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "ai"
  );
}

function capped(text: string): string {
  if (text.length <= FAILED_ANSWER_MAX_CHARS) return text;
  const cut = text.length - FAILED_ANSWER_MAX_CHARS;
  return `${text.slice(0, FAILED_ANSWER_MAX_CHARS)}\n[truncated ${cut} chars]\n`;
}

/** Write one failed answer and return its path. Throws on a write error — the caller decides. */
export async function writeFailedAnswer(caseDir: string, a: FailedAnswer, now = new Date()): Promise<string> {
  const dir = join(caseDir, "logs");
  await mkdir(dir, { recursive: true });
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const name = `ai-failed-${safeKind(a.kind)}-${stamp}-a${a.attempt}-${randomBytes(4).toString("hex")}.txt`;
  const path = join(dir, name);
  const body =
    `# AI answer that failed (${a.kind}, attempt ${a.attempt}, ${now.toISOString()})\n` +
    `# Error: ${a.error}\n\n${capped(a.text)}`;
  await writeFile(path, body, { encoding: "utf8", flag: "wx" });
  return path;
}
