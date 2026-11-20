import { readFile } from "node:fs/promises";
import type { CaseMeta } from "../types.js";
import { getServerLogger } from "../logging/serverLogger.js";

// Reading one case.json for the case list (#2768). A folder with no case.json is not a case and
// stays silent. A case.json that exists but cannot be read or parsed (truncated, empty, not a
// JSON object) used to be skipped silently too, so a real case vanished from the list with no
// trace. It is still skipped — every listCases consumer expects only valid CaseMeta — but the
// server log now names the damaged file. listCases runs on every dashboard poll, so each damaged
// file is reported once until it reads cleanly again.

const reported = new Set<string>();

export const CASE_JSON_UNREADABLE_MESSAGE = "case.json is damaged or unreadable";

/** True for the error getCaseMeta throws when case.json exists but is not valid JSON. */
export function isCaseJsonParseError(err: unknown): boolean {
  return err instanceof SyntaxError;
}

function isCaseMetaObject(value: unknown): value is CaseMeta {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One case's metadata for the case list, or null when the folder is not a listable case. */
export async function readListedCaseMeta(path: string, caseId: string): Promise<CaseMeta | null> {
  let reason: string;
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (isCaseMetaObject(parsed)) {
      reported.delete(path);
      return parsed;
    }
    reason = "not a JSON object";
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    reason = err instanceof Error ? err.message : String(err);
  }
  if (!reported.has(path)) {
    reported.add(path);
    getServerLogger().warn(
      `case "${caseId}": ${CASE_JSON_UNREADABLE_MESSAGE} (${reason}) — hidden from the case list until it is repaired: ${path}`,
    );
  }
  return null;
}
