import { appendFile, mkdir, open, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../../../storage/caseStore.js";
import { WATSON_PASTE_MAX_BYTES } from "./pasteSearch.js";
import { turnSchema } from "./turnSchema.js";
import type { WatsonTurn } from "./types.js";

// Watson remembers everything: state/watson-history.jsonl holds every turn the chat ever had, one
// JSON turn per line. Append-only: never rewritten, never trimmed (the chat file keeps only the
// newest WATSON_MAX_TURNS). WatsonChatStore.update() is the one writer. Watson reads it through a
// search hop (the reserved paste id below); the dashboard pages it back through the history route.

/** The reserved `search.pasteId` that points a search at the history instead of a stored paste. */
export const WATSON_HISTORY_ID = "history";

/** What the search hop shows for the history, in place of a file name. */
export const WATSON_HISTORY_NAME = "Watson chat history";

const flat = (s: string): string => s.replace(/\s+/g, " ").trim();

/** One turn on one line, the form the history search reads. Fields appear only when set. */
export function historyLine(t: WatsonTurn): string {
  const parts = [`[${t.id}] ${t.at} ${t.role}: ${flat(t.text)}`];
  if (t.answer) {
    parts.push(`answer: ${t.answer.status} ${flat(t.answer.answer)} → ${flat(t.answer.pointer)}`);
    if (t.answer.relatedEventIds.length > 0) parts.push(`cited: ${t.answer.relatedEventIds.join(", ")}`);
  }
  if (t.request?.kind === "query") parts.push(`asked for: ${t.request.language} query`);
  return parts.join(" | ");
}

/** The turns in a history file's text, in order. A malformed line is skipped; a repeated id is kept once. */
function parseTurns(raw: string): WatsonTurn[] {
  const seen = new Set<string>();
  const out: WatsonTurn[] = [];
  for (const row of raw.split("\n")) {
    if (!row.trim()) continue;
    let json: unknown;
    try {
      json = JSON.parse(row);
    } catch {
      continue;
    }
    const parsed = turnSchema.safeParse(json);
    if (!parsed.success || seen.has(parsed.data.id)) continue;
    seen.add(parsed.data.id);
    out.push(parsed.data);
  }
  return out;
}

const missing = (err: unknown): boolean => (err as NodeJS.ErrnoException).code === "ENOENT";

export class WatsonHistoryStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "watson-history.jsonl");
  }

  /** Whether the history file exists yet (the chat store seeds it on its first update when not). */
  async exists(caseId: string): Promise<boolean> {
    try {
      await stat(this.path(caseId));
      return true;
    } catch (err) {
      if (missing(err)) return false;
      throw err;
    }
  }

  /** Adds the turns at the end, one line each. A failed write throws, so the caller can fail its update. */
  async append(caseId: string, turns: readonly WatsonTurn[]): Promise<void> {
    if (turns.length === 0) return;
    await mkdir(this.cases.stateDir(caseId), { recursive: true });
    await appendFile(this.path(caseId), turns.map((t) => `${JSON.stringify(t)}\n`).join(""), "utf8");
  }

  private async readAll(caseId: string): Promise<WatsonTurn[]> {
    try {
      return parseTurns(await readFile(this.path(caseId), "utf8"));
    } catch (err) {
      if (missing(err)) return [];
      throw err;
    }
  }

  /** How many turns the history holds. */
  async count(caseId: string): Promise<number> {
    return (await this.readAll(caseId)).length;
  }

  /**
   * Up to `limit` turns, oldest first, ending just before turn `before` (the newest when omitted).
   * An unknown `before` pages nothing. `more` is true when older turns remain.
   */
  async page(
    caseId: string,
    opts: { before?: string; limit: number },
  ): Promise<{ turns: WatsonTurn[]; more: boolean }> {
    const all = await this.readAll(caseId);
    const end = opts.before === undefined ? all.length : all.findIndex((t) => t.id === opts.before);
    if (end < 0) return { turns: [], more: false };
    const start = Math.max(0, end - Math.max(1, Math.floor(opts.limit)));
    return { turns: all.slice(start, end), more: start > 0 };
  }

  /**
   * The history as searchable text, one turn per line. Reads at most WATSON_PASTE_MAX_BYTES: the
   * newest part when the file is larger (`truncated`), starting at a whole line.
   */
  async text(caseId: string): Promise<{ text: string; truncated: boolean }> {
    let size: number;
    try {
      size = (await stat(this.path(caseId))).size;
    } catch (err) {
      if (missing(err)) return { text: "", truncated: false };
      throw err;
    }
    const truncated = size > WATSON_PASTE_MAX_BYTES;
    let raw: string;
    if (truncated) {
      const file = await open(this.path(caseId), "r");
      try {
        const buf = Buffer.alloc(WATSON_PASTE_MAX_BYTES);
        await file.read(buf, 0, buf.length, size - buf.length);
        const cut = buf.toString("utf8");
        raw = cut.slice(cut.indexOf("\n") + 1); // the first line of the tail is usually partial
      } finally {
        await file.close();
      }
    } else {
      raw = await readFile(this.path(caseId), "utf8");
    }
    return { text: parseTurns(raw).map(historyLine).join("\n"), truncated };
  }
}
