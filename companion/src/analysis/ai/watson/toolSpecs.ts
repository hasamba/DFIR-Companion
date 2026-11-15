import type { ToolSpec } from "../../../providers/toolCalling.js";
import { WATSON_LOOKUP_LIMITS as L } from "./lookupSchema.js";
import { MAX_SEARCH_TERMS, MAX_TERM_CHARS } from "./replySchema.js";

// Watson's four read-only tools (phase 5). The parameter schemas mirror the hop's lookup object
// (lookupSchema.ts) and its 'search' field, with the same limits. Every schema is closed, and none
// takes a 'source': the tool name picks the source, so a forensic lookup can never read raw rows.
// The schemas guide the model only. The dispatcher checks every argument itself (toolDispatch.ts),
// because some adapters strip schema keywords a provider does not accept.

export const WATSON_TOOL = {
  forensic: "forensic_lookup",
  super: "supertimeline_search",
  paste: "paste_search",
  history: "history_search",
} as const;

export type WatsonToolName = (typeof WATSON_TOOL)[keyof typeof WATSON_TOOL];

const str = (description: string, maxLength: number, minLength = 1) => ({
  type: "string",
  description,
  minLength,
  maxLength,
});
const ids = (description: string, maxItems: number) => ({
  type: "array",
  description,
  items: str("One id.", L.idChars),
  maxItems,
});
const stamp = (description: string) => ({ type: "string", description });

const windowProps = {
  from: stamp("Start of a time window, ISO 8601. Give 'to' also. The window is 7 days or less."),
  to: stamp("End of the time window, ISO 8601."),
};

const terms = {
  type: "array",
  description: "Words to find. A line matches when it contains one of them. Case is not important.",
  items: str("One term.", MAX_TERM_CHARS),
  minItems: 1,
  maxItems: MAX_SEARCH_TERMS,
};

const closed = (properties: Record<string, unknown>, required: string[] = []) => ({
  type: "object",
  properties,
  ...(required.length ? { required } : {}),
  additionalProperties: false,
});

const FORENSIC: ToolSpec = {
  name: WATSON_TOOL.forensic,
  description:
    "Find events in the forensic timeline. Give finding ids, event ids, a time window, a host or text. Only in-scope events come back.",
  parameters: closed({
    findingIds: ids("Findings whose cited events you want.", L.findingIds),
    eventIds: ids("Events you want by id.", L.eventIds),
    ...windowProps,
    host: str("Events on this host.", L.chars),
    text: str("Events that contain this text.", L.chars),
  }),
};

const SUPER: ToolSpec = {
  name: WATSON_TOOL.super,
  description:
    "Search the raw super-timeline for rows that are not in the forensic timeline. Give text, a hash, a host or a time window. Use it only when the forensic timeline does not answer.",
  parameters: closed({
    text: str(
      `Rows that contain this text. Use ${L.superTextMin} or more characters.`,
      L.chars,
      L.superTextMin,
    ),
    hash: str("An MD5, SHA-1 or SHA-256 hash in hex.", 64, 32),
    host: str("Rows on this host. Use its hostname or IP address.", L.chars),
    ...windowProps,
  }),
};

const PASTE: ToolSpec = {
  name: WATSON_TOOL.paste,
  description: "Find lines in a stored paste. Use a paste id from STORED PASTES.",
  parameters: closed({ pasteId: str("The paste id.", L.idChars), terms }, ["pasteId", "terms"]),
};

const HISTORY: ToolSpec = {
  name: WATSON_TOOL.history,
  description: "Find lines in the full chat history. Use it for turns older than RECENT CHAT.",
  parameters: closed({ terms }, ["terms"]),
};

/** The tools a round offers. `super` is false in a reaction round; `history` when there is none. */
export function watsonTools(o: { super: boolean; history: boolean }): ToolSpec[] {
  return [FORENSIC, ...(o.super ? [SUPER] : []), PASTE, ...(o.history ? [HISTORY] : [])];
}

const ALL: readonly ToolSpec[] = [FORENSIC, SUPER, PASTE, HISTORY];

/** The first argument key the tool's schema does not name, or null when every key is known. */
export function unknownKey(name: WatsonToolName, input: Record<string, unknown>): string | null {
  const spec = ALL.find((t) => t.name === name);
  const known = Object.keys((spec?.parameters.properties as object | undefined) ?? {});
  return Object.keys(input).find((k) => !known.includes(k)) ?? null;
}

/** True for one of Watson's four tool names. */
export const isWatsonTool = (name: string): name is WatsonToolName => ALL.some((t) => t.name === name);
