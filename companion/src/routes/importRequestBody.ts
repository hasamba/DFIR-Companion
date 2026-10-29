// Reading the body of POST /cases/:id/import — the unified import the dashboard's Import button and
// the extension's "Push to DFIR-Companion" both post to.
//
// `sourceUrl` (#2258) is the page an extension push came from. It is provenance for the import audit
// log (metadata/imports.jsonl) ONLY: it never enters the evidence text, the forensic timeline or
// anything the AI reads. Because the page is adversary-reachable, it is validated strictly — a plain
// http(s) URL of bounded length, or the whole import is refused before any evidence is written.

export const MAX_SOURCE_URL_LENGTH = 2048;

type ImportBody = { text?: unknown; json?: unknown; csv?: unknown } | null | undefined;

/** The raw evidence text: `text`, else `json`, else `csv`; "" when none is a string. */
export function importBodyText(body: ImportBody): string {
  if (typeof body?.text === "string") return body.text;
  if (typeof body?.json === "string") return body.json;
  if (typeof body?.csv === "string") return body.csv;
  return "";
}

function sourceUrlError(raw: unknown): string | undefined {
  if (raw === undefined || raw === null || raw === "") return undefined;
  if (typeof raw !== "string") return "sourceUrl must be a string";
  if (raw.length > MAX_SOURCE_URL_LENGTH) return `sourceUrl exceeds ${MAX_SOURCE_URL_LENGTH} characters`;
  let protocol: string;
  try {
    protocol = new URL(raw).protocol;
  } catch {
    return "sourceUrl must be a valid URL";
  }
  return protocol === "http:" || protocol === "https:" ? undefined : "sourceUrl must be an http(s) URL";
}

/** The 400 message for an unusable /import body, or undefined when it may proceed. */
export function importBodyError(text: string, rawSourceUrl: unknown): string | undefined {
  return text.trim() ? sourceUrlError(rawSourceUrl) : "text is required";
}

/** `metadata` plus the validated sourceUrl, when one was sent. Call after importBodyError passed. */
export function withSourceUrl<T extends object>(
  rawSourceUrl: unknown,
  metadata: T,
): T & { sourceUrl?: string } {
  return typeof rawSourceUrl === "string" && rawSourceUrl && !sourceUrlError(rawSourceUrl)
    ? { ...metadata, sourceUrl: rawSourceUrl }
    : metadata;
}
