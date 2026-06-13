// Normalize a POST /cases/:id/push body into the text blob the importer detects + routes (#84). The
// endpoint is deliberately liberal in what it accepts so any external tool can hit it without bespoke
// glue — the SAME importDetect.ts that powers the file-upload Import button then figures out the kind.
//
// Accepted shapes (most-specific → most-generic):
//   { source, events:[...] }            → import the events array, label it `source`
//   { source, rows:[...] | records:[...] | data:[...] | results:[...] }  → same, alternate keys
//   { text|json|csv: "<string>" }        → import the raw string (mirrors the /import route)
//   "<raw string>"                       → import as-is (text/plain bodies)
//   <any other JSON>                     → import the whole body verbatim (an artifact-map, a single
//                                          SIEM alert object, a Hayabusa JSON line, …)
//
// Pure + I/O-free → unit-tested directly. The returned `filename` carries a hint importDetect uses
// (e.g. a Velociraptor-looking name routes ambiguous rows to the Velociraptor importer).

export interface PushPayload {
  text: string;        // the blob handed to detectImportKind + the importer
  source: string;      // caller-supplied label (sanitized) — drives the evidence filename
  filename: string;    // synthetic name for detection hints + the stored evidence file
}

const EVENT_ARRAY_KEYS = ["events", "rows", "records", "data", "results"] as const;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Keep a caller label safe for a filename + log line: printable, no path separators, capped.
function sanitizeSource(raw: unknown): string {
  const s = String(raw ?? "").replace(/[\r\n\t]+/g, " ").replace(/[^\w.\- ]+/g, "").trim().slice(0, 60);
  return s || "push";
}

export function extractPushPayload(body: unknown): PushPayload {
  // Raw string body (Content-Type: text/plain, or a JSON string literal).
  if (typeof body === "string") {
    return { text: body, source: "push", filename: "push.dat" };
  }

  if (isPlainObject(body)) {
    const source = sanitizeSource((body as Record<string, unknown>).source);
    const explicitName = typeof body.filename === "string" ? body.filename : "";

    // { source, events:[...] } and its aliases → serialize just the array.
    for (const key of EVENT_ARRAY_KEYS) {
      const arr = body[key];
      if (Array.isArray(arr)) {
        const filename = explicitName || defaultName(source);
        return { text: JSON.stringify(arr), source, filename };
      }
    }

    // { text|json|csv: "<string>" } — same fields the /import route accepts.
    const str =
      typeof body.text === "string" ? body.text
      : typeof body.json === "string" ? body.json
      : typeof body.csv === "string" ? body.csv
      : "";
    if (str) {
      const filename = explicitName || defaultName(source, body.csv ? "csv" : "dat");
      return { text: str, source, filename };
    }

    // Any other JSON object → push it whole (e.g. a Velociraptor artifact-map or a single alert).
    return { text: JSON.stringify(body), source, filename: explicitName || defaultName(source) };
  }

  // Arrays / primitives → stringify verbatim.
  return { text: JSON.stringify(body ?? null), source: "push", filename: "push.json" };
}

function defaultName(source: string, ext = "json"): string {
  const safe = source.replace(/[^\w.\-]+/g, "_") || "push";
  return `push_${safe}.${ext}`;
}
