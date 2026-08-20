// Deterministic importer for Windows Event Log exported as XML — the format produced by
// Event Viewer's "Save All Events As… / Save Selected Events…" (XML), `wevtutil qe <log> /f:xml`,
// and PowerShell `Get-WinEvent … | %{ $_.ToXml() }`. It is the same per-event content as the
// EVTX/SIEM JSON paths, just wrapped in the `<Events><Event>…</Event></Events>` schema, so this
// module does NOT re-map anything: it parses the regular XML envelope into the SAME record shape
// the SIEM importer's `mapWindows` already consumes ({ EventID, Channel, Computer, @timestamp,
// EventData: { Name→value } }) and hands it to the shared `buildSiemResult` — reusing the per-EID
// Windows/Sysmon mapping, severity derivation, IOC/asset extraction, aggregation and caps.
//
// The parser is dependency-free (no XML library — mirrors the hand-rolled MIME email importer):
// the Windows event XML is highly regular, so a focused scan over `<Event>` blocks is robust and
// avoids pulling an XML parser into the Node runtime / bundler graph. Pure.

import { buildSiemResult, type SiemImportOptions, type SiemParseResult } from "./siemImport.js";
import { buildSiemResultProgress, throwIfImportAborted } from "./siemBuildProgress.js";

type Row = Record<string, unknown>;

// Decode the five predefined XML entities + numeric character references. Event data (command
// lines, registry paths, messages) routinely carries escaped `&amp; &lt; &gt; &quot; &#xNN;`.
export function decodeXmlEntities(s: string): string {
  return s.replace(/&(#x?[0-9a-fA-F]+|amp|lt|gt|quot|apos);/g, (m, ent: string) => {
    switch (ent) {
      case "amp":
        return "&";
      case "lt":
        return "<";
      case "gt":
        return ">";
      case "quot":
        return '"';
      case "apos":
        return "'";
      default: {
        const code =
          ent[1] === "x" || ent[1] === "X" ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
        return Number.isFinite(code) && code > 0 ? String.fromCodePoint(code) : m;
      }
    }
  });
}

// Heuristic: does this text look like a Windows Event Log XML export? Matches the events schema
// namespace, or an `<Event>` element carrying the canonical `<System>` + `<EventID>` block. Cheap
// (scans a leading slice) so it can gate detection ahead of the JSON/CSV/log sniffs.
export function looksLikeWinEventXml(text: string): boolean {
  const t = text.trimStart();
  if (t[0] !== "<") return false;
  const head = t.slice(0, 4000);
  if (/schemas\.microsoft\.com\/win\/2004\/08\/events\/event/i.test(head)) return true;
  // No namespace (some tools strip it): require an <Event> with a <System><EventID> inside.
  return /<Event\b/i.test(head) && /<System\b/i.test(head) && /<EventID\b/i.test(head);
}

// The elText/attr patterns are memoized: parseEventBlock calls them ~8 times per event over a
// CLOSED set of tag/attribute names, and constructing the RegExp per call doubled per-event field
// extraction across million-event exports. i-flagged without g, so a cached instance carries no
// lastIndex state between calls.
const EL_TEXT_RES = new Map<string, RegExp>();
const ATTR_RES = new Map<string, RegExp>();

// Pull the text content of a simple leaf element `<Tag …>value</Tag>` (first occurrence).
function elText(block: string, tag: string): string {
  let re = EL_TEXT_RES.get(tag);
  if (!re) {
    re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, "i");
    EL_TEXT_RES.set(tag, re);
  }
  const m = re.exec(block);
  return m ? decodeXmlEntities(m[1]).trim() : "";
}
// Pull an attribute value `attr="value"` from the (first) opening tag of `element`.
function attr(block: string, element: string, attrName: string): string {
  const key = `${element}|${attrName}`;
  let re = ATTR_RES.get(key);
  if (!re) {
    re = new RegExp(`<${element}\\b[^>]*\\b${attrName}="([^"]*)"`, "i");
    ATTR_RES.set(key, re);
  }
  const m = re.exec(block);
  return m ? decodeXmlEntities(m[1]).trim() : "";
}

const SYSTEM_RE = /<System\b[^>]*>([\s\S]*?)<\/System>/i;
const DATA_RE = /<Data\b([^>]*)>([\s\S]*?)<\/Data>|<Data\b([^>]*)\/>/gi;
const NAME_ATTR_RE = /\bName="([^"]*)"/i;
// Generic leaf element (used to flatten <UserData> children and <RenderingInfo>).
const LEAF_RE = /<([A-Za-z0-9_:.\-]+)\b[^>]*>([^<]*)<\/\1>/g;

// Parse the `<EventData>` / `<UserData>` payload into a flat { Name → value } object. Modern
// exports use `<Data Name="X">v</Data>`; some events render positional `<Data>v</Data>` (captured
// as Data1, Data2…) or a `<UserData>` block of arbitrary leaf elements (captured by tag name).
function parseEventData(eventBlock: string): Row {
  const out: Row = {};

  const edMatch = /<EventData\b[^>]*>([\s\S]*?)<\/EventData>/i.exec(eventBlock);
  if (edMatch) {
    let positional = 0;
    DATA_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DATA_RE.exec(edMatch[1])) !== null) {
      const openAttrs = m[1] ?? m[3] ?? "";
      const raw = m[2] ?? "";
      const nameM = NAME_ATTR_RE.exec(openAttrs);
      const value = decodeXmlEntities(raw).trim();
      if (nameM) out[decodeXmlEntities(nameM[1]).trim()] = value;
      else out[`Data${++positional}`] = value;
    }
  }

  const udMatch = /<UserData\b[^>]*>([\s\S]*?)<\/UserData>/i.exec(eventBlock);
  if (udMatch) {
    LEAF_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = LEAF_RE.exec(udMatch[1])) !== null) {
      const tag = m[1];
      if (/^(UserData|EventXML|RuleAndFileData)$/i.test(tag)) continue; // skip wrapper containers
      const value = decodeXmlEntities(m[2]).trim();
      if (value && out[tag] === undefined) out[tag] = value;
    }
  }

  return out;
}

function parseEventBlock(block: string): Row | undefined {
  const sys = SYSTEM_RE.exec(block)?.[1] ?? "";
  const eid = elText(sys, "EventID");
  if (!eid) return undefined;

  const provider = attr(sys, "Provider", "Name");
  const rec: Row = {
    EventID: eid,
    Channel: elText(sys, "Channel") || provider,
    Provider: provider,
    Computer: elText(sys, "Computer"),
    Level: elText(sys, "Level"),
    EventRecordID: elText(sys, "EventRecordID"),
    "@timestamp": attr(sys, "TimeCreated", "SystemTime"),
    EventData: parseEventData(block),
  };
  const userId = attr(sys, "Security", "UserID");
  if (userId) rec.SecurityUserID = userId;
  return rec;
}

// Parse a Windows Event Log XML document into records shaped for the SIEM importer's mapWindows
// (EventID / Channel / Computer / @timestamp / EventData). Tolerant of missing fields and the
// optional `<?xml?>` declaration; skips a block that has no EventID.
export function parseWinEventXml(text: string): Row[] {
  const records: Row[] = [];
  const eventRe = /<Event\b[^>]*>([\s\S]*?)<\/Event>/gi;
  let m: RegExpExecArray | null;
  while ((m = eventRe.exec(text)) !== null) {
    const record = parseEventBlock(m[1]);
    if (record) records.push(record);
  }
  return records;
}

export async function parseWinEventXmlProgress(
  text: string,
  onProgress?: (done: number, total: number) => void | Promise<void>,
  signal?: AbortSignal,
): Promise<Row[]> {
  throwIfImportAborted(signal);
  // Counting exec loop, not text.match(): match() would materialize a throwaway array with one
  // string per event across a multi-hundred-MB export just to take its length.
  let total = 0;
  const countRe = /<Event\b/gi;
  while (countRe.exec(text) !== null) total++;
  if (total === 0) {
    await onProgress?.(0, 0);
    return [];
  }
  const records: Row[] = [];
  const eventRe = /<Event\b[^>]*>([\s\S]*?)<\/Event>/gi;
  const yieldChunkSize = 250;
  const progressChunkSize = 5000;
  let scanned = 0;
  let m: RegExpExecArray | null;
  while ((m = eventRe.exec(text)) !== null) {
    throwIfImportAborted(signal);
    scanned++;
    const record = parseEventBlock(m[1]);
    if (record) records.push(record);
    if (scanned % progressChunkSize === 0) {
      await onProgress?.(scanned, total);
    }
    if (scanned % yieldChunkSize === 0) {
      await new Promise<void>((resolve) => setImmediate(resolve));
      throwIfImportAborted(signal);
    }
  }
  if (scanned % progressChunkSize !== 0) await onProgress?.(scanned, total);
  throwIfImportAborted(signal);
  return records;
}

// Parse a Windows Event Log XML export into a SIEM result (identical shape to parseSiemExport).
export function parseEvtxXml(text: string, opts: SiemImportOptions = {}): SiemParseResult {
  const records = parseWinEventXml(text);
  return buildSiemResult(records, "winevent-xml", opts, text);
}

export async function parseEvtxXmlProgress(
  text: string,
  opts: SiemImportOptions = {},
  onParseProgress?: (done: number, total: number) => void | Promise<void>,
  onProcessProgress?: (done: number, total: number) => void | Promise<void>,
  signal?: AbortSignal,
): Promise<SiemParseResult> {
  const records = await parseWinEventXmlProgress(text, onParseProgress, signal);
  return buildSiemResultProgress(records, "winevent-xml", opts, text, onProcessProgress, signal);
}
