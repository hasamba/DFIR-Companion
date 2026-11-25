// Windows.Detection.Malfind — Velociraptor's YARA scan of private executable memory, one row per
// flagged region: `{Pid, Name, AddressRange, Protection, SectionSize, HexHeader, DataMagic,
// SectionData, YaraHit[], ProcessChain[], …}`.
//
// Left to the generic mapper the row was titled by the process name alone ("example.exe -") with no
// details, and every region of one process shared one event key, so distinct regions folded into one
// row with a count. It now reads like the memory-image malfind rows (memoryFields.ts): process, PID,
// region and protection lead; the YARA rule that fired, the first bytes, the region size and the
// process's command line follow in the details; malfindContext.ts states what the region does and
// does not show. The grade is unchanged (Medium, from the detection floor): the artifact flags every
// JIT / .NET / AV region too.
//
// Kept out of velociraptorImport.ts, which is frozen at the file-size ledger (#384).

import { addIoc, getCI, isObject, oneLine, str, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { malfindDescription } from "./memoryFields.js";
import { malfindContext } from "./malfindContext.js";
import { capWithHostSuffix } from "./velociraptorTitle.js";
import { pickTime } from "./veloRowTime.js";
import { boundedAggKey } from "./aggKey.js";

type Row = Record<string, unknown>;

const DESCRIPTION_CAP = 1200;

/** A Malfind region row: the artifact by name, or the region columns themselves. */
export function isVeloMalfindRow(row: Row, artifact = ""): boolean {
  const region = getCI(row, "Protection") != null && getCI(row, "AddressRange") != null;
  return (
    region && (/malfind/i.test(artifact) || getCI(row, "YaraHit") != null || getCI(row, "HexHeader") != null)
  );
}

function text(v: unknown): string {
  return oneLine(str(v).trim());
}

// "0a1b0000-0a1c0000" → "0x0a1b0000": the region's start, which is also its identity in the key.
function regionStart(row: Row): string {
  const start = text(getCI(row, "AddressRange")).split("-")[0]?.trim() ?? "";
  if (!start) return "";
  return /^0x/i.test(start) ? start.toLowerCase() : `0x${start.toLowerCase()}`;
}

// Velociraptor's letter form ("xrw", "xr") → the Windows constant malfindContext.ts reads. Any other
// spelling passes through unchanged.
function windowsProtection(p: string): string {
  if (!/^[rwx]{1,3}$/i.test(p)) return p;
  const has = (c: string): boolean => p.toLowerCase().includes(c);
  if (!has("x")) return p;
  return has("w") ? "PAGE_EXECUTE_READWRITE" : has("r") ? "PAGE_EXECUTE_READ" : "PAGE_EXECUTE";
}

// The process entry for this row: ProcessChain's last link is the process itself.
function processEntry(row: Row): Row {
  const chain = getCI(row, "ProcessChain");
  if (!Array.isArray(chain) || chain.length === 0) return {};
  const last: unknown = chain[chain.length - 1];
  return isObject(last) ? last : {};
}

// "YARA <rule>: <description>" for each hit, de-duplicated.
function yaraHits(row: Row): string[] {
  const hits = getCI(row, "YaraHit");
  if (!Array.isArray(hits)) return [];
  const out = new Set<string>();
  for (const h of hits) {
    if (!isObject(h)) continue;
    const rule = text(getCI(h, "Rule"));
    if (!rule) continue;
    const meta = getCI(h, "Meta");
    const desc = isObject(meta) ? text(getCI(meta, "description")) : "";
    out.add(`YARA ${rule}${desc ? `: ${desc}` : ""}`);
  }
  return [...out];
}

function detailParts(row: Row, proc: Row): string[] {
  const parts = yaraHits(row);
  const header = text(getCI(row, "HexHeader"));
  if (header) parts.push(`first bytes ${header}${/^4d\s*5a/i.test(header) ? " (MZ header)" : ""}`);
  const size = text(getCI(row, "SectionSize"));
  if (size) parts.push(`region size ${size} bytes`);
  const cmd = text(getCI(proc, "CommandLine"));
  if (cmd) parts.push(`CommandLine: ${cmd}`);
  return parts;
}

export function mapVeloMalfind(
  row: Row,
  artifact: string,
  host: string,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const proc = processEntry(row);
  const name = text(getCI(row, "Name")) || text(getCI(proc, "Name"));
  const pid = text(getCI(row, "Pid")) || text(getCI(proc, "Pid"));
  const protection = text(getCI(row, "Protection"));
  const start = regionStart(row);
  if (name) addIoc(sink, "process", name);

  // The region is printed AND keyed: two regions of one process share a timestamp (the process start),
  // so a key the description does not print would be undone by the case merge (memoryFields.ts).
  const title = malfindDescription(
    "Velociraptor",
    artifact ? `[${artifact}]` : "Malfind", // a bare export with no artifact name still says what it is
    name,
    pid,
    start ? ` at ${start}` : "",
    protection,
    "",
  );
  // The context helper reads its preview from a Hexdump column (the artifact names it HexHeader) and
  // knows RWX by its Windows / "rwx" spellings; Velociraptor orders the letters its own way ("xrw").
  const ctx = malfindContext({
    Protection: windowsProtection(protection),
    Hexdump: text(getCI(row, "HexHeader")),
  });
  const details = [...detailParts(row, proc), ctx.summary].filter(Boolean);
  const description = capWithHostSuffix(`${title} - ${details.join(" - ")}`, host, DESCRIPTION_CAP);

  return {
    timestamp: pickTime(row),
    description,
    severity: "Medium", // the detection floor's grade, as before — JIT/.NET/AV regions match too
    mitre: ["T1055"],
    aggKey: boundedAggKey(`vr|malfind|${host.toLowerCase()}|${pid}|${start}|${protection.toLowerCase()}`),
    sources: ["Velociraptor"],
    message: ctx.note,
    ...(name ? { processName: name } : {}),
    ...(host ? { asset: host } : {}),
  };
}
