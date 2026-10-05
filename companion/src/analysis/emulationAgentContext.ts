import type { ForensicEvent } from "./stateTypes.js";

/**
 * Adversary-emulation framework agent context (#1957).
 *
 * A MITRE Caldera sandcat agent leaves a clear shape: the binary itself (often renamed), its launch
 * arguments (`-server <url> -group <name>`), and a stager that fetches it from `/file/download` with
 * a platform/file header. The bundled tag rule `emulation_framework_agent` (data/tags.yaml) marks
 * those rows at import, but synthesis never reads the tags store — so this pure module scans the
 * forensic-timeline rows IN SYNTHESIS SCOPE and states the fact as one computed block.
 *
 * A FACT, not a verdict: a real attacker can run Caldera too, so the block says "weigh", never
 * "conclude", and nothing here changes a severity. It reads file/process names and launch arguments
 * only — never description or message — so a comment that NAMES sandcat does not fire (#747).
 *
 * The patterns mirror data/tags.yaml; a drift test runs both over one fixture set.
 */

/** Mirrors the tagger's per-field scan cap (taggerRules.ts FIELD_SCAN_CAP). */
const SCAN_CAP = 16_384;
/** At most this many hosts are named; the rest are counted. */
export const EMULATION_AGENT_MAX_HOSTS = 5;
const HOST_NAME_CAP = 100;

export const EMULATION_AGENT_BLOCK_HEADER =
  "ADVERSARY-EMULATION FRAMEWORK CONTEXT (deterministic fact from file names and launch arguments — not a verdict):";

const SANDCAT_NAME = /(?:^|[\\/])sandcat(?:\.[^\\/]{1,40})?$/i;
const SERVER_GROUP_ARGS = /(?:^|[\s"'])-server [^\n]{1,200}\s-group [^\s]/;
const STAGER_URL_FIRST = /\/file\/download[^\n]{0,300}\b(?:platform|file)[\\"']{0,2}\s*[:=,]/i;
const STAGER_HEADER_FIRST = /\b(?:platform|file)[\\"']{0,2}\s*[:=,][^\n]{0,300}\/file\/download/i;

type Shape = "agent file/process name" | "agent launch arguments" | "agent stager download";

function capped(value: string | undefined): string {
  if (!value) return "";
  return value.length > SCAN_CAP ? value.slice(0, SCAN_CAP) : value;
}

function shapeOf(e: ForensicEvent): Shape | null {
  if (SANDCAT_NAME.test(capped(e.path)) || SANDCAT_NAME.test(capped(e.processName))) {
    return "agent file/process name";
  }
  const cmd = capped(e.commandLine);
  if (!cmd) return null;
  if (SERVER_GROUP_ARGS.test(cmd)) return "agent launch arguments";
  if (STAGER_URL_FIRST.test(cmd) || STAGER_HEADER_FIRST.test(cmd)) return "agent stager download";
  return null;
}

/** True when the row carries the Caldera sandcat shape in a name or launch-argument field. */
export function isEmulationAgentEvent(e: ForensicEvent): boolean {
  return shapeOf(e) !== null;
}

/** A host name is adversary-controlled text: one line, no control characters, bounded. */
function safeHost(raw: string | undefined): string {
  const printable = [...(raw ?? "")]
    .map((ch) => {
      const code = ch.charCodeAt(0);
      return code < 0x20 || code === 0x7f ? " " : ch;
    })
    .join("");
  const flat = printable.replace(/\s+/g, " ").trim();
  if (!flat) return "an unnamed host";
  return flat.length > HOST_NAME_CAP ? `${flat.slice(0, HOST_NAME_CAP)}…` : flat;
}

interface HostHit {
  rows: number;
  shapes: Set<Shape>;
}

function collectHits(scopedEvents: readonly ForensicEvent[]): Map<string, HostHit> {
  const hits = new Map<string, HostHit>();
  for (const e of scopedEvents) {
    const shape = shapeOf(e);
    if (!shape) continue;
    const host = safeHost(e.asset);
    const prev = hits.get(host);
    hits.set(host, {
      rows: (prev?.rows ?? 0) + 1,
      shapes: new Set([...(prev?.shapes ?? []), shape]),
    });
  }
  return hits;
}

/**
 * One block naming each host where a sandcat-shaped row sits in the scoped forensic timeline.
 * Returns "" when no row matches. The caller passes the synthesis-scoped forensic events only —
 * never the super-timeline (CLAUDE.md §7).
 */
export function buildEmulationAgentBlock(scopedEvents: readonly ForensicEvent[]): string {
  const hits = collectHits(scopedEvents);
  if (hits.size === 0) return "";
  const ranked = [...hits.entries()].sort((a, b) => b[1].rows - a[1].rows || a[0].localeCompare(b[0]));
  const shown = ranked.slice(0, EMULATION_AGENT_MAX_HOSTS);
  const lines = shown.map(
    ([host, hit]) =>
      `- An adversary-emulation agent (MITRE Caldera sandcat shape: ${[...hit.shapes].sort().join(", ")}) ` +
      `is present on ${host} (${hit.rows} ${hit.rows === 1 ? "row" : "rows"}).`,
  );
  const rest = ranked.length - shown.length;
  if (rest > 0) lines.push(`- …and ${rest} more ${rest === 1 ? "host" : "hosts"} with the same shape.`);
  return (
    `${EMULATION_AGENT_BLOCK_HEADER}\n${lines.join("\n")}\n` +
    "Weigh this when you judge exercise against real compromise. It is not proof of an exercise on " +
    "its own: a real attacker can also run Caldera. It does not lower the severity of any row."
  );
}
