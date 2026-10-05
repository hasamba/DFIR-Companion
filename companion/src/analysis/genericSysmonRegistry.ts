// A generic "something wrote the registry" alert is not a detection (#1958).
//
// Hayabusa and Velociraptor's Windows.Sigma.Base pack both ship "Reg Key Value Set (Sysmon Alert)"
// and "Reg Key Create/Delete (Sysmon Alert)". The rules fire on EVERY Sysmon registry event the
// Sysmon configuration tags, at level medium, and both importers copy that level as the grade. One
// case held 5,097 of these rows at Medium — CompatTelRunner's application inventory, svchost,
// services, OneDrive — and they used up the AI's event budget.
//
// This is the registry twin of #1530 (firstPartyEgress.ts), and it runs in the same place: at the
// import seam, BEFORE the dual-write and BEFORE the content tagger. The order matters. The tagger is
// raise-only, and its Run-key rule grades Medium — the grade the generic rule already gave — so
// after the tagger a Run-key row and a CompatTelRunner row look the same. Lowering first, then one
// chance to raise, then demote: the order ARCHITECTURE.md documents.
//
// ─────────────────────────────── WHY THIS IS SAFE TO LOWER ───────────────────────────────
//
// The tagger alone is not the escape hatch: auto-tagging can be off, and its registry coverage is
// the Run keys only. So the pass carries its own KEEP-LIST of the keys an intruder writes to persist
// or to blind the host — Run keys, IFEO, Winlogon, LSA, Defender policy, service ImagePath — and a
// row on one of them is never lowered, whatever the tagger does.
//
// The other bounds keep the blast radius at the generic verdict this exists to quiet:
//   • The generic title must OPEN the description. A specific rule ("Autorun Keys Modification",
//     a Defender-tamper rule) on the same key keeps its grade.
//   • ≤ Medium only. A High or Critical keeps its grade.
//   • No ATT&CK technique beyond T1112 (the generic rule's own tag on Windows.Sigma.Base).
//   • Not analyst-promoted, no `origin`, not a manual event, and one parser only: a row two tools
//     merged may carry the other tool's specific verdict behind this description.
//   • The registry key must be readable in FULL. No key, or a key the importer cut, keeps the grade.
//
// And the row is not deleted. Info means the super-timeline keeps it and the analyst can search it.
//
// PURE — no I/O, returns new events, never mutates its input.

// The stated reason lives in the retention registry for the layering reason firstPartyEgress.ts
// gives: the store that enforces the super-timeline cap may not import upward into this layer.
import { GENERIC_SYSMON_REGISTRY_MARKER } from "./setAsideRows.js";
import { isManualId } from "./manualId.js";
import type { ForensicEvent } from "./stateTypes.js";

/** The generic rule titles, anchored at the start of the description each importer writes. */
const GENERIC_TITLE =
  /^(?:Hayabusa: |Velociraptor(?: \[[^\]]*\])? Sigma: )Reg Key (?:Value Set|Create\/Delete) \(Sysmon Alert\)/;

/** Severities this pass may lower. */
const LOWERABLE = new Set(["Low", "Medium"]);

/** The one technique the generic rule names itself ("Modify Registry"). */
const GENERIC_TECHNIQUE = "T1112";

/** Hayabusa cuts each detail value at 120 characters, and the Sigma salient render at 140. */
const DESCRIPTION_VALUE_CAP = 120;

/** The longest description this pass leaves behind. The NOTE is never what the clip removes. */
const DESCRIPTION_MAX = 1200;

const UNKNOWN_SOURCE = "unknown source";

/** The Windows services whose Start value turns off a defence (the list tradecraftRules.ts uses). */
const DEFENCE_SERVICES = "windefend|wdnissvc|wdfilter|wdboot|sense|securityhealthservice|wscsvc|mpssvc";

/**
 * Keys an intruder writes to persist or to blind the host. Matched case-insensitively anywhere in
 * the key, so HKLM\…, HKU\…, \REGISTRY\MACHINE\… and Wow6432Node spellings all match. A word
 * boundary (not `$`) ends each value name, so a trailing render artefact cannot slip past.
 */
const KEEP_KEYS: readonly RegExp[] = [
  /\\currentversion\\(?:policies\\explorer\\)?run/i, // Run, RunOnce, RunOnceEx, RunServices
  /\\explorer\\startupapproved\\run/i,
  /\\image file execution options\b/i,
  /\\silentprocessexit\b/i,
  /\\winlogon\b/i, // Shell, Userinit, Notify
  /\bappinit_dlls\b/i,
  /\\appcertdlls\b/i,
  /\\control\\session manager\\bootexecute\b/i,
  /\\control\\lsa\b/i,
  /\\windows defender\b/i, // policies and exclusions
  /\\windows advanced threat protection\b/i,
  /\\services\\[^\\]+\\(?:parameters\\)?(?:imagepath|servicedll|failurecommand)\b/i,
  new RegExp(String.raw`\\services\\(?:${DEFENCE_SERVICES})\\start\b`, "i"),
  /\\terminal server\b/i,
  /\\environment\\userinitmprlogonscript\b/i,
  /\\microsoft\\office\\.*\\addins\b/i,
  /\\office test\\/i,
  /\\classes\\(?:wow6432node\\)?clsid\\[^\\]+\\(?:inprocserver32|localserver32)\b/i,
];

/** True when the key is one this pass never lowers. */
export function isKeptRegistryKey(key: string): boolean {
  const k = key.replace(/\//g, "\\");
  return KEEP_KEYS.some((re) => re.test(k));
}

/** Where a key token starts: `TargetObject: `, `TargetObject=`, `TgtObj=`, `TgtObj: `. */
const KEY_TOKEN = /(?:^|[\s¦])(?:TargetObject|TgtObj)(?:=|:[ \t]*)/;

/** What ends a key token: a line break, the next field, or the host suffix. */
const KEY_END = /\r|\n| ¦ | @ | (?:- )?[A-Za-z][A-Za-z0-9_]*(?:=|: )/;

/** The key token in `text`, and whether the text ran out before the token ended. */
function keyToken(text: string): { value: string; ended: boolean } | null {
  const start = KEY_TOKEN.exec(text);
  if (!start) return null;
  const rest = text.slice(start.index + start[0].length);
  const end = KEY_END.exec(rest);
  return { value: (end ? rest.slice(0, end.index) : rest).trim(), ended: !!end };
}

const isCut = (key: string): boolean => key.includes("…");

/**
 * The registry key this row names, in full, or "" when it names none or the importer cut it. The
 * canonical block holds the event's own TargetObject; the message is the full untruncated text;
 * the description is the last resort, and a value at its render cap, or one the description ends
 * inside, counts as cut.
 */
export function readRegistryKey(event: ForensicEvent): string {
  const canonical = (event.canonical?.registry?.key ?? "").trim();
  if (canonical) return isCut(canonical) ? "" : canonical;
  const fromMessage = keyToken(event.message ?? "");
  if (fromMessage?.value) return isCut(fromMessage.value) ? "" : fromMessage.value;
  const fromDescription = keyToken(event.description ?? "");
  if (!fromDescription?.value || !fromDescription.ended) return "";
  const value = fromDescription.value;
  return isCut(value) || value.length >= DESCRIPTION_VALUE_CAP ? "" : value;
}

function singleSource(event: ForensicEvent): boolean {
  const real = new Set((event.sources ?? []).filter((s) => s && s !== UNKNOWN_SOURCE));
  return real.size <= 1;
}

/** Why a row reads Info, written into the row itself so the record explains its own grade. */
export function genericSysmonRegistryNote(event: ForensicEvent): string {
  if (!event || event.promotedAt || event.origin || isManualId(event.id)) return "";
  if (!LOWERABLE.has(event.severity)) return "";
  if (!GENERIC_TITLE.test(event.description ?? "")) return "";
  if ((event.mitreTechniques ?? []).some((t) => t.toUpperCase() !== GENERIC_TECHNIQUE)) return "";
  if (!singleSource(event)) return "";
  const key = readRegistryKey(event);
  if (!key || isKeptRegistryKey(key)) return "";
  return `${GENERIC_SYSMON_REGISTRY_MARKER} no specific rule matched this registry write]`;
}

export interface GenericSysmonRegistryResult {
  events: ForensicEvent[];
  /** Ids this pass lowered, for the import log line. */
  downgraded: string[];
}

/**
 * Lower every qualifying row to Info, with its reason appended. Returns new objects; the input
 * array and its events are untouched. Idempotent: a row already carrying the note is left alone.
 */
export function downgradeGenericSysmonRegistry(
  events: readonly ForensicEvent[],
): GenericSysmonRegistryResult {
  const downgraded: string[] = [];
  const out = events.map((e) => {
    const note = genericSysmonRegistryNote(e);
    if (!note || e.description.includes(note)) return e;
    downgraded.push(e.id);
    // Clip the BASE, never the note (#1535): the cap must still tell this row from bulk telemetry.
    const base = e.description.slice(0, Math.max(0, DESCRIPTION_MAX - note.length)).trimEnd();
    return { ...e, severity: "Info" as const, description: `${base}${note}` };
  });
  return { events: downgraded.length ? out : [...events], downgraded };
}
