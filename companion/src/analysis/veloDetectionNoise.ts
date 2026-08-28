// Two shapes where a detection fires on the DETECTION STACK rather than on the host.
//
// Both are the same mistake seen from different angles: a rule pack sweeping a machine finds its own
// reflection — the signatures it ships, the sample logs it was written against, the Windows modules
// it inspects — and reports them as if an attacker had put them there. Neither row is dropped. Both
// are demoted to Info, which is what velociraptorImport already does for a `.yms` hit: the row still
// accounts for itself in `total`, an analyst who goes looking can still find it, and it stops
// crowding out the findings that are about the host.
//
// EVERY PREDICATE HERE LOWERS A GRADE, so every one of them is a place an attacker would like to
// reach. That shapes the whole design: nothing demotes on a signal the attacker chooses (a filename,
// a pasted comment), the callers cap how far a demotion can reach, and where a cheap signal and a
// costly one disagree the costly one wins.

import { getCI, getPath, isObject, str } from "./siemImport.js";
import { tradecraftSignal } from "./tradecraftRules.js";

type Row = Record<string, unknown>;

// `.yms` is Velociraptor's own compiled-Sigma format. Nothing else on a Windows host carries it, so
// the extension alone identifies the file — an attacker who renamed a payload to `.yms` would be
// choosing an extension that exists nowhere but inside Velociraptor's unpacked tool directory.
const VELOCIRAPTOR_SIGNATURE_EXT = /\.yms$/i;

// These extensions are NOT self-identifying. `.yml` is the most common configuration format there
// is, and `.evtx` is a live Windows log; an attacker's `C:\Users\Public\payload.yml` ends the same
// way a Sigma rule does. So the extension only narrows the field — the path has to place the file
// inside detection tooling before anything is demoted.
const SHARED_CONTENT_EXT = /\.(?:ya?ml|evtx|etl)$/i;

// Where detection content actually lives, in the two forms a filesystem sweep reports it.
//
//   the directory   Velociraptor unpacks a signature tree into
//                   `\Program Files\Velociraptor\Tools\tmp*\signatures\sigma\…` for the duration of
//                   a hunt; Hayabusa, Chainsaw and Sigma trees have their own equivalents.
//   the ABSENCE of  …and Velociraptor deletes that tree when the hunt ends, so the MFT keeps the
//   a directory     entries with no resolvable parent and reports them as `<Err>\<Parent N-M need K>`.
//                   That placeholder is written by the MFT parser, not by anything on disk, so it
//                   cannot be forged by naming a file — and on a real collection it was where every
//                   single one of these rows landed.
const DETECTION_CONTENT_LOCATION =
  /<Err>|<Parent |\\Velociraptor\\Tools\\|\\signatures\\|\\sigma\\|\\rules\\|\\hayabusa\\|\\chainsaw\\|EVTX-ATTACK/i;

/**
 * A file whose CONTENT is detection logic or detection test data, matched by a rule pack that only
 * looked at the filename.
 *
 * On a real collection this covered 47 of the 48 High findings the MFT rule pack produced. The 48th
 * was a ransomware binary in ProgramData — which is the point: an analyst reading 48 High findings
 * does not see it, and reading one does.
 *
 * Scoped deliberately to the keyword-detection path in velociraptorImport. It is a statement about
 * what a FILENAME MATCH proves, not a claim that these extensions are harmless — a `.yml` carrying
 * an attacker's configuration is still ingested, still timelined, and still graded by everything
 * that reads content rather than names.
 */
export function isDetectionContentPath(value: string): boolean {
  const path = value.trim();
  if (VELOCIRAPTOR_SIGNATURE_EXT.test(path)) return true;
  return SHARED_CONTENT_EXT.test(path) && DETECTION_CONTENT_LOCATION.test(path);
}

// Windows compiles a cdxml module (NetSecurity, NetTCPIP, DnsClient, Defender, …) into PowerShell
// when it is imported, and logs the generated body to EID 4104 like any other script. The generated
// code is dense with the punctuation, dynamic invocation and alias forms that broad "suspicious
// PowerShell" rules key on — so importing a firewall module lights up the same rule a real obfuscated
// payload does.
//
// Every marker is structural: something a compiler or a signing tool emits, never a word an attacker
// picks. The signature block is the one that needs care — it is a COMMENT, so anybody can type it —
// which is why the closing marker is required too. A begin-marker on its own says only that somebody
// wrote seven words, and is not evidence of anything.
const GENERATED_MARKERS: RegExp[] = [
  /\$__cmdletization_/, // cdxml-generated cmdlet body
  /Microsoft\.PowerShell\.Cmdletization/i, // its supporting types
  /Microsoft\.PowerShell\.Core\\Set-StrictMode\s+-Off/i, // the cdxml preamble
  /\\chocolatey\\helpers\\[^\n]*\.psm1/i, // Chocolatey's own helper modules
  // A CLOSED Authenticode block. Still forgeable — which is why callers never let this reach a
  // High/Critical verdict — but a pasted opener alone no longer reaches the demotion at all.
  /#\s*SIG\s*#\s*Begin signature block[\s\S]*#\s*SIG\s*#\s*End signature block/i,
];

const SCRIPT_BLOCK_EID = 4104;
const EVENT_WRAPPERS = ["Event", "_Event"] as const;

// An EventID as Windows/Velociraptor variously writes it: a bare number, a numeric string, or an
// object with a `Value`.
function toEventId(value: unknown): number {
  if (typeof value === "number") return value;
  if (isObject(value)) return toEventId(getCI(value, "Value"));
  const n = Number(str(value).trim());
  return Number.isFinite(n) ? n : 0;
}

// The row's EID, from every shape this importer already accepts: flat (`EID`, Hayabusa), the native
// parsed-EVTX `System.EventID`, and the same under an `Event`/`_Event` wrapper.
function eventId(row: Row): number {
  const flat = toEventId(getCI(row, "EID") ?? getCI(row, "EventID"));
  if (flat) return flat;
  const native = toEventId(getPath(row, "System.EventID"));
  if (native) return native;
  for (const w of EVENT_WRAPPERS) {
    const id = toEventId(getPath(row, `${w}.System.EventID`));
    if (id) return id;
  }
  return 0;
}

// The compiled script text. Read from EventData first — scriptBlockFragments has already reassembled
// a multi-part block there, so a marker split across two fragments is still visible. The rendered
// message is the fallback for a row that carries no EventData at all.
function scriptText(row: Row): string {
  let ed = getCI(row, "EventData");
  for (const w of EVENT_WRAPPERS) {
    if (isObject(ed)) break;
    ed = getPath(row, `${w}.EventData`);
  }
  if (isObject(ed)) {
    const t = str(getCI(ed, "ScriptBlockText")).trim();
    if (t) return t;
  }
  return str(getCI(row, "Details") ?? getCI(row, "Message")).trim();
}

/**
 * Is this row a 4104 script block whose text is generated or signed module scaffolding?
 *
 * The tradecraft check is a filter, NOT the safety argument. It catches a payload that happens to
 * name something tradecraftRules knows; plenty of real tradecraft (`Invoke-Mimikatz -DumpCreds`, for
 * one) matches no rule there and passes straight through. Treating it as protection would be a
 * mistake — it narrows the input, nothing more.
 *
 * The safety argument lives at the call site, which refuses to apply this demotion to a High or
 * Critical verdict. That bounds the worst case to what it should be: a specific rule that named a
 * technique keeps its grade whatever the script is wrapped in, and only the broad
 * "this PowerShell looks odd" verdicts — the ones that fire on generated code in the first place —
 * are ever lowered.
 */
export function isGeneratedModuleScript(row: Row): boolean {
  if (eventId(row) !== SCRIPT_BLOCK_EID) return false;
  const text = scriptText(row);
  if (!text) return false;
  if (!GENERATED_MARKERS.some((re) => re.test(text))) return false;
  return tradecraftSignal("", text)?.weight !== "strong";
}
