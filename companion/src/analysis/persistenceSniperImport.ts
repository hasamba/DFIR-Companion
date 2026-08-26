// Windows.Forensics.PersistenceSniper wraps Matteo Malvica's PersistenceSniper PowerShell module —
// every row is one persistence mechanism the module found, with its own fixed column set (Technique
// / Classification / Path / Value / Access Gained / Note / Reference / Signature / IsLolbin / …).
// Without this mapper the row falls through to velociraptorImport.ts's generic key=value dump,
// which reads every column back verbatim — including a Signature struct that stringifies to
// "Status = , Subject = " when PowerShell found nothing to sign-check, and a Reference URL that
// adds noise, not signal. Kept as its own module (not inlined into velociraptorImport.ts) because
// that file is frozen at its current size by the file-size ledger (#384) — see check-file-size.mjs.
import { str, getCI, oneLine, addIoc, mitreFromText, worst, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { withHostSuffix } from "./velociraptorTitle.js";

type Row = Record<string, unknown>;

// Same staging-directory convention as data/tags.yaml's staging_temp_executable rule (world-writable
// / transient locations malware commonly drops into). Judged directly against the row's OWN Value/
// Path text — unlike the [lolbin]/[signature: …] markers this replaced elsewhere in this file, this
// isn't re-deriving a verdict the module already computed; the path IS the ground truth for "is this
// staged somewhere unusual", so there's nothing to spoof by shaping it — an attacker choosing to
// stage there is exactly the case this is meant to catch.
//
// Deliberately NOT built on the same strict quoted-or-clean extraction as the file IOC below: that
// extraction returns nothing at all once a Value carries trailing arguments (the common case for a
// Scheduled Task/service command line — "…MpCmdRun.exe -IdleTask …"), which silently blinded the
// staging check to exactly the values it most needs to see. This regex instead scans the WHOLE raw
// Value/Path text and anchors on a real executable extension immediately following the staging
// directory with no further subdirectory in between — the same "must sit directly in that folder"
// restriction as the file IOC's extension anchor (companion/src/analysis/velociraptorImport.ts's own
// history has two prior rounds of counterexamples for weaker anchors), which is what keeps a
// legitimately deep vendor path — Windows Defender's own
// "C:\ProgramData\Microsoft\Windows Defender\Platform\<ver>\MpCmdRun.exe" — from false-matching:
// there are backslashes between "ProgramData\" and the filename, so it can't match. A false MATCH
// here only nudges severity, not a displayed IOC value, so scanning the whole string (rather than
// only a leading, provably-single path) is an acceptable, much safer trade-off than it would be for
// the file IOC.
//
// The trailing boundary is an explicit end-of-path lookahead (end of string / quote / whitespace /
// comma) — NOT a bare `\b`. A plain word boundary is satisfied by ANY non-word character, including
// another literal dot, so it treats an extension prefix earlier in a multi-dot filename as if it
// were the real one: "C:\ProgramData\readme.hta.txt" is a .txt file, but `\.hta\b` still matches
// because a dot follows "hta" too. Requiring the boundary to actually look like the end of a path
// closes that off while leaving every real case (bare end of string, a closing quote, a following
// argument) matching exactly as before.
const STAGED_FILE_RE =
  /\\(?:temp|tmp|appdata\\local\\temp|programdata|public|windows\\temp)\\[^\\]*?\.(?:exe|dll|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|msi|scr|cpl|ocx|sys|drv|hta|jar|py|pyw|msc|lnk)(?=["'\s,]|$)/i;

export function mapPersistenceSniper(
  row: Row,
  host: string,
  sink: Map<string, SiemIoc>,
  timestamp: string,
): MappedEvent {
  const technique = str(getCI(row, "Technique")).trim();
  const classification = str(getCI(row, "Classification")).trim();
  const path = str(getCI(row, "Path")).trim();
  const value = str(getCI(row, "Value")).trim();
  const accessGained = str(getCI(row, "Access Gained")).trim();
  const signature = str(getCI(row, "Signature")).trim();
  const isLolbin = str(getCI(row, "IsLolbin")).trim().toLowerCase() === "true";
  const isBuiltinBinary = str(getCI(row, "IsBuiltinBinary")).trim().toLowerCase() === "true";

  // Value is the actual executable/command the technique runs — the payload an analyst cares
  // about — when the module found one; Path (a registry key, task name, or service) is always
  // present and is the fallback subject for techniques with no separate value (e.g. WMI events).
  const subject = oneLine(value || path).slice(0, 300);

  // Pull a leading drive-letter path out of Value/Path as a file IOC. Real PersistenceSniper values
  // routinely mix "path + trailing arguments" into one blob with NO reliable delimiter between the
  // two (e.g. "C:\...\MicrosoftEdgeUpdate.exe /c"), or comma-join several values into one string
  // (AppInit_DLLs, Security Packages, …). Every split-point GUESS tried here fabricated a truncated,
  // non-existent path for some real, ordinary layout: splitting on "whitespace + -//" breaks on a
  // folder/product name containing one ("Suite -64-bit", "Company - Product"); anchoring the split
  // on a trailing file extension still concatenates a comma-joined multi-value list into one bogus
  // "path" (nothing in that shape says where value 1 ends and value 2 begins). There is no syntactic
  // rule that can safely guess a split point here, so this deliberately stops guessing: extract only
  // when there's NOTHING to split — an explicitly quoted path (the quotes are the delimiter, not a
  // guess), or an unquoted value that is ALREADY a single unadorned path (no whitespace, no comma —
  // nothing else it could be). Anything else (unquoted path + args, comma-joined lists) yields no
  // IOC rather than risk emitting one that doesn't exist on disk.
  const filePaths: string[] = [];
  for (const candidate of [value, path]) {
    const quoted = /^["']([A-Za-z]:\\[^"']+)["']/.exec(candidate);
    if (quoted) {
      filePaths.push(quoted[1].slice(0, 300));
    } else if (/^[A-Za-z]:\\[^\s,"']+$/.test(candidate)) {
      filePaths.push(candidate.slice(0, 300));
    }
  }
  for (const p of filePaths) addIoc(sink, "file", p);
  // Scans the raw value/path (see STAGED_FILE_RE's own comment for why) — not filePaths, which is
  // empty for exactly the argument-carrying values this needs to see.
  const staged = STAGED_FILE_RE.test(value) || STAGED_FILE_RE.test(path);

  // Signature is only worth surfacing when it says something OTHER than "found and valid" — a
  // clean Authenticode signature is the common case and just adds noise to the title.
  const sigStatus = /status\s*=\s*([^,]*)/i.exec(signature)?.[1]?.trim() ?? "";
  const sigFlag = sigStatus && sigStatus.toLowerCase() !== "valid" ? sigStatus : "";

  // IsLolbin alone is a weak, noisy signal: rundll32.exe/sc.exe/cmd.exe/msiexec.exe are all
  // catalogued LOLBins, and they're ALSO how a large fraction of Windows' own stock scheduled
  // tasks run (sysmain.dll, PcaSvc.dll, AppxDeploymentClient.dll, …) — on one real host's import,
  // 27 rows came back IsLolbin=True and 23 of those were the OS's own recognised binaries
  // (IsBuiltinBinary=True), flooding the timeline with High-severity "findings" that were just
  // ordinary Windows behavior. But gating on !IsBuiltinBinary ALONE went too far the other way:
  // classic LOLBin abuse runs from a genuinely signed, built-in tool (that's the point of a
  // living-off-the-land binary) — suppressing every IsBuiltinBinary=True row unconditionally would
  // miss a builtin LOLBin loading a bad-signed or oddly-staged payload. Escalate on IsLolbin when
  // EITHER it isn't a recognised built-in, OR one of the other anomaly signals also fired for the
  // same row — a builtin tool alone, cleanly signed, not staged anywhere unusual, is the routine
  // case and stays suppressed; anything else earns the promotion.
  const lolbinFlag = isLolbin && (!isBuiltinBinary || sigFlag !== "" || staged);

  // Grade directly from the module's own STRUCTURED verdict columns — never from the free-text
  // description below. `subject` is built from Value/Path, real filesystem/registry content on the
  // target host that an adversary can shape (e.g. naming a dropped file `evil.exe [lolbin]`); a
  // downstream rule that re-parsed the rendered description for a bracket marker was both spoofable
  // (a crafted Value fakes a High grade the module never gave) and lossy (the description is capped
  // at 600 chars, so a long subject could push a genuine marker past the cut and leave a real
  // anomaly sitting at Info). Grading here, before any text is assembled, is immune to both:
  // PersistenceSniper enumerates almost every autostart on the box — mostly signed, first-party, and
  // ordinary — so most rows stay Info by design; only its own anomaly signals earn a promotion.
  let severity: MappedEvent["severity"] = "Info";
  if (sigFlag) severity = worst(severity, "Medium");
  // Staged is treated as High outright: an executable sitting directly in a world-writable/transient
  // location (per STAGED_FILE_RE) wired up for persistence is a strong signal on its own, whether or
  // not the tool itself is a recognised built-in.
  if (staged) severity = worst(severity, "High");
  if (lolbinFlag) severity = worst(severity, "High");

  let description = `Velociraptor: Persistence [${technique || "unknown"}]`;
  if (subject) description += ` — ${subject}`;
  if (accessGained) description += ` (${accessGained})`;
  // These markers are for the analyst reading the title — informational only, not re-parsed for
  // grading (see above). Gated on the SAME conditions that drive severity, so the marker and the
  // grade never disagree (a "[lolbin]" tag on an Info-severity row would be its own confusing bug).
  if (sigFlag) description += ` [signature: ${sigFlag}]`;
  if (staged) description += ` [staged: temp/appdata]`;
  if (lolbinFlag) description += ` [lolbin]`;
  description = withHostSuffix(description, host).slice(0, 600);

  const aggKey = `vr-persist|${technique.toLowerCase()}|${(value || path).toLowerCase()}|${host.toLowerCase()}`
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp,
    description,
    severity,
    mitre: mitreFromText(classification),
    aggKey,
    sources: ["Velociraptor"],
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
  };
}
