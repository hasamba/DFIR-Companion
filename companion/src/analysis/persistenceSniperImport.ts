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
const STAGING_DIR_RE = /\\(?:temp|tmp|appdata\\local\\temp|programdata|public|windows\\temp)\\/i;

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
  const staged = filePaths.some((p) => STAGING_DIR_RE.test(p));

  // Signature is only worth surfacing when it says something OTHER than "found and valid" — a
  // clean Authenticode signature is the common case and just adds noise to the title.
  const sigStatus = /status\s*=\s*([^,]*)/i.exec(signature)?.[1]?.trim() ?? "";
  const sigFlag = sigStatus && sigStatus.toLowerCase() !== "valid" ? sigStatus : "";

  // Grade directly from the module's own STRUCTURED verdict columns (IsLolbin, Signature) — never
  // from the free-text description below. `subject` is built from Value/Path, real filesystem/
  // registry content on the target host that an adversary can shape (e.g. naming a dropped file
  // `evil.exe [lolbin]`); a downstream rule that re-parsed the rendered description for a bracket
  // marker was both spoofable (a crafted Value fakes a High grade the module never gave) and lossy
  // (the description is capped at 600 chars, so a long subject could push a genuine marker past the
  // cut and leave a real LOLBin sitting at Info). Grading here, before any text is assembled, is
  // immune to both: PersistenceSniper enumerates almost every autostart on the box — mostly signed,
  // first-party, and ordinary — so most rows stay Info by design; only its own anomaly signals earn
  // a promotion.
  let severity: MappedEvent["severity"] = "Info";
  if (sigFlag) severity = worst(severity, "Medium");
  if (staged) severity = worst(severity, "Medium");
  if (isLolbin) severity = worst(severity, "High");

  let description = `Velociraptor: Persistence [${technique || "unknown"}]`;
  if (subject) description += ` — ${subject}`;
  if (accessGained) description += ` (${accessGained})`;
  // These markers are for the analyst reading the title — informational only, not re-parsed for
  // grading (see above).
  if (sigFlag) description += ` [signature: ${sigFlag}]`;
  if (staged) description += ` [staged: temp/appdata]`;
  if (isLolbin) description += ` [lolbin]`;
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
