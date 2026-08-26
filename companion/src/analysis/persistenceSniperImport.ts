// Windows.Forensics.PersistenceSniper wraps Matteo Malvica's PersistenceSniper PowerShell module —
// every row is one persistence mechanism the module found, with its own fixed column set (Technique
// / Classification / Path / Value / Access Gained / Note / Reference / Signature / IsLolbin / …).
// Without this mapper the row falls through to velociraptorImport.ts's generic key=value dump,
// which reads every column back verbatim — including a Signature struct that stringifies to
// "Status = , Subject = " when PowerShell found nothing to sign-check, and a Reference URL that
// adds noise, not signal. Kept as its own module (not inlined into velociraptorImport.ts) because
// that file is frozen at its current size by the file-size ledger (#384) — see check-file-size.mjs.
import { str, getCI, oneLine, addIoc, mitreFromText, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { withHostSuffix } from "./velociraptorTitle.js";

type Row = Record<string, unknown>;

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
  for (const candidate of [value, path]) {
    const quoted = /^["']([A-Za-z]:\\[^"']+)["']/.exec(candidate);
    if (quoted) {
      addIoc(sink, "file", quoted[1].slice(0, 300));
    } else if (/^[A-Za-z]:\\[^\s,"']+$/.test(candidate)) {
      addIoc(sink, "file", candidate.slice(0, 300));
    }
  }

  // Signature is only worth surfacing when it says something OTHER than "found and valid" — a
  // clean Authenticode signature is the common case and just adds noise to the title.
  const sigStatus = /status\s*=\s*([^,]*)/i.exec(signature)?.[1]?.trim() ?? "";
  const sigFlag = sigStatus && sigStatus.toLowerCase() !== "valid" ? sigStatus : "";

  let description = `Velociraptor: Persistence [${technique || "unknown"}]`;
  if (subject) description += ` — ${subject}`;
  if (accessGained) description += ` (${accessGained})`;
  if (sigFlag) description += ` [signature: ${sigFlag}]`;
  description = withHostSuffix(description, host).slice(0, 600);

  const aggKey = `vr-persist|${technique.toLowerCase()}|${(value || path).toLowerCase()}|${host.toLowerCase()}`
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp,
    description,
    severity: "Info",
    mitre: mitreFromText(classification),
    aggKey,
    sources: ["Velociraptor"],
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
  };
}
