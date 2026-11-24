// DetectRaptor.Windows.Detection.Applications — an installed program (Windows.Sys.Programs) whose
// KeyName or DisplayName matched one of the pack's application lists ("RMM", …). The row is
// `{Category, KeyName, KeyLastWriteTimestamp, DisplayName, DisplayVersion, InstallLocation, Publisher,
// KeyPath, Regex, Comment, …}`: the verdict is `Category`, with no rule Name. rowVerdict() finds no
// rule Name, so before this mapper the row fell to the generic dump, which titles a row by its first
// message-like column — `Category` — so the title read just "RMM" and never named the application,
// and every application of one category on a host collapsed into ONE event.
//
// In its own module (not velociraptorImport) because that file is frozen at the size ledger.

import { getCI, oneLine, str, type MappedEvent } from "./siemImport.js";
import { titleSafe, withHostSuffix } from "./velociraptorTitle.js";
import { pickTime } from "./veloRowTime.js";
import { boundedAggKey } from "./aggKey.js";

type Row = Record<string, unknown>;

const TIME_KEYS = ["KeyLastWriteTimestamp", "InstallDate"] as const;
const DETAIL_KEYS = ["Publisher", "InstallLocation", "InstallSource", "UninstallString", "KeyPath"] as const;
const DESCRIPTION_CAP = 600;
const MESSAGE_CAP = 4000;

function field(row: Row, key: string): string {
  return oneLine(str(getCI(row, key)).trim());
}

const NAME_KEYS = ["DisplayName", "KeyName", "Name"] as const;
const APPLICATIONS_ARTIFACT = /detection\.applications/i;

function nameOf(row: Row): string {
  for (const k of NAME_KEYS) {
    const v = field(row, k);
    if (v) return v;
  }
  return "";
}

/**
 * The DetectRaptor Applications shape: a Category verdict plus a named program, and either the Regex
 * that matched or an artifact name that says so. An export that dropped the Regex column (a narrowed
 * hunt download, a notebook copy) still came from this artifact, and without the artifact check it
 * fell to the generic mapper, titled by the category alone.
 */
export function isApplicationsRow(row: Row, artifact = ""): boolean {
  if (field(row, "Category") === "" || nameOf(row) === "") return false;
  return getCI(row, "Regex") != null || APPLICATIONS_ARTIFACT.test(artifact);
}

// "RMM — TeamViewer 15.40.8": the category and the application lead; titleSafe keeps a " - " inside
// either from being read as the title/details boundary.
function titleOf(row: Row): { category: string; name: string; text: string } {
  const category = field(row, "Category");
  const name = nameOf(row);
  const version = field(row, "DisplayVersion");
  const text = `${titleSafe(category)} — ${titleSafe(name)}${version ? ` ${titleSafe(version)}` : ""}`;
  return { category, name, text };
}

function messageOf(row: Row): string {
  return Object.entries(row)
    .map(([k, v]) => [k, oneLine(str(v).trim())] as const)
    .filter(([k, v]) => v !== "" && !k.startsWith("_"))
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n")
    .slice(0, MESSAGE_CAP);
}

export function mapApplications(row: Row, artifact: string, host: string): MappedEvent {
  const title = titleOf(row);
  const details = DETAIL_KEYS.map((k) => [k, field(row, k)] as const)
    .filter(([, v]) => v !== "")
    .map(([k, v]) => `${k}: ${k === "Publisher" ? titleSafe(v) : v}`);
  let description = `Velociraptor${artifact ? ` [${artifact}]` : ""}: ${title.text}`;
  if (details.length) description += ` - ${details.join(" - ")}`;
  description = withHostSuffix(description.slice(0, DESCRIPTION_CAP), host).slice(0, DESCRIPTION_CAP);

  return {
    timestamp: pickTime(row, TIME_KEYS),
    description,
    severity: "Medium", // a named application list fired — the grade the detection-pack floor gave it
    mitre: [],
    // One event per host + category + application: a re-collection folds in, two applications never do.
    aggKey: boundedAggKey(
      `vr|applications|${host.toLowerCase()}|${title.category.toLowerCase()}|${title.name.toLowerCase()}`,
    ),
    sources: ["Velociraptor"],
    message: messageOf(row),
    ...(host ? { asset: host } : {}),
  };
}
