// DetectRaptor.Windows.Detection.Webhistory — a browser visit or download whose domain matched one of
// the pack's domain lists. The row is `{BrowserArtifact, Category, Domain, ArtifactData, Detection}`:
// the verdict is `Detection.Category` (+ DomainRegex/Comment, no rule Name), and the visit itself
// (URL, page title, user, date, history file) sits nested in `ArtifactData`. rowVerdict() finds no
// rule Name, so before this mapper the row fell to the generic dump as "Phishing Hosting - " — no
// domain, no URL, empty details — and every domain on a host collapsed into ONE event.
//
// In its own module (not velociraptorImport) because that file is frozen at the size ledger.

import { getCI, isObject, oneLine, str, addIoc, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { withHostSuffix } from "./velociraptorTitle.js";
import { pickTime } from "./veloRowTime.js";
import { boundedAggKey } from "./aggKey.js";

type Row = Record<string, unknown>;

const URL_KEYS = ["URL", "Tab_URL", "Places_URL"] as const;
const TIME_KEYS = ["Visit_Date", "Download_Date", "Last_Visit_Date", "Last_Modified_Date"] as const;
const FILE_KEYS = ["Target_Path", "Current_Path"] as const;
const MESSAGE_CAP = 4000;

/** The DetectRaptor Webhistory shape: a `Detection` object carrying a DomainRegex, plus the `Domain`. */
export function isWebhistoryRow(row: Row): boolean {
  const d = getCI(row, "Detection");
  return isObject(d) && getCI(d, "DomainRegex") != null && str(getCI(row, "Domain")).trim() !== "";
}

function firstOf(obj: Row, keys: readonly string[]): string {
  for (const k of keys) {
    const v = str(getCI(obj, k)).trim();
    if (v) return v;
  }
  return "";
}

function baseName(p: string): string {
  return p.split(/[\\/]/).pop() ?? p;
}

// Every non-empty field, one "Key: value" per line, for the expandable details.
function fieldLines(obj: Row): string[] {
  return Object.entries(obj)
    .map(([k, v]) => [k, isObject(v) || Array.isArray(v) ? JSON.stringify(v) : str(v).trim()] as const)
    .filter(([, v]) => v !== "")
    .map(([k, v]) => `${k}: ${oneLine(v)}`);
}

export function mapWebhistory(
  row: Row,
  artifact: string,
  host: string,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const detRaw = getCI(row, "Detection");
  const det: Row = isObject(detRaw) ? detRaw : {};
  const dataRaw = getCI(row, "ArtifactData");
  const data: Row = isObject(dataRaw) ? dataRaw : {};
  const domain = str(getCI(row, "Domain")).trim();
  const category =
    str(getCI(row, "Category")).trim() || str(getCI(det, "Category")).trim() || "Web history hit";
  const browser = str(getCI(row, "BrowserArtifact")).trim();
  const url = firstOf(data, URL_KEYS);
  const user = str(getCI(data, "User")).trim();
  const pageTitle = str(getCI(data, "Title")).trim();
  const file = firstOf(data, FILE_KEYS);

  if (domain) addIoc(sink, "domain", domain);
  if (/^https?:\/\//i.test(url)) addIoc(sink, "url", url);

  const parts: string[] = [];
  if (url) parts.push(`URL: ${oneLine(url)}`);
  if (file) parts.push(`File: ${baseName(file)}`);
  if (pageTitle) parts.push(`Title: ${oneLine(pageTitle)}`);
  if (user) parts.push(`User: ${user}`);
  if (browser) parts.push(browser);
  let description = `Velociraptor${artifact ? ` [${artifact}]` : ""}: ${category} — ${domain}`;
  if (parts.length) description += ` - ${parts.join(" - ")}`;
  description = withHostSuffix(description.slice(0, 600), host).slice(0, 600);

  const message = [
    `Category: ${category}`,
    `Domain: ${domain}`,
    ...(browser ? [`BrowserArtifact: ${browser}`] : []),
    ...fieldLines(data),
    ...fieldLines(det).filter((l) => !l.startsWith("Category: ")),
  ]
    .join("\n")
    .slice(0, MESSAGE_CAP);

  return {
    timestamp: pickTime(data, TIME_KEYS) || pickTime(row),
    description,
    severity: "Medium", // a named domain list fired — the same grade a DetectRaptor verdict gets by default
    mitre: [],
    // One event per host + list + domain: repeat visits to one domain fold together, two domains never do.
    aggKey: boundedAggKey(
      `vr|webhistory|${host.toLowerCase()}|${category.toLowerCase()}|${domain.toLowerCase()}`,
    ),
    sources: ["Velociraptor"],
    message,
    ...(host ? { asset: host } : {}),
  };
}
