// Loader + resolution for the bundled regulatory/compliance mapping (companion/data/compliance-map.json),
// issue #234. Same shape as the ATT&CK mitigations loader (attackMitigationsData.ts): a static,
// committed dataset, read once and cached, degrading to an empty mapping if the file is missing or
// corrupt (the feature then reports "not available" rather than failing the case).
//
// The dataset is a TECHNICAL mapping, not a legal determination. Two consequences are baked into the
// types here:
//   - `note` carries the "not legal advice" disclaimer and MUST be surfaced by every consumer. It is
//     part of the payload, not decoration — a control-failure list rendered without it reads as a
//     compliance verdict.
//   - `notification` models ONLY genuine breach-notification clocks (GDPR Art. 33's 72 hours, HIPAA
//     164.404's 60 days, Reg S-P's 30 days, Form 8-K Item 1.05's 4 business days). An earlier draft
//     used one loose `deadline` field for both those clocks and arbitrary control cadences ("back up
//     within 7 days"), which would have driven a dashboard countdown that looks regulatory and is
//     not. Control cadences carry no clock. `from` names the legal event that starts the clock —
//     counsel's determination, never the timestamp of a forensic finding.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "./stateTypes.js";

export type ComplianceFramework =
  | "NIST 800-53"
  | "PCI-DSS"
  | "HIPAA"
  | "GDPR"
  | "SEC"
  | "ISO 27001";

// A statutory/regulatory notification clock. `within` is an ISO-8601 duration, `unit` says whether
// it runs in calendar or business days, and `from` is the legal trigger — all three are needed to
// state a deadline honestly; a bare duration is not actionable.
export interface NotificationClock {
  within: string;
  unit: "calendar" | "business";
  from: string;
}

export interface ComplianceMapping {
  framework: ComplianceFramework | string;
  control: string;
  title: string;
  obligation: string;
  notification?: NotificationClock;
}

export interface ComplianceMapDataset {
  source: string;
  note: string;
  generated: string;
  // Which edition each framework's control identifiers were drawn from. Mixing editions silently
  // (ISO 27001:2013's A.12.x alongside :2022's A.6.x, say) makes the whole dataset untrustworthy,
  // so the edition ships with the data and is returned to callers.
  frameworkVersions: Record<string, string>;
  techniqueCount: number;
  map: Record<string, ComplianceMapping[]>;
}

export interface ComplianceResult {
  technique: string;
  findingId: string;
  frameworks: ComplianceMapping[];
}

const EMPTY: ComplianceMapDataset = {
  source: "",
  note: "",
  generated: "",
  frameworkVersions: {},
  techniqueCount: 0,
  map: {},
};

function candidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/compliance-map.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers)
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "compliance-map.json"));
  } catch {
    // ignore
  }
  return paths;
}

function coerceClock(raw: unknown): NotificationClock | undefined {
  const c = raw as Partial<NotificationClock>;
  if (!c || typeof c.within !== "string" || typeof c.from !== "string") return undefined;
  if (c.unit !== "calendar" && c.unit !== "business") return undefined;
  return { within: c.within, unit: c.unit, from: c.from };
}

function coerce(raw: unknown): ComplianceMapDataset {
  const obj = raw as Partial<ComplianceMapDataset>;
  const map =
    obj?.map && typeof obj.map === "object" && !Array.isArray(obj.map) ? obj.map : {};
  const cleaned: Record<string, ComplianceMapping[]> = {};
  for (const [tech, entries] of Object.entries(map)) {
    if (!Array.isArray(entries)) continue;
    const rows = entries
      .filter((e): e is ComplianceMapping =>
        !!e &&
        typeof e.framework === "string" &&
        typeof e.control === "string" &&
        typeof e.title === "string" &&
        typeof e.obligation === "string")
      .map((e) => {
        const notification = coerceClock(e.notification);
        return {
          framework: e.framework,
          control: e.control,
          title: e.title,
          obligation: e.obligation,
          ...(notification ? { notification } : {}),
        };
      });
    if (rows.length) cleaned[tech] = rows;
  }
  const versions: Record<string, string> = {};
  const rawVersions = obj?.frameworkVersions;
  if (rawVersions && typeof rawVersions === "object" && !Array.isArray(rawVersions)) {
    for (const [name, version] of Object.entries(rawVersions)) {
      if (typeof version === "string") versions[name] = version;
    }
  }
  return {
    source: typeof obj?.source === "string" ? obj.source : "",
    note: typeof obj?.note === "string" ? obj.note : "",
    generated: typeof obj?.generated === "string" ? obj.generated : "",
    frameworkVersions: versions,
    // Derived, never read from the file — a hand-maintained count silently goes stale the first
    // time someone adds a technique and forgets to bump it.
    techniqueCount: Object.keys(cleaned).length,
    map: cleaned,
  };
}

let cached: ComplianceMapDataset | null = null;
let warned = false;

export function loadComplianceMap(): ComplianceMapDataset {
  if (cached) return cached;
  for (const path of candidatePaths()) {
    try {
      cached = coerce(JSON.parse(readFileSync(path, "utf8")));
      return cached;
    } catch {
      // try next candidate
    }
  }
  if (!warned) {
    warned = true;
    console.warn(
      "[compliance] compliance-map.json not found or invalid — compliance mapping disabled.",
    );
  }
  cached = EMPTY;
  return cached;
}

export function _resetComplianceMapCache(): void {
  cached = null;
  warned = false;
}

export function mapFindings(findings: Finding[]): ComplianceResult[] {
  const dataset = loadComplianceMap();
  const results: ComplianceResult[] = [];
  for (const f of findings) {
    // Confirmed only. An open or dismissed finding is a hypothesis, and a hypothesis must never
    // reach a page that names breach-notification clocks.
    if (f.status !== "confirmed") continue;
    if (!Array.isArray(f.mitreTechniques) || f.mitreTechniques.length === 0) continue;
    const seen = new Set<string>();
    for (const technique of f.mitreTechniques) {
      if (seen.has(technique)) continue;
      const mappings = dataset.map[technique];
      if (!mappings || mappings.length === 0) continue;
      seen.add(technique);
      results.push({ technique, findingId: f.id, frameworks: mappings });
    }
  }
  return results;
}
