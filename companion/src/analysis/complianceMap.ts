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

export interface ComplianceMapping {
  framework: ComplianceFramework | string;
  control: string;
  obligation: string;
  deadline?: string;
}

export interface ComplianceMapDataset {
  source: string;
  note: string;
  generated: string;
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
  techniqueCount: 0,
  map: {},
};

function candidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/compliance-map.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable — fall through.
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "compliance-map.json"));
  } catch {
    // ignore
  }
  return paths;
}

function coerce(raw: unknown): ComplianceMapDataset {
  const obj = raw as Partial<ComplianceMapDataset>;
  const map =
    obj?.map && typeof obj.map === "object" && !Array.isArray(obj.map) ? obj.map : {};
  const cleaned: Record<string, ComplianceMapping[]> = {};
  for (const [tech, entries] of Object.entries(map)) {
    if (!Array.isArray(entries)) continue;
    cleaned[tech] = entries
      .filter((e): e is ComplianceMapping =>
        !!e &&
        typeof e.framework === "string" &&
        typeof e.control === "string" &&
        typeof e.obligation === "string")
      .map((e) => ({
        framework: e.framework,
        control: e.control,
        obligation: e.obligation,
        ...(e.deadline ? { deadline: e.deadline } : {}),
      }));
  }
  return {
    source: typeof obj?.source === "string" ? obj.source : "",
    note: typeof obj?.note === "string" ? obj.note : "",
    generated: typeof obj?.generated === "string" ? obj.generated : "",
    techniqueCount: typeof obj?.techniqueCount === "number" ? obj.techniqueCount : 0,
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

const CONFIRMED: ReadonlySet<string> = new Set(["confirmed"]);

export function mapFindings(findings: Finding[]): ComplianceResult[] {
  const dataset = loadComplianceMap();
  const results: ComplianceResult[] = [];
  for (const f of findings) {
    if (!CONFIRMED.has(f.status)) continue;
    if (!Array.isArray(f.mitreTechniques) || f.mitreTechniques.length === 0) continue;
    const seen = new Set<string>();
    for (const technique of f.mitreTechniques) {
      const mappings = dataset.map[technique];
      if (!mappings || mappings.length === 0) continue;
      if (seen.has(technique)) continue;
      seen.add(technique);
      results.push({ technique, findingId: f.id, frameworks: mappings });
    }
  }
  return results;
}