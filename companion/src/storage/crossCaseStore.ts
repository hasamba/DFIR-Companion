import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState, IOC } from "../analysis/stateTypes.js";

// Cross-case knowledge base — indexes every case's IOCs, MITRE techniques, and FP patterns so
// new cases can surface "seen in N prior cases" badges and propagate previously-benign verdicts.
// Stored as a single JSON side-file at the cases root (`cross-case-kb.json`) — lightweight and
// lock-tolerant via atomicWrite. No SQLite (the KB is small: a map of IOC value → case refs).

export interface CrossCaseIocEntry {
  value: string;
  type: IOC["type"];
  cases: CrossCaseCaseRef[];
  benignCases: string[];   // case ids where this IOC was marked false-positive / benign
}

export interface CrossCaseCaseRef {
  caseId: string;
  caseName: string;
  verdict: string;         // worst enrichment verdict observed
  lastSeen: string;        // ISO timestamp of the last state save that indexed this IOC
}

export interface CrossCaseTechniqueEntry {
  technique: string;       // e.g. "T1059.001"
  cases: { caseId: string; caseName: string; lastSeen: string }[];
}

export interface CrossCaseKB {
  iocs: Record<string, CrossCaseIocEntry>;          // keyed by IOC value
  techniques: Record<string, CrossCaseTechniqueEntry>;
  lastIndexedAt: string;
}

const EMPTY: CrossCaseKB = { iocs: {}, techniques: {}, lastIndexedAt: "" };

export class CrossCaseStore {
  private readonly kbPath: string;

  constructor(private readonly cases: CaseStore) {
    this.kbPath = join(cases.casesRoot, "cross-case-kb.json");
  }

  async load(): Promise<CrossCaseKB> {
    try {
      const raw = await readFile(this.kbPath, "utf8");
      return { ...EMPTY, ...(JSON.parse(raw) as Partial<CrossCaseKB>) };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  async save(kb: CrossCaseKB): Promise<void> {
    await atomicWrite(this.kbPath, JSON.stringify(kb, null, 2));
  }

  // Index a case's state into the KB. Called on state save (write-through).
  // Idempotent: re-indexing the same case updates refs without duplicating.
  async indexCase(state: InvestigationState, caseName: string, now = new Date().toISOString()): Promise<CrossCaseKB> {
    const kb = await this.load();

    for (const ioc of state.iocs) {
      const key = ioc.value.toLowerCase();
      const existing = kb.iocs[key] ?? { value: ioc.value, type: ioc.type, cases: [], benignCases: [] };
      const refIdx = existing.cases.findIndex((c) => c.caseId === state.caseId);
      const verdict = worstVerdict(ioc);
      const ref: CrossCaseCaseRef = { caseId: state.caseId, caseName, verdict, lastSeen: now };
      if (refIdx >= 0) existing.cases[refIdx] = ref;
      else existing.cases.push(ref);
      kb.iocs[key] = existing;
    }

    for (const t of state.mitreTechniques ?? []) {
      const id = t.id;
      const existing = kb.techniques[id] ?? { technique: id, cases: [] };
      const refIdx = existing.cases.findIndex((c) => c.caseId === state.caseId);
      const ref = { caseId: state.caseId, caseName, lastSeen: now };
      if (refIdx >= 0) existing.cases[refIdx] = ref;
      else existing.cases.push(ref);
      kb.techniques[id] = existing;
    }

    kb.lastIndexedAt = now;
    await this.save(kb);
    return kb;
  }

  // Mark an IOC as benign in a given case (cross-case FP propagation).
  async markBenign(caseId: string, iocValue: string): Promise<void> {
    const kb = await this.load();
    const key = iocValue.toLowerCase();
    const entry = kb.iocs[key];
    if (!entry) return;
    if (!entry.benignCases.includes(caseId)) entry.benignCases.push(caseId);
    await this.save(kb);
  }

  // Look up an IOC value across all cases.
  async lookupIoc(value: string): Promise<CrossCaseIocEntry | null> {
    const kb = await this.load();
    return kb.iocs[value.toLowerCase()] ?? null;
  }

  // Look up a MITRE technique across all cases.
  async lookupTechnique(techniqueId: string): Promise<CrossCaseTechniqueEntry | null> {
    const kb = await this.load();
    return kb.techniques[techniqueId] ?? null;
  }

  // Stats for the diagnostics panel.
  async stats(): Promise<{ totalIocs: number; totalTechniques: number; casesCovered: number; lastIndexedAt: string }> {
    const kb = await this.load();
    const caseIds = new Set<string>();
    for (const e of Object.values(kb.iocs)) for (const c of e.cases) caseIds.add(c.caseId);
    for (const e of Object.values(kb.techniques)) for (const c of e.cases) caseIds.add(c.caseId);
    return {
      totalIocs: Object.keys(kb.iocs).length,
      totalTechniques: Object.keys(kb.techniques).length,
      casesCovered: caseIds.size,
      lastIndexedAt: kb.lastIndexedAt,
    };
  }
}

function worstVerdict(ioc: IOC): string {
  if (!ioc.enrichments?.length) return "unknown";
  let worst = "unknown";
  for (const e of ioc.enrichments) {
    const v = (e as { verdict?: string }).verdict ?? "unknown";
    if (v === "malicious") return "malicious";
    if (v === "suspicious" && worst !== "malicious") worst = "suspicious";
    if (worst === "unknown" && v === "harmless") worst = "harmless";
  }
  return worst;
}