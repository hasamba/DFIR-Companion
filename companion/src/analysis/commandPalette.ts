import type { InvestigationState } from "./stateTypes.js";

export type PaletteCategory = "Navigation" | "Actions" | "Exports" | "Settings" | "Case";

export interface PaletteAction {
  id: string;
  label: string;
  keywords?: string[];
  category: PaletteCategory;
  run?: (caseId: string) => void;
  available?: (caseState: InvestigationState) => boolean;
}

const CATEGORY_ORDER: PaletteCategory[] = ["Navigation", "Actions", "Exports", "Settings", "Case"];

export function buildActionRegistry(): Record<PaletteCategory, PaletteAction[]> {
  const registry: Record<PaletteCategory, PaletteAction[]> = {
    Navigation: [],
    Actions: [],
    Exports: [],
    Settings: [],
    Case: [],
  };

  const navActions: PaletteAction[] = [
    { id: "nav.findings", label: "Go to Findings", keywords: ["findings", "alerts"], category: "Navigation" },
    { id: "nav.iocs", label: "Go to IOCs", keywords: ["ioc", "indicators"], category: "Navigation" },
    { id: "nav.timeline", label: "Go to Timeline", keywords: ["timeline", "events"], category: "Navigation" },
    { id: "nav.assetGraph", label: "Go to Asset Graph", keywords: ["asset", "graph"], category: "Navigation" },
    { id: "nav.attackerPath", label: "Go to Attacker Path", keywords: ["attacker", "path", "narrative"], category: "Navigation" },
    { id: "nav.questions", label: "Go to Key Questions", keywords: ["questions", "hypotheses"], category: "Navigation" },
  ];

  const actionActions: PaletteAction[] = [
    { id: "act.import", label: "Import Evidence", keywords: ["import", "ingest", "upload"], category: "Actions" },
    { id: "act.synthesize", label: "Re-run Synthesis", keywords: ["synthesize", "ai", "analysis"], category: "Actions", available: (s) => s.findings.length > 0 },
    { id: "act.enrich", label: "Enrich IOCs", keywords: ["enrich", "threatintel", "lookup"], category: "Actions", available: (s) => s.iocs.length > 0 },
    { id: "act.tag", label: "Run Tagger", keywords: ["tag", "tagger", "label"], category: "Actions" },
    { id: "act.addFinding", label: "Add Finding", keywords: ["finding", "add", "manual"], category: "Actions" },
    { id: "act.addIoc", label: "Add IOC", keywords: ["ioc", "add", "manual"], category: "Actions" },
    { id: "act.addEvent", label: "Add Forensic Event", keywords: ["event", "manual", "timeline"], category: "Actions" },
    { id: "act.mergeIocs", label: "Merge IOCs", keywords: ["merge", "ioc", "dedupe"], category: "Actions", available: (s) => s.iocs.length > 1 },
  ];

  const exportActions: PaletteAction[] = [
    { id: "exp.report", label: "Generate Report", keywords: ["report", "pdf", "docx"], category: "Exports" },
    { id: "exp.misp", label: "Export IOCs to MISP", keywords: ["misp", "ioc", "export"], category: "Exports", available: (s) => s.iocs.length > 0 },
    { id: "exp.csv", label: "Export Findings to CSV", keywords: ["csv", "findings", "export"], category: "Exports", available: (s) => s.findings.length > 0 },
    { id: "exp.stix", label: "Export STIX Bundle", keywords: ["stix", "bundle", "export"], category: "Exports" },
    { id: "exp.thehive", label: "Push to TheHive", keywords: ["thehive", "export", "push"], category: "Exports" },
  ];

  const settingsActions: PaletteAction[] = [
    { id: "set.ai", label: "Open AI Settings", keywords: ["ai", "settings", "provider"], category: "Settings" },
    { id: "set.enrich", label: "Open Enrichment Settings", keywords: ["enrich", "settings", "provider"], category: "Settings" },
    { id: "set.theme", label: "Toggle Theme", keywords: ["theme", "dark", "light"], category: "Settings" },
    { id: "set.log", label: "Change Log Level", keywords: ["log", "level", "debug"], category: "Settings" },
  ];

  const caseActions: PaletteAction[] = [
    { id: "case.new", label: "New Case", keywords: ["case", "new", "create"], category: "Case" },
    { id: "case.switch", label: "Switch Case", keywords: ["case", "switch", "open"], category: "Case" },
    { id: "case.archive", label: "Archive Case", keywords: ["case", "archive"], category: "Case" },
    { id: "case.close", label: "Close Case", keywords: ["case", "close"], category: "Case" },
  ];

  registry.Navigation = navActions;
  registry.Actions = actionActions;
  registry.Exports = exportActions;
  registry.Settings = settingsActions;
  registry.Case = caseActions;
  return registry;
}

export function allActions(registry: Record<PaletteCategory, PaletteAction[]>): PaletteAction[] {
  return CATEGORY_ORDER.flatMap((c) => registry[c] ?? []);
}

const LOWER_A = 0x61;
const LOWER_Z = 0x7a;

function isAlpha(ch: string): boolean {
  const c = ch.charCodeAt(0);
  return c >= LOWER_A && c <= LOWER_Z;
}

function fuzzyScore(query: string, text: string): number {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (!q) return 1;
  if (!t) return 0;
  if (q === t) return 1000;
  const words = t.split(/\s+/).filter(Boolean);
  for (const w of words) {
    if (w === q) return 800;
  }
  for (const w of words) {
    if (w.startsWith(q)) return 600;
  }
  if (t.startsWith(q)) return 500;
  const subIdx = t.indexOf(q);
  if (subIdx >= 0) return 400 - Math.min(subIdx, 50);
  let qi = 0;
  let consec = 0;
  let best = 0;
  let cur = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) {
      qi++;
      consec++;
      cur += 10 + consec * 5;
      if (cur > best) best = cur;
      if (isAlpha(t[ti]) && qi === q.length) break;
    } else {
      consec = 0;
      cur = Math.max(0, cur - 1);
    }
  }
  if (qi < q.length) return 0;
  return Math.max(50, best);
}

export function fuzzyMatch(query: string, action: PaletteAction): number {
  if (!query) return 1;
  const labelScore = fuzzyScore(query, action.label);
  const kwScore = (action.keywords ?? []).reduce((m, k) => Math.max(m, fuzzyScore(query, k)), 0);
  return Math.max(labelScore, kwScore * 0.9);
}

export interface SearchResult {
  action: PaletteAction;
  score: number;
}

export function searchActions(query: string, actions: PaletteAction[]): SearchResult[] {
  let categoryFilter: PaletteCategory | undefined;
  let q = query.trim();
  if (q.startsWith(">")) {
    const rest = q.slice(1).trim();
    const spaceIdx = rest.indexOf(" ");
    const candidate = spaceIdx < 0 ? rest : rest.slice(0, spaceIdx);
    const matched = CATEGORY_ORDER.find((c) => c.toLowerCase() === candidate.toLowerCase());
    if (matched) {
      categoryFilter = matched;
      q = spaceIdx < 0 ? "" : rest.slice(spaceIdx + 1).trim();
    }
  }
  const filtered = categoryFilter ? actions.filter((a) => a.category === categoryFilter) : actions;
  const results: SearchResult[] = [];
  for (const a of filtered) {
    const score = fuzzyMatch(q, a);
    if (score > 0) results.push({ action: a, score });
  }
  results.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const ca = CATEGORY_ORDER.indexOf(a.action.category);
    const cb = CATEGORY_ORDER.indexOf(b.action.category);
    if (ca !== cb) return ca - cb;
    return a.action.label.localeCompare(b.action.label);
  });
  return results;
}