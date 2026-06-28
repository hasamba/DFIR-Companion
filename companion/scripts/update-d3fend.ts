// Re-fetch + re-slim the MITRE D3FEND ATT&CK→countermeasure mapping into
// companion/data/d3fend-map.json.
//
// The bundled `d3fend-map.json` powers the offline "Defensive Countermeasures" feature (issue #178):
// for each ATT&CK technique a case identified, it suggests the MITRE D3FEND countermeasures that
// harden against / detect / isolate that technique — bridging "what the attacker did" to "how to
// defend against it next time" WITHOUT any runtime network call or AI (OPSEC-safe, deterministic).
//
// This script is the ONLY part that touches the network, and it runs offline-prep only (never at
// request time). It downloads D3FEND's full inferred ATT&CK→D3FEND mapping (a SPARQL result set,
// ~45 MB) plus the ontology version, keeps just the technique → countermeasure links (deduped per
// technique), and writes a slimmed JSON two orders of magnitude smaller.
//
// Run:  npm run data:update-d3fend   (re-fetches and overwrites companion/data/d3fend-map.json)
//
// It is run with tsx and is NOT in tsconfig `include`, so `tsc` won't type-check it — verify by
// running. Keep it dependency-free (Node 20+ global fetch only).

import { writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Official D3FEND endpoints. The full-mappings query returns every inferred ATT&CK(off)→D3FEND(def)
// relationship; the version endpoint carries the ontology release we slimmed.
const MAPPINGS_URL =
  process.env.DFIR_D3FEND_MAPPINGS_URL ||
  "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json";
const VERSION_URL = process.env.DFIR_D3FEND_VERSION_URL || "https://d3fend.mitre.org/api/version.json";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(HERE, "..", "data", "d3fend-map.json");

// D3FEND's defensive lifecycle order — countermeasures are emitted in this order so the report and
// dashboard present a coherent Model → Harden → Detect → Isolate → Deceive → Evict → Restore flow.
const TACTIC_ORDER = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"];
const tacticRank = (t: string): number => {
  const i = TACTIC_ORDER.indexOf(t);
  return i === -1 ? TACTIC_ORDER.length : i;
};

const TECHNIQUE_RE = /^T(\d{4})(?:\.(\d{3}))?$/; // ATT&CK technique or sub-technique id

// ── SPARQL JSON result shapes (only the fields we read) ─────────────────────────────────────────
interface Binding {
  off_tech_id?: { value?: string }; // ATT&CK technique id, e.g. "T1550.001"
  def_tech?: { value?: string }; // D3FEND technique URI, …owl#TokenBinding
  def_tech_label?: { value?: string }; // "Token Binding"
  def_tactic_label?: { value?: string }; // "Harden" | "Detect" | …
  top_def_tech_label?: { value?: string }; // top-level category, "Credential Hardening"
}
interface SparqlResult {
  results?: { bindings?: Binding[] };
}

// One slimmed D3FEND countermeasure. `id` is the D3FEND technique URI fragment ("TokenBinding"),
// from which the resolver derives the d3fend.mitre.org link; `tactic` is the D3FEND defensive tactic.
interface SlimCountermeasure {
  id: string;
  name: string;
  tactic: string;
  category: string;
}

// Normalize an ATT&CK technique id, keeping the sub-technique ("t1550.001" → "T1550.001").
function normTechnique(raw: string | undefined): string | null {
  if (!raw) return null;
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  if (!m) return null;
  return m[2] ? `T${m[1]}.${m[2]}` : `T${m[1]}`;
}

// The D3FEND id is the URI fragment after '#': "…owl#TokenBinding" → "TokenBinding".
function d3fendId(uri: string | undefined): string | null {
  if (!uri) return null;
  const frag = uri.includes("#") ? uri.slice(uri.lastIndexOf("#") + 1) : uri;
  const clean = frag.trim();
  return clean ? clean : null;
}

async function fetchJson(url: string): Promise<unknown> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText} (${url})`);
  return res.json();
}

async function main(): Promise<void> {
  console.log(`[d3fend] fetching ${MAPPINGS_URL}`);
  const data = (await fetchJson(MAPPINGS_URL)) as SparqlResult;
  const bindings = data.results?.bindings ?? [];
  console.log(`[d3fend] ${bindings.length} mapping rows`);

  // Ontology version (best-effort — the mapping is still usable if this endpoint changes shape).
  let d3fendVersion = "unknown";
  try {
    const v = (await fetchJson(VERSION_URL)) as { ontology_version?: string; version?: string };
    d3fendVersion = v.ontology_version || v.version || "unknown";
  } catch (err) {
    console.warn(`[d3fend] version lookup failed (${err instanceof Error ? err.message : err}) — using "unknown"`);
  }

  // technique id → (d3fend id → countermeasure). The inferred mapping explodes each technique×
  // countermeasure across many digital-artifact rows, so dedupe by D3FEND id within each technique.
  const byTechnique = new Map<string, Map<string, SlimCountermeasure>>();
  const allCountermeasures = new Set<string>();
  for (const b of bindings) {
    const tech = normTechnique(b.off_tech_id?.value);
    const id = d3fendId(b.def_tech?.value);
    const name = b.def_tech_label?.value?.trim();
    const tactic = b.def_tactic_label?.value?.trim() || "";
    const category = b.top_def_tech_label?.value?.trim() || "";
    if (!tech || !id || !name) continue;
    let cms = byTechnique.get(tech);
    if (!cms) {
      cms = new Map<string, SlimCountermeasure>();
      byTechnique.set(tech, cms);
    }
    if (!cms.has(id)) cms.set(id, { id, name, tactic, category });
    allCountermeasures.add(id);
  }

  // Assemble: each technique's countermeasures sorted by D3FEND lifecycle tactic then name.
  const map: Record<string, SlimCountermeasure[]> = {};
  for (const tech of [...byTechnique.keys()].sort()) {
    const cms = [...byTechnique.get(tech)!.values()].sort(
      (a, b) => tacticRank(a.tactic) - tacticRank(b.tactic) || a.name.localeCompare(b.name),
    );
    map[tech] = cms;
  }

  const dataset = {
    source: "MITRE D3FEND (ATT&CK → countermeasure mappings)",
    note: "Suggested defensive countermeasures inferred by D3FEND — not exhaustive or guaranteed.",
    d3fendVersion,
    generated: new Date().toISOString().slice(0, 10),
    techniqueCount: Object.keys(map).length,
    countermeasureCount: allCountermeasures.size,
    map,
  };

  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, JSON.stringify(dataset, null, 2) + "\n", "utf8");
  console.log(
    `[d3fend] wrote ${OUT_PATH}\n[d3fend] D3FEND v${d3fendVersion} · ${dataset.techniqueCount} techniques · ` +
      `${dataset.countermeasureCount} countermeasures`,
  );
}

main().catch((err) => {
  console.error("[d3fend] FAILED:", err instanceof Error ? err.message : err);
  process.exit(1);
});
