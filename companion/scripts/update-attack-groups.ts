// Re-fetch + re-slim the MITRE ATT&CK Groups dataset into companion/data/attack-groups.json.
//
// The bundled `attack-groups.json` powers the offline "Adversary Hints" feature (issue #46):
// it maps each named adversary group to the set of ATT&CK techniques attributed to it, so the
// Companion can score a case's identified techniques against every group WITHOUT any runtime
// network call (no OPSEC risk — adversary attribution is computed locally from a static file).
//
// This script is the ONLY part that touches the network, and it runs offline-prep only (never at
// request time). It downloads the full enterprise-attack STIX bundle (~9 MB), keeps just the
// group → base-technique mapping plus a little metadata, and writes a <100 KB slimmed JSON.
//
// Run:  npm run data:update-attack   (re-fetches and overwrites companion/data/attack-groups.json)
//
// It is run with tsx and is NOT in tsconfig `include`, so `tsc` won't type-check it — verify by
// running. Keep it dependency-free (Node 20+ global fetch only).

import { writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Official, versioned ATT&CK STIX data. `master` tracks the current published release.
const STIX_URL =
  process.env.DFIR_ATTACK_STIX_URL ||
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(HERE, "..", "data", "attack-groups.json");

// ── STIX shapes (only the fields we read) ──────────────────────────────────────────────────────
interface ExternalRef {
  source_name?: string;
  external_id?: string;
  url?: string;
}
interface StixObject {
  type?: string;
  id?: string;
  name?: string;
  description?: string;
  aliases?: string[];
  x_mitre_aliases?: string[];
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  x_mitre_version?: string;
  external_references?: ExternalRef[];
  // relationship fields
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
  // data-component → its parent data-source
  x_mitre_data_source_ref?: string;
}
interface StixBundle {
  objects?: StixObject[];
}

// Output record: one adversary group → the base techniques attributed to it.
interface SlimGroup {
  id: string; // ATT&CK group id, e.g. "G0016"
  name: string; // e.g. "APT29"
  aliases: string[]; // other names, e.g. ["Cozy Bear", "The Dukes"]
  description: string; // short attribution/sector context (citations stripped, trimmed)
  techniques: string[]; // technique ids the group uses (sub-technique where MITRE maps it), sorted
}

const MITRE_SOURCE = "mitre-attack";
const TECHNIQUE_RE = /^T(\d{4})(?:\.(\d{3}))?$/; // technique or sub-technique
const DESC_MAX = 400;

// The ATT&CK external id (Gxxxx / Txxxx) for an object, or undefined.
function attackId(obj: StixObject): string | undefined {
  return obj.external_references?.find((r) => r.source_name === MITRE_SOURCE)?.external_id;
}

// Full, validated technique id, KEEPING the sub-technique ("T1059.001" stays "T1059.001",
// "T1486" stays "T1486"), or null when not a technique id. The hint scorer matches at this full
// granularity (exact sub-technique = strong signal) and derives the base itself for partial credit.
function fullTechnique(raw: string | undefined): string | null {
  if (!raw) return null;
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  if (!m) return null;
  return m[2] ? `T${m[1]}.${m[2]}` : `T${m[1]}`;
}

// MITRE descriptions embed "(Citation: Foo 2020)" markers and Markdown — strip those to a clean,
// short one-liner of attribution/sector context for the hint card.
function cleanDescription(raw: string | undefined): string {
  if (!raw) return "";
  let s = raw
    .replace(/\(Citation:[^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1") // markdown links → their text
    .replace(/[`*_]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (s.length > DESC_MAX) {
    const cut = s.slice(0, DESC_MAX);
    const lastSpace = cut.lastIndexOf(" ");
    s = (lastSpace > DESC_MAX * 0.6 ? cut.slice(0, lastSpace) : cut).trim() + "…";
  }
  return s;
}

function isLive(obj: StixObject): boolean {
  return !obj.revoked && !obj.x_mitre_deprecated;
}

async function main(): Promise<void> {
  console.log(`[attack] fetching ${STIX_URL}`);
  const res = await fetch(STIX_URL);
  if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
  const bundle = (await res.json()) as StixBundle;
  const objects = bundle.objects ?? [];
  console.log(`[attack] ${objects.length} STIX objects`);

  // 1. attack-pattern STIX id → full technique id (live techniques only), plus id → human name.
  const techniqueById = new Map<string, string>();
  const techniqueName = new Map<string, string>(); // full technique id → name ("System Information Discovery")
  for (const o of objects) {
    if (o.type !== "attack-pattern" || !o.id || !isLive(o)) continue;
    const full = fullTechnique(attackId(o));
    if (!full) continue;
    techniqueById.set(o.id, full);
    if (o.name) techniqueName.set(full, o.name.trim());
  }

  // 1b. Data sources (ATT&CK's relationship model): an x-mitre-data-component belongs to an
  // x-mitre-data-source, and a "detects" relationship links a component to the technique it can
  // detect. We resolve each technique → the "Source: Component" labels (e.g. "Process: Process
  // Creation") so the emulation panel can say WHERE to look when hunting that technique (#121).
  const dataSourceName = new Map<string, string>(); // x-mitre-data-source stix id → name
  for (const o of objects) {
    if (o.type === "x-mitre-data-source" && o.id && o.name && isLive(o)) dataSourceName.set(o.id, o.name.trim());
  }
  const componentLabel = new Map<string, string>(); // x-mitre-data-component stix id → "Source: Component"
  for (const o of objects) {
    if (o.type !== "x-mitre-data-component" || !o.id || !o.name || !isLive(o)) continue;
    const src = o.x_mitre_data_source_ref ? dataSourceName.get(o.x_mitre_data_source_ref) : undefined;
    componentLabel.set(o.id, src ? `${src}: ${o.name.trim()}` : o.name.trim());
  }
  const dataSourcesByTechnique = new Map<string, Set<string>>(); // full technique id → labels
  for (const o of objects) {
    if (o.type !== "relationship" || o.relationship_type !== "detects") continue;
    const label = o.source_ref ? componentLabel.get(o.source_ref) : undefined;
    const tech = o.target_ref ? techniqueById.get(o.target_ref) : undefined;
    if (!label || !tech) continue;
    let set = dataSourcesByTechnique.get(tech);
    if (!set) { set = new Set<string>(); dataSourcesByTechnique.set(tech, set); }
    set.add(label);
  }

  // 2. intrusion-set STIX id → slim group record (live groups only).
  const groupById = new Map<string, SlimGroup>();
  for (const o of objects) {
    if (o.type !== "intrusion-set" || !o.id || !isLive(o)) continue;
    const gid = attackId(o);
    const name = o.name?.trim();
    if (!gid || !name) continue;
    const aliasSource = o.aliases?.length ? o.aliases : o.x_mitre_aliases ?? [];
    const aliases = [...new Set(aliasSource.map((a) => a.trim()).filter((a) => a && a !== name))];
    groupById.set(o.id, { id: gid, name, aliases, description: cleanDescription(o.description), techniques: [] });
  }

  // 3. "uses" relationships intrusion-set → attack-pattern accumulate the group's technique set.
  const techSets = new Map<string, Set<string>>(); // group STIX id → full technique ids
  for (const o of objects) {
    if (o.type !== "relationship" || o.relationship_type !== "uses") continue;
    if (!o.source_ref || !o.target_ref) continue;
    if (!groupById.has(o.source_ref)) continue;
    const tech = techniqueById.get(o.target_ref);
    if (!tech) continue;
    let set = techSets.get(o.source_ref);
    if (!set) { set = new Set<string>(); techSets.set(o.source_ref, set); }
    set.add(tech);
  }

  // Assemble, dropping groups with no attributed techniques (nothing to match against).
  const groups: SlimGroup[] = [];
  for (const [stixId, group] of groupById) {
    const techniques = [...(techSets.get(stixId) ?? new Set<string>())].sort();
    if (techniques.length === 0) continue;
    groups.push({ ...group, aliases: group.aliases.sort(), techniques });
  }
  groups.sort((a, b) => a.id.localeCompare(b.id));

  // Technique metadata (name + data sources) for ONLY the techniques some group uses — bounds the
  // map (no point shipping names for techniques no group is attributed). Powers the human-readable
  // labels and "where to look" hunt hints on the emulation panel (#121).
  const usedTechniques = new Set<string>();
  for (const g of groups) for (const t of g.techniques) usedTechniques.add(t);
  const techniqueInfo: Record<string, { name: string; dataSources?: string[] }> = {};
  for (const id of [...usedTechniques].sort()) {
    const name = techniqueName.get(id) ?? "";
    const ds = dataSourcesByTechnique.get(id);
    techniqueInfo[id] = ds && ds.size ? { name, dataSources: [...ds].sort() } : { name };
  }

  // ATT&CK release version from the collection object, when present.
  const collection = objects.find((o) => o.type === "x-mitre-collection");
  const attackVersion = collection?.x_mitre_version || "unknown";

  const dataset = {
    source: "MITRE ATT&CK Enterprise (Groups)",
    note: "Statistical similarity based on technique overlap — NOT attribution.",
    attackVersion,
    generated: new Date().toISOString().slice(0, 10),
    techniqueField: "full" as const, // techniques keep sub-technique granularity (T1059.001), base derived at match time
    groupCount: groups.length,
    groups,
    techniqueInfo, // full technique id → { name, dataSources? } for the used techniques (#121)
  };

  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, JSON.stringify(dataset, null, 2) + "\n", "utf8");
  const totalTechniques = groups.reduce((n, g) => n + g.techniques.length, 0);
  console.log(
    `[attack] wrote ${OUT_PATH}\n[attack] ATT&CK v${attackVersion} · ${groups.length} groups · ` +
      `${totalTechniques} group-technique links`,
  );
}

main().catch((err) => {
  console.error("[attack] FAILED:", err instanceof Error ? err.message : err);
  process.exit(1);
});
