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
  techniques: string[]; // base technique ids the group uses, e.g. ["T1059", "T1566"], sorted
}

const MITRE_SOURCE = "mitre-attack";
const TECHNIQUE_RE = /^T(\d{4})(?:\.\d{3})?$/; // technique or sub-technique
const DESC_MAX = 400;

// The ATT&CK external id (Gxxxx / Txxxx) for an object, or undefined.
function attackId(obj: StixObject): string | undefined {
  return obj.external_references?.find((r) => r.source_name === MITRE_SOURCE)?.external_id;
}

// Base technique id ("T1059.001" → "T1059"), or null when not a technique id.
function baseTechnique(raw: string | undefined): string | null {
  if (!raw) return null;
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  return m ? `T${m[1]}` : null;
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

  // 1. attack-pattern STIX id → base technique id (live techniques only).
  const techniqueById = new Map<string, string>();
  for (const o of objects) {
    if (o.type !== "attack-pattern" || !o.id || !isLive(o)) continue;
    const base = baseTechnique(attackId(o));
    if (base) techniqueById.set(o.id, base);
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
  const techSets = new Map<string, Set<string>>(); // group STIX id → base techniques
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

  // ATT&CK release version from the collection object, when present.
  const collection = objects.find((o) => o.type === "x-mitre-collection");
  const attackVersion = collection?.x_mitre_version || "unknown";

  const dataset = {
    source: "MITRE ATT&CK Enterprise (Groups)",
    note: "Statistical similarity based on technique overlap — NOT attribution.",
    attackVersion,
    generated: new Date().toISOString().slice(0, 10),
    techniqueField: "base" as const, // techniques are normalized to base ids (sub-techniques rolled up)
    groupCount: groups.length,
    groups,
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
