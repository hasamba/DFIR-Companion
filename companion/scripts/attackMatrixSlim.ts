// Pure STIX → attack-matrix.json transform, split out of update-attack-matrix.ts so a test can
// feed it a small bundle without the network (#1764).
//
// Keeps, for ATT&CK Enterprise: the tactic columns in the matrix's own order, and every live
// (not revoked, not deprecated) technique and sub-technique with its tactics, platforms and parent.
// A sub-technique's parent comes from its `subtechnique-of` relationship, cross-checked against the
// id prefix (T1059.001 → T1059); a mismatch is a broken bundle and throws rather than guessing.

const MITRE_SOURCE = "mitre-attack";
const TECHNIQUE_RE = /^T(\d{4})(?:\.(\d{3}))?$/;
const TACTIC_RE = /^TA\d{4}$/;

interface ExternalRef {
  source_name?: string;
  external_id?: string;
}
interface KillChainPhase {
  kill_chain_name?: string;
  phase_name?: string;
}
export interface StixObject {
  type?: string;
  id?: string;
  name?: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  x_mitre_shortname?: string;
  x_mitre_platforms?: string[];
  x_mitre_is_subtechnique?: boolean;
  kill_chain_phases?: KillChainPhase[];
  tactic_refs?: string[];
  external_references?: ExternalRef[];
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
}

export interface SlimTactic {
  id: string; // "TA0002"
  shortname: string; // "execution"
  name: string; // "Execution"
}
export interface SlimTechnique {
  id: string; // "T1059" | "T1059.001"
  name: string; // own name only — "PowerShell", not "Command and Scripting Interpreter: PowerShell"
  tactics: string[]; // tactic shortnames, in matrix column order
  platforms: string[]; // x_mitre_platforms, verbatim
  parent?: string; // sub-techniques only
}
export interface SlimMatrix {
  tactics: SlimTactic[];
  techniques: SlimTechnique[];
  warnings: string[]; // child/parent tactic mismatches etc. — logged by the script, not stored
}

function attackId(o: StixObject): string | undefined {
  return o.external_references?.find((r) => r.source_name === MITRE_SOURCE)?.external_id;
}
function isLive(o: StixObject): boolean {
  return !o.revoked && !o.x_mitre_deprecated;
}

function tacticsInOrder(objects: StixObject[]): SlimTactic[] {
  const byStixId = new Map<string, SlimTactic>();
  for (const o of objects) {
    if (o.type !== "x-mitre-tactic" || !o.id || !isLive(o)) continue;
    const id = attackId(o);
    if (!id || !TACTIC_RE.test(id) || !o.x_mitre_shortname || !o.name) continue;
    byStixId.set(o.id, { id, shortname: o.x_mitre_shortname, name: o.name.trim() });
  }
  const matrix = objects.find(
    (o) => o.type === "x-mitre-matrix" && isLive(o) && Array.isArray(o.tactic_refs),
  );
  if (!matrix?.tactic_refs) throw new Error("no live x-mitre-matrix with tactic_refs in the bundle");
  const ordered: SlimTactic[] = [];
  for (const ref of matrix.tactic_refs) {
    const t = byStixId.get(ref);
    if (t) ordered.push(t);
  }
  return ordered;
}

export function slimAttackMatrix(objects: StixObject[]): SlimMatrix {
  const tactics = tacticsInOrder(objects);
  const order = new Map(tactics.map((t, i) => [t.shortname, i]));
  const warnings: string[] = [];

  const byStixId = new Map<string, SlimTechnique>();
  for (const o of objects) {
    if (o.type !== "attack-pattern" || !o.id || !isLive(o) || !o.name) continue;
    const id = attackId(o)?.trim().toUpperCase();
    if (!id || !TECHNIQUE_RE.test(id)) continue;
    const phases = (o.kill_chain_phases ?? [])
      .filter((p) => p.kill_chain_name === MITRE_SOURCE && typeof p.phase_name === "string")
      .map((p) => p.phase_name as string)
      .filter((p) => order.has(p));
    const tacticList = [...new Set(phases)].sort((a, b) => (order.get(a) ?? 0) - (order.get(b) ?? 0));
    byStixId.set(o.id, {
      id,
      name: o.name.trim(),
      tactics: tacticList,
      platforms: Array.isArray(o.x_mitre_platforms) ? [...o.x_mitre_platforms] : [],
    });
  }

  for (const o of objects) {
    if (o.type !== "relationship" || o.relationship_type !== "subtechnique-of" || !isLive(o)) continue;
    const child = o.source_ref ? byStixId.get(o.source_ref) : undefined;
    const parent = o.target_ref ? byStixId.get(o.target_ref) : undefined;
    if (!child || !parent) continue;
    if (child.id.split(".")[0] !== parent.id) {
      throw new Error(`subtechnique-of mismatch: ${child.id} → ${parent.id}`);
    }
    child.parent = parent.id;
  }

  const techniques = [...byStixId.values()].sort((a, b) => a.id.localeCompare(b.id));
  const ids = new Map(techniques.map((t) => [t.id, t]));
  for (const t of techniques) {
    if (!t.id.includes(".")) continue;
    if (!t.parent) {
      throw new Error(`sub-technique ${t.id} has no live subtechnique-of relationship`);
    }
    const p = ids.get(t.parent);
    if (p && t.tactics.join(",") !== p.tactics.join(",")) {
      warnings.push(
        `${t.id} tactics [${t.tactics.join(",")}] differ from parent ${p.id} [${p.tactics.join(",")}]`,
      );
    }
  }
  return { tactics, techniques, warnings };
}
