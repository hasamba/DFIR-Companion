import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { AssetType, AssetGraph, GraphAsset, GraphIoc, AssetGraphEdge } from "./assetGraph.js";
import type { Severity } from "./stateTypes.js";

// Manual analyst edits to the asset ↔ IoC graph: renames, additions, suppressions, and link
// overrides. Kept in `state/asset-overrides.json` — NOT in InvestigationState, so synthesis
// never wipes them (same pattern as comments.json / tags.json). Applied after buildAssetGraph
// so the deterministic derivation is always the baseline.

const manualAssetSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.enum(["host", "account", "service", "other"]),
});
export type ManualAsset = z.infer<typeof manualAssetSchema>;

export const assetOverridesSchema = z.object({
  renames: z.record(z.string(), z.string()).default({}),
  added: z.array(manualAssetSchema).default([]),
  removed: z.array(z.string()).default([]),          // suppressed auto-derived asset ids
  addedLinks: z.array(z.object({ asset: z.string(), ioc: z.string() })).default([]),
  removedLinks: z.array(z.object({ asset: z.string(), ioc: z.string() })).default([]),
}).catch({ renames: {}, added: [], removed: [], addedLinks: [], removedLinks: [] });

export type AssetOverrides = z.infer<typeof assetOverridesSchema>;

export function emptyOverrides(): AssetOverrides {
  return { renames: {}, added: [], removed: [], addedLinks: [], removedLinks: [] };
}

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// Apply manual overrides to an auto-derived asset graph. Pure — mutates neither argument.
export function applyAssetOverrides(graph: AssetGraph, overrides: AssetOverrides): AssetGraph {
  // 1. Build asset map: start from auto-derived, apply suppressions and renames.
  const assetMap = new Map<string, GraphAsset>();
  for (const a of graph.assets) {
    if (overrides.removed.includes(a.id)) continue;
    const name = overrides.renames[a.id] ?? a.name;
    assetMap.set(a.id, { ...a, name, iocIds: [] });
  }

  // 2. Add manual assets (skip if id already in map from auto-derivation).
  for (const ma of overrides.added) {
    if (!assetMap.has(ma.id)) {
      assetMap.set(ma.id, {
        id: ma.id, name: ma.name, type: ma.type,
        compromised: false, iocIds: [], findingIds: [], eventCount: 0, maxSeverity: "Info",
      });
    }
  }

  // 3. Build final edge set: suppress removedLinks, append addedLinks.
  const iocById = new Map<string, GraphIoc>(graph.iocs.map((i) => [i.id, i]));
  const removedSet = new Set(overrides.removedLinks.map((r) => `${r.asset}|${r.ioc}`));
  const edgeSet = new Set<string>();
  const edges: AssetGraphEdge[] = [];

  for (const e of graph.edges) {
    const key = `${e.asset}|${e.ioc}`;
    if (!removedSet.has(key) && assetMap.has(e.asset) && !edgeSet.has(key)) {
      edgeSet.add(key);
      edges.push(e);
    }
  }
  for (const link of overrides.addedLinks) {
    const key = `${link.asset}|${link.ioc}`;
    if (!edgeSet.has(key) && assetMap.has(link.asset) && iocById.has(link.ioc)) {
      edgeSet.add(key);
      edges.push(link);
    }
  }

  // 4. Re-derive iocIds on assets and assetIds on iocs from the final edge set.
  const iocAssets = new Map<string, string[]>();
  for (const e of edges) {
    const a = assetMap.get(e.asset);
    if (a && !a.iocIds.includes(e.ioc)) a.iocIds.push(e.ioc);
    const arr = iocAssets.get(e.ioc) ?? [];
    arr.push(e.asset);
    iocAssets.set(e.ioc, arr);
  }

  // 5. Rebuild the connected-IoC list (only IoCs that still have ≥1 asset after overrides).
  const iocs: GraphIoc[] = [];
  for (const [iocId, assetIds] of iocAssets) {
    const base = iocById.get(iocId);
    if (base) iocs.push({ ...base, assetIds });
  }

  // 6. Recompute the compromised flag (manual assets start clean; renamed/re-linked ones keep theirs).
  const assets = [...assetMap.values()].map((a) => ({
    ...a,
    compromised: a.findingIds.length > 0 || a.maxSeverity === "Critical" || a.maxSeverity === "High",
  }));

  assets.sort(
    (a, b) =>
      Number(b.compromised) - Number(a.compromised) ||
      SEV_RANK[a.maxSeverity] - SEV_RANK[b.maxSeverity] ||
      a.name.localeCompare(b.name),
  );
  iocs.sort((a, b) => a.value.localeCompare(b.value));

  return { assets, iocs, edges };
}

export class AssetOverridesStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "asset-overrides.json");
  }

  async load(caseId: string): Promise<AssetOverrides> {
    try {
      return assetOverridesSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyOverrides();
      throw err;
    }
  }

  private async save(caseId: string, overrides: AssetOverrides): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(overrides, null, 2));
  }

  // Set (or clear) a display-name override for an asset. An empty name clears the rename.
  async rename(caseId: string, assetId: string, name: string): Promise<AssetOverrides> {
    const ov = await this.load(caseId);
    const trimmed = name.trim();
    const renames = { ...ov.renames };
    if (trimmed) renames[assetId] = trimmed;
    else delete renames[assetId];
    const next = { ...ov, renames };
    await this.save(caseId, next);
    return next;
  }

  // Add a manually created asset. Returns the created asset + updated overrides.
  // Assigns a stable UUID-based id prefixed "manual:" to distinguish from auto-derived ones.
  async addAsset(caseId: string, input: { name: string; type: AssetType }): Promise<{ overrides: AssetOverrides; asset: ManualAsset }> {
    const name = input.name.trim();
    if (!name) throw new Error("name is required");
    const ov = await this.load(caseId);
    const asset: ManualAsset = { id: `manual:${randomUUID()}`, name, type: input.type };
    const next = { ...ov, added: [...ov.added, asset] };
    await this.save(caseId, next);
    return { overrides: next, asset };
  }

  // Remove an asset: deletes from `added` if manual; pushes to `removed` if auto-derived.
  async removeAsset(caseId: string, assetId: string): Promise<AssetOverrides> {
    const ov = await this.load(caseId);
    const next = assetId.startsWith("manual:")
      ? { ...ov, added: ov.added.filter((a) => a.id !== assetId) }
      : { ...ov, removed: [...new Set([...ov.removed, assetId])] };
    await this.save(caseId, next);
    return next;
  }

  // Restore a suppressed auto-derived asset (remove it from the `removed` list).
  async restoreAsset(caseId: string, assetId: string): Promise<AssetOverrides> {
    const ov = await this.load(caseId);
    const next = { ...ov, removed: ov.removed.filter((id) => id !== assetId) };
    await this.save(caseId, next);
    return next;
  }

  // Add a manual link between an asset and an IoC. Idempotent; also un-suppresses the pair.
  async addLink(caseId: string, asset: string, ioc: string): Promise<AssetOverrides> {
    const ov = await this.load(caseId);
    const alreadyAdded = ov.addedLinks.some((l) => l.asset === asset && l.ioc === ioc);
    const addedLinks = alreadyAdded ? ov.addedLinks : [...ov.addedLinks, { asset, ioc }];
    const removedLinks = ov.removedLinks.filter((l) => !(l.asset === asset && l.ioc === ioc));
    const next = { ...ov, addedLinks, removedLinks };
    await this.save(caseId, next);
    return next;
  }

  // Suppress (or delete) a link. If it was a manual addition, removes from addedLinks;
  // otherwise adds to removedLinks so the auto-derived edge is hidden. Idempotent.
  async removeLink(caseId: string, asset: string, ioc: string): Promise<AssetOverrides> {
    const ov = await this.load(caseId);
    const wasManual = ov.addedLinks.some((l) => l.asset === asset && l.ioc === ioc);
    const addedLinks = ov.addedLinks.filter((l) => !(l.asset === asset && l.ioc === ioc));
    const alreadyRemoved = ov.removedLinks.some((l) => l.asset === asset && l.ioc === ioc);
    const removedLinks = wasManual || alreadyRemoved ? ov.removedLinks : [...ov.removedLinks, { asset, ioc }];
    const next = { ...ov, addedLinks, removedLinks };
    await this.save(caseId, next);
    return next;
  }

  // Restore a suppressed auto-derived link (remove it from removedLinks).
  async restoreLink(caseId: string, asset: string, ioc: string): Promise<AssetOverrides> {
    const ov = await this.load(caseId);
    const next = { ...ov, removedLinks: ov.removedLinks.filter((l) => !(l.asset === asset && l.ioc === ioc)) };
    await this.save(caseId, next);
    return next;
  }
}
