// What a bundle can actually collect on THIS Velociraptor server, decided before anything is launched.
//
// Velociraptor compiles a hunt request as a whole: if ONE named artifact is missing, or ONE artifact's
// third-party tool cannot be fetched, hunt() returns nothing and every OTHER artifact in the request is
// lost with it. A 45-artifact triage bundle therefore fails completely over a single bad name or a
// single unconfigured tool, and the analyst sees only "no hunt id". So the run-bundle route asks the
// server what it has, launches the subset that can run, and reports what it left behind.

import {
  partitionByToolAvailability,
  type UnavailableArtifact,
  type VeloArtifactTool,
} from "./artifactTools.js";
import type { VeloArtifactInfo } from "./velociraptorApi.js";

export interface BundlePreflight {
  artifacts: string[]; // the subset to launch
  unknownArtifacts: string[]; // named by the bundle, absent from the server's catalog
  unavailableArtifacts: UnavailableArtifact[]; // present, but the server cannot get their tool
  definitions: VeloArtifactInfo[]; // the catalog, so the caller's time-scope plan needn't re-fetch it
  error?: string; // nothing can run — the caller answers 400 and launches nothing
  notes: string[]; // what was dropped and why, for the caller's log
}

/**
 * Resolve a bundle against the server's artifact catalog.
 *
 * `fetchDefinitions` should BYPASS any catalog cache: this is the one caller whose decision is
 * destructive. A stale catalog missing a just-added artifact would silently drop it from the hunt (an
 * incomplete collection, with no error), and one still listing a just-deleted artifact would let hunt()
 * reject the whole run. It fires once per human-initiated run, so the extra query costs nothing next to
 * a fleet-wide hunt.
 *
 * `fetchToolInventory` reads the server's TOOL state, a different query from the catalog and the only
 * authority on it: the catalog echoes each artifact's YAML, so a tool the analyst uploaded or re-pointed
 * still looks unconfigured there (see parseToolInventory). Its failure is not fatal either — the tool
 * check falls back to what each artifact declares, and says so in a note.
 *
 * Best-effort by design: when the catalog read itself fails, the bundle is returned UNCHANGED (a
 * diagnostics query must not be the thing that blocks a hunt) with the reason as a note. Same when the
 * server reports an empty catalog — an empty answer is not evidence that nothing exists.
 */
export async function preflightBundleArtifacts(
  artifacts: readonly string[],
  fetchDefinitions: () => Promise<VeloArtifactInfo[]>,
  fetchToolInventory?: () => Promise<Map<string, VeloArtifactTool>>,
): Promise<BundlePreflight> {
  const asIs = (notes: string[], definitions: VeloArtifactInfo[] = []): BundlePreflight => ({
    artifacts: [...artifacts],
    unknownArtifacts: [],
    unavailableArtifacts: [],
    definitions,
    notes,
  });

  let definitions: VeloArtifactInfo[];
  try {
    definitions = await fetchDefinitions();
  } catch (e) {
    return asIs([`artifact catalog check failed (launching bundle as-is): ${(e as Error).message}`]);
  }

  const known = new Set(definitions.map((a) => a.name));
  if (!known.size) return asIs([], definitions);

  const notes: string[] = [];
  const present = artifacts.filter((a) => known.has(a));
  const unknownArtifacts = artifacts.filter((a) => !known.has(a));
  if (!present.length) {
    return {
      ...asIs([], definitions),
      artifacts: [],
      unknownArtifacts,
      error: `none of this bundle's artifacts exist on the Velociraptor server — check the names in the bundle editor: ${artifacts.join(", ")}`,
    };
  }
  if (unknownArtifacts.length)
    notes.push(
      `skipping ${unknownArtifacts.length} artifact(s) not on this server: ${unknownArtifacts.join(", ")}`,
    );

  // The tool state, when we can get it. A failed read only costs the check its authority, never the run.
  let inventory: Map<string, VeloArtifactTool> | undefined;
  try {
    inventory = await fetchToolInventory?.();
  } catch (e) {
    notes.push(`tool inventory read failed (checking declared tool URLs only): ${(e as Error).message}`);
  }

  const { runnable, unavailable } = partitionByToolAvailability(present, definitions, inventory);
  for (const u of unavailable) notes.push(`skipping ${u.artifact} — ${u.reason}`);
  if (unavailable.length && !runnable.length) {
    return {
      artifacts: [],
      unknownArtifacts,
      unavailableArtifacts: unavailable,
      definitions,
      notes,
      error: `every artifact in this bundle needs a third-party tool the server cannot download: ${unavailable
        .map((u) => `${u.artifact} — ${u.reason}`)
        .join("; ")}`,
    };
  }
  return {
    artifacts: runnable,
    unknownArtifacts,
    unavailableArtifacts: unavailable,
    definitions,
    notes,
  };
}
