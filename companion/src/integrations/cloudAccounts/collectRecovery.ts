/**
 * Startup recovery of cloud collect jobs (#2308). Live collection (#2311 onward) registers its
 * recovery steps here; the server runs them once it is listening — except on the public demo, where
 * cloud collection does not exist at all and a leftover job must never be picked up again.
 */

/** One startup step that picks up interrupted cloud collection. */
export type CloudCollectRecoverer = () => void | Promise<void>;

export interface CloudCollectRecoveryInput {
  demoMode: boolean;
  recoverers: readonly CloudCollectRecoverer[];
  log: (line: string) => void;
}

/** Runs every recovery step, each on its own (one failing never stops the rest). Skipped on the demo. */
export async function startCloudCollectRecovery({
  demoMode,
  recoverers,
  log,
}: CloudCollectRecoveryInput): Promise<"skipped-demo" | "done"> {
  if (demoMode) {
    if (recoverers.length > 0) log("[cloud-collect] demo mode — startup recovery of collect jobs skipped");
    return "skipped-demo";
  }
  for (const recover of recoverers) {
    try {
      await recover();
    } catch (err) {
      log(`[cloud-collect] startup recovery failed: ${(err as Error).message}`);
    }
  }
  return "done";
}
