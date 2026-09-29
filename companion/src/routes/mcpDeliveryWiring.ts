import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { CustodyStore } from "../analysis/custody.js";
import { EXPORT_STAGING_DIRNAME } from "../analysis/caseArchive.js";
import type { DeliverySource } from "../integrations/mcp/mcpDelivery.js";

/**
 * The case an MCP delivery reads from (#1847): the target is opened through storage/caseFileRead.ts
 * and SCP sends a snapshot staged beside the cases, where exports stage theirs.
 */
export function mcpDeliverySource(store: CaseStore, caseId: string): DeliverySource {
  return {
    casesRoot: store.casesRoot,
    caseDir: store.caseDir(caseId),
    stagingDir: join(store.casesRoot, EXPORT_STAGING_DIRNAME),
  };
}

/**
 * Where recordTransfer (#231) meets its producer: evidence leaving this box for an analysis host is
 * the canonical `transferred` event, recorded before the tool runs. When the sender hashed the bytes
 * it sent (the SCP snapshot), the chain records that hash rather than re-hashing the name.
 */
export function mcpTransferRecorder(
  custodyStore: CustodyStore | undefined,
  caseId: string,
  targetPath: string | undefined,
  serverId: string,
): ((destination: string, sent?: { sha256: string }) => Promise<void>) | undefined {
  if (!custodyStore || !targetPath) return undefined;
  return async (destination, sent) => {
    await custodyStore.recordTransfer(caseId, {
      artifactPaths: [targetPath],
      transferredBy: "analyst",
      destination,
      trigger: `mcp:${serverId}`,
      ...(sent ? { knownSha256: { [targetPath]: sent.sha256 } } : {}),
    });
  };
}
