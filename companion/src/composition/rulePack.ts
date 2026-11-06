// Server wiring for the detection-rule pack (#2349): one store under the server data folder, handed
// to the tagger store as its third rule source, and the optional startup check.

import { join } from "node:path";
import { RulePackStore } from "../analysis/rulePackStore.js";
import { checkRulePack, rulePackUpdateCheckEnabled } from "../analysis/rulePackCheck.js";
import { fetchOutbound } from "../routes/outboundFetchGuard.js";
import { getServerLogger } from "../logging/serverLogger.js";

let store: RulePackStore | undefined;

/** Set up the installed-pack store under `<dataRoot>/tagger/pack`. Called once by the runtime stores. */
export function configureRulePack(dataRoot: string, appVersion: string): RulePackStore {
  store = new RulePackStore(join(dataRoot, "tagger", "pack"), appVersion);
  // Sweep what an interrupted install left behind. Readers never wait on it: they resolve the
  // active pack through its pointer, which leftovers cannot affect; install and roll back do wait.
  void store.recover().then((failed) => {
    if (failed.length)
      getServerLogger().warn(`Rule pack cleanup left ${failed.length} item(s): ${failed.join(", ")}`);
  });
  return store;
}

/**
 * The optional startup check (DFIR_RULE_PACK_UPDATE_CHECK=on): records a notice for the Rule pack
 * panel and logs it. It never downloads the rules file into use and never installs. Skipped in demo.
 */
export async function startupRulePackCheck(fetchFn: typeof fetch, demoMode: boolean): Promise<void> {
  if (!store || demoMode || !rulePackUpdateCheckEnabled()) return;
  const { record } = await checkRulePack(store, {
    fetchFn,
    fetchAsset: (url, timeoutMs) => fetchOutbound(url, { timeoutMs }),
    stage: false,
  });
  const log = getServerLogger();
  if (record.status === "error") log.warn(`Rule pack update check failed: ${record.message}`);
  else if (record.status === "update") log.info(record.message);
}
