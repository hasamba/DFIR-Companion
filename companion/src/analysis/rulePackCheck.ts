// "Check for updates" for the detection-rule pack (#2349), shared by the dashboard button and the
// optional startup check (DFIR_RULE_PACK_UPDATE_CHECK, off by default). It finds the newest pack this
// app can load (rulePackClient.ts), compares it with the installed one and records the answer as a
// sentence. With `stage`, a newer pack is held for review — never installed: only the analyst's
// Install click does that, and the startup check never stages at all.

import type { ReleaseAssetFetch } from "./githubReleaseDownload.js";
import { findLatestRulePack } from "./rulePackClient.js";
import { comparePackVersions } from "./rulePackManifest.js";
import {
  RulePackError,
  type RulePackCheckRecord,
  type RulePackStore,
  type StagedPack,
} from "./rulePackStore.js";

const ON = new Set(["on", "1", "true", "yes"]);

/** The startup check is OFF unless DFIR_RULE_PACK_UPDATE_CHECK says on. */
export const rulePackUpdateCheckEnabled = (env: NodeJS.ProcessEnv = process.env): boolean =>
  ON.has(env.DFIR_RULE_PACK_UPDATE_CHECK?.trim().toLowerCase() ?? "");

export interface RulePackCheckResult {
  record: RulePackCheckRecord;
  staged?: StagedPack;
}

export async function checkRulePack(
  store: RulePackStore,
  deps: { fetchFn: typeof fetch; fetchAsset: ReleaseAssetFetch; stage: boolean },
): Promise<RulePackCheckResult> {
  const at = new Date().toISOString();
  const done = (record: RulePackCheckRecord, staged?: StagedPack): RulePackCheckResult => {
    store.lastCheck = record;
    return { record, ...(staged ? { staged } : {}) };
  };
  try {
    const search = await findLatestRulePack({ ...deps, appVersion: store.appVersion });
    const tail = search.newerNeedsApp ? ` A newer pack exists: ${search.newerNeedsApp.message}.` : "";
    if (search.status === "superseded")
      return done({
        at,
        status: "superseded",
        latest: search.supersededTag,
        message: `The newest rule pack this app can load (${search.supersededTag}) is older than the rules bundled with this app; nothing to install.${tail}`,
      });
    if (search.status === "none" || !search.pack)
      return done({
        at,
        status: search.newerNeedsApp ? "needs-newer-app" : "none",
        message: search.newerNeedsApp
          ? `${search.newerNeedsApp.message}.`
          : "No rule pack has been published for this app version; the bundled rules are current.",
      });
    const status = await store.status();
    const installed = status.inUse === "pack" ? status.installed : null;
    if (installed && comparePackVersions(search.pack.tag, installed.version) <= 0)
      return done({
        at,
        status: "current",
        latest: search.pack.tag,
        message: `Rule pack ${installed.version} is installed and current.${tail}`,
      });
    const staged = deps.stage
      ? store.stage({
          rulesText: search.pack.rulesText,
          manifest: search.pack.manifest,
          origin: "downloaded",
          verifiedByGitHub: true,
          htmlUrl: search.pack.htmlUrl,
        })
      : undefined;
    return done(
      {
        at,
        status: "update",
        latest: search.pack.tag,
        message: `Rule pack ${search.pack.tag} is available (installed: ${installed?.version ?? "the bundled rules"}).${tail}`,
      },
      staged,
    );
  } catch (err) {
    const record: RulePackCheckRecord = { at, status: "error", message: (err as Error).message };
    // A pack refused while staging keeps its own status (422 and the like) for the route to answer.
    if (err instanceof RulePackError) {
      store.lastCheck = record;
      throw err;
    }
    return done(record);
  }
}
