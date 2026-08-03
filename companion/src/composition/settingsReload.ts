/**
 * Live config rebuild (#178) — what POST /settings/reload actually does. Lifted out of createApp
 * by #416.
 *
 * THE PROBLEM IT SOLVES. /settings/reload applies a just-saved DFIR_<PREFIX>_* group into
 * process.env. On its own that changes nothing observable, because every integration client is
 * built ONCE at startup from env and then captured in `options` — so a corrected MISP URL (or a
 * first-time enrichment key) sat in process.env while the live client kept its boot-time config,
 * and the operator's only remedy was the restart the route exists to avoid. This rebuilds whatever
 * the prefix feeds, from the now-current env, and returns the component names so the route can
 * report what took effect.
 *
 * CONSTRUCTOR CALLS ONLY — no network, no reachability probe — so the reload stays fast and cannot
 * fail on an unreachable server. The per-integration /xxx/reconnect routes remain the way to VERIFY
 * connectivity.
 *
 * DELIBERATELY NOT REBUILT, each for its own reason:
 *   DFIR_AI_ / DFIR_VISION_  buildProvider() already reads env per call; the RUNNING analysis
 *                            pipeline still needs a restart, unchanged by this.
 *   DFIR_TOOL_               the runner is stateless — the next liveToolConfigs() sees the new env.
 *   DFIR_NSRL_               a live SQLite handle, with its own connect/disconnect routes.
 *   DFIR_PUSH_TOKEN          a store, not env-derived config.
 */
import type { AppOptions } from "./appOptions.js";
import type { EnrichmentProvider } from "../enrichment/provider.js";
import type { IrisClient } from "../integrations/iris/irisClient.js";
import { buildEnrichmentProviders, buildCustomerExposureProviders } from "./enrichmentProviders.js";
import {
  buildClickUpClient,
  buildIrisClient,
  buildMispPushClient,
  buildNotionClient,
  buildTimesketchClient,
  clickupOptions,
  irisPushOptions,
  mispPushOptions,
  notionPushOptions,
  timesketchPushOptions,
} from "./integrationClients.js";
import { buildVelociraptorClient } from "../integrations/velociraptor/velociraptorApi.js";
import { logLine } from "../logging/serverLogger.js";

const ENRICHMENT_PREFIXES = new Set([
  "DFIR_VT_",
  "DFIR_ABUSEIPDB_",
  "DFIR_HUNTINGCH_",
  "DFIR_MB_",
  "DFIR_CROWDSTRIKE_",
  "DFIR_SHODAN_",
  "DFIR_MISP_",
  "DFIR_YETI_",
  "DFIR_OPENCTI_",
  "DFIR_ROCKYRACCOON_",
  "DFIR_GEOIP_",
]);
// DFIR_SHODAN_ feeds both sets — the one key backs the IOC provider and the attack-surface check.
const EXPOSURE_PREFIXES = new Set(["DFIR_LEAKCHECK_", "DFIR_HIBP_", "DFIR_DEHASHED_", "DFIR_SHODAN_"]);

export interface SettingsReloadDeps {
  options: AppOptions;
  /** Swap the live enrichment provider set (the engine reads it through an accessor). */
  setEnrichmentProviders: (next: EnrichmentProvider[]) => void;
  /** Swap the live IRIS client, which createApp also rebinds on POST /iris/reconnect. */
  setIrisClient: (client: IrisClient | undefined) => void;
}

/**
 * Returns `rebuildForPrefix`: rebuild everything the given DFIR_<PREFIX>_ group feeds, and report
 * the component names that were rebuilt (empty when the prefix feeds nothing live).
 */
export function createSettingsReload({
  options,
  setEnrichmentProviders,
  setIrisClient,
}: SettingsReloadDeps): (prefix: string) => string[] {
  return function rebuildForPrefix(prefix: string): string[] {
    const rebuilt: string[] = [];
    if (ENRICHMENT_PREFIXES.has(prefix)) {
      const providers = buildEnrichmentProviders();
      setEnrichmentProviders(providers);
      options.enrichmentProviders = providers;
      rebuilt.push("enrichment");
    }
    if (EXPOSURE_PREFIXES.has(prefix)) {
      options.customerExposureProviders = buildCustomerExposureProviders();
      rebuilt.push("exposure");
    }
    if (prefix === "DFIR_MISP_") {
      options.mispPushClient = buildMispPushClient();
      options.mispPushOptions = mispPushOptions();
      rebuilt.push("misp");
    }
    if (prefix === "DFIR_IRIS_") {
      setIrisClient((options.rebuildIrisClient ?? buildIrisClient)());
      options.irisOptions = irisPushOptions();
      rebuilt.push("iris");
    }
    if (prefix === "DFIR_TIMESKETCH_") {
      options.timesketchClient = (options.rebuildTimesketchClient ?? buildTimesketchClient)();
      options.timesketchOptions = timesketchPushOptions();
      rebuilt.push("timesketch");
    }
    if (prefix === "DFIR_VELOCIRAPTOR_") {
      options.velociraptorClient = (options.rebuildVelociraptorClient ?? buildVelociraptorClient)();
      rebuilt.push("velociraptor");
    }
    if (prefix === "DFIR_NOTION_") {
      options.notionClient = buildNotionClient();
      options.notionOptions = notionPushOptions();
      rebuilt.push("notion");
    }
    if (prefix === "DFIR_CLICKUP_") {
      options.clickupClient = buildClickUpClient();
      options.clickupOptions = clickupOptions();
      rebuilt.push("clickup");
    }
    if (rebuilt.length > 0) logLine(`[settings] ${prefix} reloaded — rebuilt ${rebuilt.join(", ")}`);
    return rebuilt;
  };
}
