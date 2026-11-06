// The Microsoft live collector (#2315): one CloudCollectProvider for the #2311 engine.
//
// Sources (microsoftSources.ts): the unified audit log (Graph AuditLogQuery, v1.0), Entra directory
// audits (v1.0), Entra sign-ins in four categories (beta, for `signInEventTypes`), and the Azure
// Activity log of every subscription the app can read (Azure Monitor 2015-04-01). Pages are saved by
// the engine exactly as the cloud sent them and imported through the existing importers: the M365
// importer for Graph audit records (#2304 adapter) and Entra logs, the cloud-activity importer for
// Azure Activity (#2303 streaming).
//
// The session's wire is injected (MicrosoftWire), so every test runs on mocked Graph and ARM;
// microsoftWire.ts builds the real one over the cloud transport.

import type { OpenCloudAccount } from "../cloudAccounts/types.js";
import type {
  CloudCollectProvider,
  CloudCollectSession,
  CollectIdentity,
  CollectPage,
  CollectPageRequest,
} from "../cloudCollect/collectTypes.js";
import { realClock } from "../cloudCollect/collectRateLimit.js";
import { AZURE_ACTIVITY_SOURCE, fetchActivityPage, listSubscriptions } from "./azureActivitySource.js";
import { DIRECTORY_AUDITS_SOURCE, fetchEntraPage, isSignInSource } from "./entraSources.js";
import { ACTIVITY_LOG_API_VERSION, SUBSCRIPTIONS_API_VERSION, type HttpCall } from "./microsoftHttp.js";
import { MICROSOFT_NOTES, MICROSOFT_SOURCES, UAL_SOURCE } from "./microsoftSources.js";
import { fetchUalPage, type PendingQueries, type UalTiming } from "./ualSource.js";

export interface MicrosoftWire {
  graph: HttpCall;
  arm: HttpCall;
  close?(): void;
}

export interface MicrosoftProviderDeps {
  /** Build the wire for an opened account. Throws a fixed-text error for an unusable certificate. */
  wire(account: Extract<OpenCloudAccount, { provider: "microsoft" }>): MicrosoftWire;
  /** Poll pacing for audit queries; the tests pass a clock that never waits. */
  timing?: Partial<UalTiming>;
}

export const MICROSOFT_API_VERSIONS: Record<string, string> = {
  "graph:security/auditLog/queries": "v1.0",
  "graph:auditLogs/directoryAudits": "v1.0",
  "graph:auditLogs/signIns": "beta",
  "arm:Microsoft.Insights/eventtypes/management/values": ACTIVITY_LOG_API_VERSION,
  "arm:subscriptions": SUBSCRIPTIONS_API_VERSION,
};

/** A session that failed to open: every call answers with the reason (never a secret). */
function brokenSession(err: unknown): CloudCollectSession {
  const fail = async (): Promise<never> => {
    throw err instanceof Error ? err : new Error(String(err));
  };
  return { identity: fail, fetchPage: fail };
}

class MicrosoftSession implements CloudCollectSession {
  private readonly pending: PendingQueries = new Map();
  private subscriptions?: Promise<string[]>;

  constructor(
    private readonly account: Extract<OpenCloudAccount, { provider: "microsoft" }>,
    private readonly wire: MicrosoftWire,
    private readonly timing: UalTiming,
  ) {}

  async identity(): Promise<CollectIdentity> {
    return {
      accountRef: this.account.settings.tenantId,
      caller: this.account.settings.clientId,
      sdkVersions: MICROSOFT_API_VERSIONS,
    };
  }

  private subscriptionList(signal?: AbortSignal): Promise<string[]> {
    this.subscriptions ??= listSubscriptions(this.wire.arm, this.timing.now, signal).catch((err: unknown) => {
      this.subscriptions = undefined; // a failed listing is asked again on the next page
      throw err;
    });
    return this.subscriptions;
  }

  async fetchPage(request: CollectPageRequest): Promise<CollectPage> {
    const { source } = request;
    if (source === UAL_SOURCE) return fetchUalPage(this.wire.graph, request, this.timing, this.pending);
    if (source === DIRECTORY_AUDITS_SOURCE || isSignInSource(source))
      return fetchEntraPage(this.wire.graph, request, this.timing.now);
    if (source === AZURE_ACTIVITY_SOURCE) {
      const subs = await this.subscriptionList(request.signal);
      return fetchActivityPage(this.wire.arm, request, subs, this.timing.now);
    }
    throw new Error(`unknown Microsoft source: ${source}`);
  }

  close(): void {
    this.pending.clear();
    this.wire.close?.();
  }
}

/** The provider the server registers under `microsoft`. */
export function microsoftCollectProvider(deps: MicrosoftProviderDeps): CloudCollectProvider {
  const timing: UalTiming = { now: realClock.now, sleep: realClock.sleep, ...deps.timing };
  return {
    provider: "microsoft",
    sources: MICROSOFT_SOURCES,
    notes: MICROSOFT_NOTES,
    // Two accounts of one tenant draw on one shared daily audit-query quota.
    quotaScope: (settings) =>
      typeof settings.tenantId === "string" && settings.tenantId
        ? `microsoft:${settings.tenantId.toLowerCase()}`
        : undefined,
    open(account) {
      if (account.provider !== "microsoft") return brokenSession(new Error("not a Microsoft account"));
      try {
        return new MicrosoftSession(account, deps.wire(account), timing);
      } catch (err) {
        return brokenSession(err);
      }
    },
  };
}
