// AWS CloudTrail live collection (#2313): the provider the #2311 engine runs. Two sources, in the
// order the panel lists them:
//
//   s3-trail           the trail's S3 objects — full history, data events included, each object
//                      saved as CloudTrail wrote it (awsTrailObjects.ts);
//   cloudtrail-lookup  LookupEvents, region by region — 90 days, management events only, the
//                      fallback when no trail delivers to S3 (awsLookupEvents.ts).
//
// Both import through the existing CloudTrail importer (stream kind "aws"). The #2312 limits:
// LookupEvents is paced at 2 requests a second per region; both sources split down to 1 s and fall
// back on the account's regions; the ingestion-delay overlap is 15 minutes.
//
// A credential is never opened here: `open` takes the account openCloudAccountForCollect opened
// (#2308). The clients — and the sign-in — are built on first use, over the cloud transport.

import { createRequire } from "node:module";
import { GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import type { AwsSecrets, AwsSettings, OpenCloudAccount } from "../../cloudAccounts/types.js";
import type { CloudTransport } from "../../cloudTransport/cloudAgent.js";
import { awsClientConfig } from "../../cloudTransport/awsTransport.js";
import {
  DEFAULT_OVERLAP_MS,
  MIN_WINDOW_MS,
  PARTITION_KEYS,
  RATE_LIMITS,
  RETENTION,
} from "../collectDefaults.js";
import type {
  CloudCollectProvider,
  CloudCollectSession,
  CollectIdentity,
  CollectPage,
  CollectPageRequest,
  CollectRegionChoice,
  CollectRegionListing,
  CollectSourceInfo,
} from "../collectTypes.js";
import { LOOKUP_SOURCE, S3_TRAIL_SOURCE, sendAws, type AwsCollectClients } from "./awsCollectTypes.js";
import { createAwsCollectClients } from "./awsCollectClients.js";
import { discoverTrailRoots, type TrailDiscovery } from "./awsTrailDiscovery.js";
import { CLOUDTRAIL_DELIVERY_HORIZON_MS, fetchTrailObject, TrailObjectWalk } from "./awsTrailObjects.js";
import { fetchLookupPage } from "./awsLookupEvents.js";
import {
  fallbackRegions,
  FILTER_REGIONS,
  FILTER_SKIPPED_BY_CHOICE,
  listEnabledRegions,
  regionScope,
  regionScopeNotes,
  splitRegions,
} from "./awsRegions.js";

export const LOOKUP_NOTICE =
  "CloudTrail event history (LookupEvents) holds the last 90 days of management events only — no " +
  "data events (S3 object reads, Lambda invocations). Collect the S3 trail for full history.";

/** The S3 source's limit, always disclosed: a file delivered later is not looked for. */
export const S3_TRAIL_NOTICE =
  `Trail files delivered more than ${CLOUDTRAIL_DELIVERY_HORIZON_MS / 3_600_000} h after the window end ` +
  "are not collected; collect the window again later to pick up a file delivered that late.";

export const AWS_COLLECT_SOURCES: readonly CollectSourceInfo[] = [
  {
    id: S3_TRAIL_SOURCE,
    label: "CloudTrail S3 trail files",
    streamKind: "aws",
    minWindowMs: MIN_WINDOW_MS.cloudTrail,
    partition: { key: PARTITION_KEYS.aws },
    overlapMs: DEFAULT_OVERLAP_MS.aws,
    notice: S3_TRAIL_NOTICE,
  },
  {
    id: LOOKUP_SOURCE,
    label: "CloudTrail event history (LookupEvents, 90 days, management events)",
    streamKind: "aws",
    minWindowMs: MIN_WINDOW_MS.cloudTrail,
    partition: { key: PARTITION_KEYS.aws },
    rateLimit: RATE_LIMITS.cloudTrailLookupEvents,
    overlapMs: DEFAULT_OVERLAP_MS.aws,
    retention: RETENTION.cloudTrailLookupEvents,
    notice: LOOKUP_NOTICE,
  },
];

const SDK_PACKAGES = [
  "@aws-sdk/client-cloudtrail",
  "@aws-sdk/client-ec2",
  "@aws-sdk/client-s3",
  "@aws-sdk/client-sts",
];

/** The SDK versions for the manifest header; empty where they cannot be read (a packaged build). */
function sdkVersions(): Record<string, string> {
  const out: Record<string, string> = {};
  try {
    const require = createRequire(import.meta.url);
    for (const name of SDK_PACKAGES) {
      try {
        out[name] = (require(`${name}/package.json`) as { version: string }).version;
      } catch {
        /* not resolvable in this build: left out, never a failure */
      }
    }
  } catch {
    /* no module resolution here (single-executable build) */
  }
  return out;
}

/**
 * The regions walked by a collection without a recorded scope (one started before #2363): the
 * account's own first, then the default ones — the fallback list (awsRegions.ts).
 */
export function lookupRegions(settings: AwsSettings): string[] {
  return fallbackRegions(settings);
}

/** A page with the collection's region sentences added to its own note (#2363). */
function withScopeNote(page: CollectPage, notes: readonly string[]): CollectPage {
  if (!notes.length) return page;
  const note = [page.note, ...notes].filter(Boolean).join(" ");
  return { ...page, note };
}

/** No trail region folder is left once the analyst's unticked regions are taken out. */
export function allTrailRegionsUnticked(skipped: readonly string[]): string {
  return (
    "every region folder the account's trails hold was unticked in the region picker " +
    `(skipped by choice: ${skipped.join(", ")}) — nothing is left to collect from S3`
  );
}

class AwsCollectSession implements CloudCollectSession {
  private clientsCache?: AwsCollectClients;
  private who?: Promise<{ account: string; caller: string }>;
  private roots?: Promise<TrailDiscovery>;
  private walk?: TrailObjectWalk;
  private filters: Readonly<Record<string, string>> = {};

  constructor(
    private readonly settings: AwsSettings,
    private readonly makeClients: () => AwsCollectClients,
  ) {}

  private get clients(): AwsCollectClients {
    this.clientsCache ??= this.makeClients();
    return this.clientsCache;
  }

  private caller(signal?: AbortSignal): Promise<{ account: string; caller: string }> {
    this.who ??= sendAws<{ Account?: string; Arn?: string }>(
      this.clients.sts,
      new GetCallerIdentityCommand({}),
      signal,
    ).then(
      (out) => ({ account: out.Account ?? "", caller: out.Arn ?? "" }),
      (err: unknown) => {
        this.who = undefined;
        throw err;
      },
    );
    return this.who;
  }

  /**
   * The regions this collection walks — the one accessor (#2363): the scope recorded in the
   * manifest header, or the pre-#2363 list for a collection that has none.
   */
  walkRegions(): string[] {
    const recorded = splitRegions(this.filters[FILTER_REGIONS]);
    return recorded.length ? recorded : lookupRegions(this.settings);
  }

  private skippedByChoice(): Set<string> {
    return new Set(splitRegions(this.filters[FILTER_SKIPPED_BY_CHOICE]));
  }

  listRegions(signal?: AbortSignal): Promise<CollectRegionListing> {
    return listEnabledRegions(this.clients.ec2, this.settings, signal);
  }

  async prepareFilters(choice: CollectRegionChoice, signal?: AbortSignal): Promise<Record<string, string>> {
    const filters = regionScope(await this.listRegions(signal), choice);
    this.applyFilters(filters);
    return filters;
  }

  applyFilters(filters: Readonly<Record<string, string>>): void {
    this.filters = { ...filters };
    this.roots = undefined;
    this.walk = undefined;
  }

  /** Trail discovery, asked in the walked regions; a region folder the analyst unticked is dropped. */
  private async discover(account: string, signal?: AbortSignal): Promise<TrailDiscovery> {
    const found = await discoverTrailRoots(this.clients, { account, regions: this.walkRegions() }, signal);
    const skipped = this.skippedByChoice();
    if (!skipped.size) return found;
    // Only an explicit untick drops a folder: a folder of a region that is not enabled today
    // (an opt-in region turned off after it logged) is still history, and still read.
    const roots = found.roots
      .map((r) => ({ ...r, regions: r.regions.filter((g) => !skipped.has(g)) }))
      .filter((r) => r.regions.length);
    if (!roots.length) throw new Error(allTrailRegionsUnticked([...skipped]));
    return { ...found, roots };
  }

  private trailRoots(signal?: AbortSignal): Promise<TrailDiscovery> {
    this.roots ??= this.caller(signal)
      .then(({ account }) => this.discover(account, signal))
      .catch((err: unknown) => {
        this.roots = undefined;
        throw err;
      });
    return this.roots;
  }

  async identity(signal?: AbortSignal): Promise<CollectIdentity> {
    const who = await this.caller(signal);
    return { accountRef: who.account, caller: who.caller, sdkVersions: sdkVersions() };
  }

  async fetchPage(request: CollectPageRequest): Promise<CollectPage> {
    const notes = regionScopeNotes(this.filters);
    if (request.source === LOOKUP_SOURCE)
      return withScopeNote(await fetchLookupPage(this.clients, this.walkRegions(), request), notes);
    if (request.source !== S3_TRAIL_SOURCE) throw new Error(`unknown AWS source "${request.source}"`);
    const discovery = await this.trailRoots(request.signal);
    this.walk ??= new TrailObjectWalk(this.clients);
    return withScopeNote(await fetchTrailObject(this.walk, this.clients, discovery, request), notes);
  }

  async partitionValues(source: string, signal?: AbortSignal): Promise<readonly string[]> {
    if (source === LOOKUP_SOURCE) return this.walkRegions();
    const { roots } = await this.trailRoots(signal);
    return [...new Set(roots.flatMap((r) => r.regions))].sort();
  }
}

export interface AwsCollectProviderDeps {
  /** The cloud transport, made at open (the settings are read then, like the read check). */
  transport: () => CloudTransport;
  /** Tests: a recording request handler in place of the transport's. */
  config?: (transport: CloudTransport) => { requestHandler: unknown };
  /** Tests: structural fake clients in place of the SDK's. */
  clients?: (settings: AwsSettings, secrets: AwsSecrets) => AwsCollectClients;
}

export function createAwsCollectProvider(deps: AwsCollectProviderDeps): CloudCollectProvider {
  return {
    provider: "aws",
    sources: AWS_COLLECT_SOURCES,
    regionPicker: true,
    open(account: OpenCloudAccount): CloudCollectSession {
      if (account.provider !== "aws") throw new Error("not an AWS account");
      const { settings, secrets } = account;
      const make = (): AwsCollectClients => {
        if (deps.clients) return deps.clients(settings, secrets);
        const transport = deps.transport();
        const config = deps.config ? deps.config(transport) : awsClientConfig(transport);
        return createAwsCollectClients(settings, secrets, transport, config);
      };
      return new AwsCollectSession(settings, make);
    },
  };
}
