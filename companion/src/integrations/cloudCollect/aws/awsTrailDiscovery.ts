// Where an account's CloudTrail files are (#2313): DescribeTrails, asked in every region, names each
// trail's bucket and key prefix, and the bucket itself shows the rest. The trail record does not
// carry the organization id, so an organization trail's path is found by listing:
//
//   <prefix>/AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/          an account trail
//   <prefix>/AWSLogs/<org-id>/<account-id>/CloudTrail/<region>/YYYY/MM/DD/ an organization trail
//
// Only the collecting account's folder is read — an organization bucket holds every member
// account, and the analyst picked one. The regions are the region folders the bucket really holds.

import { DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { ListObjectsV2Command } from "@aws-sdk/client-s3";
import { regionOff, sendAws, type AwsCollectClients } from "./awsCollectTypes.js";

/** One account folder of one trail bucket. */
export interface TrailRoot {
  bucket: string;
  /** Ends in `/`: `[<prefix>/]AWSLogs/[<org-id>/]<account-id>/`. */
  root: string;
  regions: string[];
  trails: string[];
  organization: boolean;
}

interface TrailRecord {
  Name?: string;
  S3BucketName?: string;
  S3KeyPrefix?: string;
  IsOrganizationTrail?: boolean;
}

interface ListedPrefixes {
  CommonPrefixes?: { Prefix?: string }[];
  IsTruncated?: boolean;
  NextContinuationToken?: string;
}

/** A safety stop: a delimiter listing never walks more pages than this. */
const MAX_PREFIX_PAGES = 50;

/** The folder names directly under `prefix`, e.g. `["123456789012", "o-abc123"]`. */
async function childFolders(
  clients: AwsCollectClients,
  bucket: string,
  prefix: string,
  signal?: AbortSignal,
): Promise<string[]> {
  const out: string[] = [];
  let token: string | undefined;
  for (let page = 0; page < MAX_PREFIX_PAGES; page++) {
    const listed = await sendAws<ListedPrefixes>(
      clients.s3,
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        Delimiter: "/",
        ...(token ? { ContinuationToken: token } : {}),
      }),
      signal,
    );
    for (const p of listed.CommonPrefixes ?? []) {
      const name = p.Prefix?.slice(prefix.length).replace(/\/$/, "");
      if (name) out.push(name);
    }
    token = listed.IsTruncated ? listed.NextContinuationToken : undefined;
    if (!token) break;
  }
  return out;
}

const ORG_FOLDER = /^o-[a-z0-9]{10,32}$/;
const REGION_FOLDER = /^[a-z]{2}(-[a-z]+)+-\d$/;

async function rootsOfTrail(
  clients: AwsCollectClients,
  trail: { bucket: string; prefix: string; names: string[]; organization: boolean },
  account: string,
  signal?: AbortSignal,
): Promise<TrailRoot[]> {
  const base = `${trail.prefix ? `${trail.prefix.replace(/\/+$/, "")}/` : ""}AWSLogs/`;
  const top = await childFolders(clients, trail.bucket, base, signal);
  const candidates = [
    ...(top.includes(account) ? [`${base}${account}/`] : []),
    ...top.filter((f) => ORG_FOLDER.test(f)).map((org) => `${base}${org}/${account}/`),
  ];
  const roots: TrailRoot[] = [];
  for (const root of candidates) {
    const regions = (await childFolders(clients, trail.bucket, `${root}CloudTrail/`, signal))
      .filter((r) => REGION_FOLDER.test(r))
      .sort();
    if (!regions.length) continue;
    roots.push({
      bucket: trail.bucket,
      root,
      regions,
      trails: trail.names,
      organization: root !== `${base}${account}/`,
    });
  }
  return roots;
}

type Location = { bucket: string; prefix: string; names: string[]; organization: boolean };

/** Add one region's trails to `by`, one entry per bucket + key prefix (a shadow trail is the same). */
function addTrails(by: Map<string, Location>, trails: readonly TrailRecord[]): void {
  for (const t of trails) {
    if (!t.S3BucketName) continue;
    const prefix = t.S3KeyPrefix ?? "";
    const key = `${t.S3BucketName}\n${prefix}`;
    const prev = by.get(key) ?? { bucket: t.S3BucketName, prefix, names: [], organization: false };
    by.set(key, {
      ...prev,
      names: t.Name && !prev.names.includes(t.Name) ? [...prev.names, t.Name] : prev.names,
      organization: prev.organization || !!t.IsOrganizationTrail,
    });
  }
}

/**
 * The trails that deliver to S3, asked in EVERY region: a single-region trail is only listed in its
 * home region (shadow trails cover multi-region and organization trails only). A region the account
 * has not enabled is passed over and named on every page; any other error stops the discovery.
 */
async function trailLocations(clients: AwsCollectClients, regions: readonly string[], signal?: AbortSignal) {
  const by = new Map<string, Location>();
  const notEnabled: string[] = [];
  for (const region of regions) {
    try {
      const out = await sendAws<{ trailList?: TrailRecord[] }>(
        clients.cloudtrail(region),
        new DescribeTrailsCommand({ includeShadowTrails: true }),
        signal,
      );
      addTrails(by, out.trailList ?? []);
    } catch (err) {
      if (!regionOff(err)) throw err;
      notEnabled.push(region);
    }
  }
  return { locations: [...by.values()], notEnabled };
}

/** No trail writes to a bucket this identity can read: the S3 source has nothing to collect. */
export const NO_TRAIL_REASON =
  "no CloudTrail trail of this account delivers to an S3 folder this identity can list — collect " +
  '"CloudTrail event history" instead (LookupEvents: 90 days, management events only)';

export interface TrailDiscovery {
  roots: TrailRoot[];
  /** Regions that answered "not enabled" to DescribeTrails. */
  regionsNotEnabled: string[];
}

/** Every account folder of every S3-delivering trail, sorted, so a page token means the same on resume. */
export async function discoverTrailRoots(
  clients: AwsCollectClients,
  input: { account: string; regions: readonly string[] },
  signal?: AbortSignal,
): Promise<TrailDiscovery> {
  const { locations, notEnabled } = await trailLocations(clients, input.regions, signal);
  const roots: TrailRoot[] = [];
  for (const loc of locations) {
    for (const r of await rootsOfTrail(clients, loc, input.account, signal)) {
      if (!roots.some((x) => x.bucket === r.bucket && x.root === r.root)) roots.push(r);
    }
  }
  if (!roots.length) throw new Error(NO_TRAIL_REASON);
  return {
    roots: roots.sort((a, b) => `${a.bucket}/${a.root}`.localeCompare(`${b.bucket}/${b.root}`)),
    regionsNotEnabled: notEnabled,
  };
}
