// Fakes for the AWS CloudTrail collector tests (#2313): STS, CloudTrail and S3 answered by command
// name from a scripted account, with every command recorded. Synthetic data only: the documentation
// account id, TEST-NET addresses, made-up bucket names.

import { gzipSync } from "node:zlib";
import type {
  AwsCollectClients,
  AwsSender,
} from "../../src/integrations/cloudCollect/aws/awsCollectTypes.js";
import type { OpenCloudAccount } from "../../src/integrations/cloudAccounts/types.js";
import { trailRecord } from "./cloudCollectFakes.js";
import { fakeAccessKeyId, fakeAwsSecret } from "./cloudAccountFixtures.js";

export const ACCOUNT = "123456789012";
export const ORG = "o-abc123def45";

/** An opened AWS account with made-up keys (made at runtime, never a real key). */
export const awsAccount = (region = "eu-west-1"): OpenCloudAccount => ({
  id: "a1",
  name: "lab",
  revision: 1,
  createdAt: "",
  updatedAt: "",
  provider: "aws",
  settings: { authMode: "access-key", region },
  secrets: { accessKeyId: fakeAccessKeyId(), secretAccessKey: fakeAwsSecret() },
});

export interface FakeObject {
  key: string;
  body: Uint8Array;
  versionId?: string;
  /** GetObject refuses this key the way S3 does for a KMS key the identity may not use. */
  kmsDenied?: boolean;
}

export interface FakeTrail {
  Name: string;
  S3BucketName: string;
  S3KeyPrefix?: string;
  IsOrganizationTrail?: boolean;
}

export interface FakeAwsOptions {
  /** DescribeTrails' answer in every region, unless `trailsByRegion` names the region. */
  trails: FakeTrail[];
  /** DescribeTrails per region: its own trails, "off" (region not enabled) or "dns" (lookup fails). */
  trailsByRegion?: Record<string, FakeTrail[] | "off" | "dns">;
  /** LookupEvents in `region` fails DNS on page `page` (0-based) `times` times. */
  lookupDnsFail?: { region: string; page: number; times: number };
  buckets: Record<string, FakeObject[]>;
  /** LookupEvents per region: pages of CloudTrailEvent strings, or "off" (region not enabled). */
  lookup?: Record<string, string[][] | "off">;
  /** S3 list page size, to exercise truncation. */
  listPageSize?: number;
  /** Throw this many SlowDown errors on the first GetObject calls. */
  slowDowns?: number;
  /** Buckets whose object listing (no delimiter, the trail walk) is refused; folder listing still works. */
  walkListDenied?: string[];
}

export interface Sent {
  op: string;
  region?: string;
  input: Record<string, unknown>;
}

const awsError = (name: string, status: number, message = name) =>
  Object.assign(new Error(message), { name, $metadata: { httpStatusCode: status } });

/** What Node throws when a hostname does not resolve. */
const dnsError = (region: string) =>
  Object.assign(new Error(`getaddrinfo EAI_AGAIN cloudtrail.${region}.amazonaws.com`), {
    name: "Error",
    code: "EAI_AGAIN",
  });

/** A gzipped CloudTrail object of `records` (what CloudTrail writes to S3). */
export function trailObject(records: unknown[]): Uint8Array {
  return gzipSync(Buffer.from(JSON.stringify({ Records: records })));
}

/** A CloudTrail object key, delivered at `at` (ISO, minute precision). */
export function trailKey(root: string, region: string, at: string, n = 1): string {
  const d = new Date(at);
  const p = (v: number) => String(v).padStart(2, "0");
  const day = `${d.getUTCFullYear()}/${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())}`;
  const stamp = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}T${p(d.getUTCHours())}${p(d.getUTCMinutes())}Z`;
  return `${root}CloudTrail/${region}/${day}/${ACCOUNT}_CloudTrail_${region}_${stamp}_x${n}.json.gz`;
}

export const recordJson = (i: number, name?: string): string => JSON.stringify(trailRecord(i, name));

function listBucket(objects: FakeObject[], input: Record<string, unknown>, pageSize: number) {
  const prefix = String(input.Prefix ?? "");
  const delimiter = input.Delimiter as string | undefined;
  const after = (input.ContinuationToken ?? input.StartAfter ?? "") as string;
  const keys = objects
    .map((o) => o.key)
    .filter((k) => k.startsWith(prefix))
    .sort();
  if (delimiter) {
    const prefixes = [
      ...new Set(
        keys
          .map((k) => k.slice(prefix.length))
          .filter((rest) => rest.includes(delimiter))
          .map((rest) => prefix + rest.slice(0, rest.indexOf(delimiter) + 1)),
      ),
    ];
    return { CommonPrefixes: prefixes.map((Prefix) => ({ Prefix })), IsTruncated: false };
  }
  const rest = keys.filter((k) => !after || k > after);
  const page = rest.slice(0, pageSize);
  const truncated = rest.length > pageSize;
  return {
    Contents: page.map((Key) => ({ Key })),
    IsTruncated: truncated,
    ...(truncated ? { NextContinuationToken: page[page.length - 1] } : {}),
  };
}

export function fakeAwsClients(opts: FakeAwsOptions): AwsCollectClients & { sent: Sent[] } {
  const sent: Sent[] = [];
  let slowDowns = opts.slowDowns ?? 0;
  const sender = (region?: string): AwsSender => ({
    send: async (command: object) => {
      const op = command.constructor.name.replace(/Command$/, "");
      const input = (command as { input: Record<string, unknown> }).input;
      sent.push({ op, ...(region ? { region } : {}), input });
      switch (op) {
        case "GetCallerIdentity":
          return { Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:role/collector` };
        case "DescribeTrails": {
          const own = opts.trailsByRegion?.[region ?? ""];
          if (own === "off") throw awsError("UnrecognizedClientException", 400);
          if (own === "dns") throw dnsError(region ?? "");
          return { trailList: own ?? (opts.trailsByRegion ? [] : opts.trails) };
        }
        case "ListObjectsV2": {
          const objects = opts.buckets[String(input.Bucket)];
          if (!objects) throw awsError("NoSuchBucket", 404);
          if (!input.Delimiter && opts.walkListDenied?.includes(String(input.Bucket)))
            throw awsError("AccessDenied", 403, "Access Denied");
          return listBucket(objects, input, opts.listPageSize ?? 1000);
        }
        case "GetObject": {
          if (slowDowns > 0) {
            slowDowns--;
            throw awsError("SlowDown", 503);
          }
          const obj = opts.buckets[String(input.Bucket)]?.find((o) => o.key === input.Key);
          if (!obj) throw awsError("NoSuchKey", 404);
          if (obj.kmsDenied)
            throw awsError(
              "AccessDenied",
              403,
              "User is not authorized to perform kms:Decrypt on the resource associated with this ciphertext",
            );
          return {
            Body: { transformToByteArray: async () => obj.body },
            ...(obj.versionId ? { VersionId: obj.versionId } : {}),
            ETag: '"etag"',
            $metadata: { requestId: `s3-${obj.key.slice(-12)}` },
          };
        }
        case "LookupEvents": {
          const plan = opts.lookup?.[region ?? ""] ?? [];
          if (plan === "off") throw awsError("UnrecognizedClientException", 400);
          const index = input.NextToken ? Number(String(input.NextToken).slice(1)) : 0;
          const dns = opts.lookupDnsFail;
          if (dns && dns.region === region && dns.page === index && dns.times > 0) {
            dns.times--;
            throw dnsError(region);
          }
          const events = (plan[index] ?? []).map((CloudTrailEvent, i) => ({
            EventId: `e${index}-${i}`,
            CloudTrailEvent,
          }));
          const next = index + 1 < plan.length ? `n${index + 1}` : undefined;
          return {
            Events: events,
            ...(next ? { NextToken: next } : {}),
            $metadata: { requestId: `ct-${region}-${index}` },
          };
        }
        default:
          throw new Error(`unexpected AWS command ${op}`);
      }
    },
  });
  const s3 = sender();
  const sts = sender();
  return { sent, sts, s3, cloudtrail: (region) => sender(region) };
}
