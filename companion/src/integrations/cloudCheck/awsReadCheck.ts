// AWS read check (#2309). The ONLY calls it makes, all reads:
//
//   sts:GetCallerIdentity        who the credential is (needs no permission, so it proves nothing
//                                about collection — it is the sign-in, not a source)
//   cloudtrail:LookupEvents      one page of one event                 → "cloudtrail-lookup"
//   s3:ListObjectsV2             one key under the trail prefix        → "s3-trail"
//   s3:GetObject                 the first byte of that key            → "s3-trail"
//   ec2:DescribeRegions          the regions enabled on the account    → "ec2-regions" (#2363)
//   guardduty:ListDetectors      the detectors of the account's region → "guardduty" (#2361)
//
// No policy simulator (it needs extra permission and cannot prove read-only) and no write of any
// kind. The clients are injected, so a test can record every command sent.

import { GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { GetObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { DescribeRegionsCommand } from "@aws-sdk/client-ec2";
import { ListDetectorsCommand } from "@aws-sdk/client-guardduty";
import {
  CHECK_CALL_TIMEOUT_MS,
  sourceResult,
  type AwsCheckSource,
  type SourceCheckResult,
} from "./readCheckTypes.js";
import { checkFailureReason } from "./readCheckWording.js";

/** The structural part of an AWS SDK v3 client the check uses. */
export interface AwsCommandSender {
  send(command: object, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

export interface AwsCheckClients {
  sts: AwsCommandSender;
  cloudtrail: AwsCommandSender;
  s3: AwsCommandSender;
  /** #2363: EC2 in the account's own region, for ec2:DescribeRegions only. */
  ec2: AwsCommandSender;
  /** GuardDuty in the account's region (#2361). */
  guardduty: AwsCommandSender;
}

export interface AwsCheckInput {
  sources: AwsCheckSource[];
  s3Bucket?: string;
  s3Prefix?: string;
  /** Every secret of the account, cut out of any error text. */
  secrets: readonly string[];
}

export interface AwsCheckOutcome {
  results: SourceCheckResult[];
  signedInAs?: string;
}

export const DEFAULT_TRAIL_PREFIX = "AWSLogs/";
const KMS_HINT = "if the trail is KMS-encrypted, the identity also needs kms:Decrypt on the trail key";

function send(client: AwsCommandSender, command: object): Promise<unknown> {
  return client.send(command, { abortSignal: AbortSignal.timeout(CHECK_CALL_TIMEOUT_MS) });
}

async function checkLookup(clients: AwsCheckClients, secrets: readonly string[]): Promise<SourceCheckResult> {
  try {
    await send(clients.cloudtrail, new LookupEventsCommand({ MaxResults: 1 }));
    return sourceResult("cloudtrail-lookup", "succeeded");
  } catch (err) {
    return sourceResult("cloudtrail-lookup", "failed", checkFailureReason(err, secrets));
  }
}

/** Without ec2:DescribeRegions a collection falls back to the default region list (#2363). */
const REGIONS_FALLBACK_HINT =
  "without it, collection uses the default region list and says so — opt-in regions may be missed";

async function checkRegions(
  clients: AwsCheckClients,
  secrets: readonly string[],
): Promise<SourceCheckResult> {
  try {
    const out = (await send(clients.ec2, new DescribeRegionsCommand({ AllRegions: false }))) as {
      Regions?: unknown[];
    };
    const n = Array.isArray(out.Regions) ? out.Regions.length : 0;
    return sourceResult("ec2-regions", "succeeded", `${n} region(s) enabled on the account`);
  } catch (err) {
    return sourceResult(
      "ec2-regions",
      "failed",
      `${checkFailureReason(err, secrets)}; ${REGIONS_FALLBACK_HINT}`,
    );
  }
}

/** No detector in the account's region: the read worked, but GuardDuty is off there. */
export const NO_DETECTOR_DETAIL =
  "the read worked; GuardDuty has no detector in the account's region (collection also asks the other regions)";

async function checkGuardDuty(
  clients: AwsCheckClients,
  secrets: readonly string[],
): Promise<SourceCheckResult> {
  try {
    const out = (await send(clients.guardduty, new ListDetectorsCommand({ MaxResults: 1 }))) as {
      DetectorIds?: unknown[];
    };
    return out.DetectorIds?.length
      ? sourceResult("guardduty", "succeeded")
      : sourceResult("guardduty", "succeeded", NO_DETECTOR_DETAIL);
  } catch (err) {
    return sourceResult("guardduty", "failed", checkFailureReason(err, secrets));
  }
}

interface ListedKeys {
  Contents?: { Key?: string }[];
}

async function readFirstObject(clients: AwsCheckClients, bucket: string, key: string): Promise<void> {
  const out = (await send(
    clients.s3,
    new GetObjectCommand({ Bucket: bucket, Key: key, Range: "bytes=0-0" }),
  )) as {
    Body?: { transformToByteArray?: () => Promise<Uint8Array> };
  };
  // Drain the one-byte body so the socket goes back to the pool.
  await out.Body?.transformToByteArray?.();
}

async function checkS3(clients: AwsCheckClients, input: AwsCheckInput): Promise<SourceCheckResult> {
  const bucket = input.s3Bucket;
  if (!bucket) return sourceResult("s3-trail", "not-tested", "name the trail bucket to test it");
  const prefix = input.s3Prefix || DEFAULT_TRAIL_PREFIX;
  let key: string | undefined;
  try {
    const listed = (await send(
      clients.s3,
      new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix, MaxKeys: 1 }),
    )) as ListedKeys;
    key = listed.Contents?.find((c) => typeof c.Key === "string")?.Key;
  } catch (err) {
    return sourceResult(
      "s3-trail",
      "failed",
      `listing ${prefix} failed: ${checkFailureReason(err, input.secrets)}`,
    );
  }
  if (!key) {
    return sourceResult(
      "s3-trail",
      "not-tested",
      `listing ${prefix} worked, but it holds no file to test reading one`,
    );
  }
  try {
    await readFirstObject(clients, bucket, key);
    return sourceResult("s3-trail", "succeeded");
  } catch (err) {
    const reason = checkFailureReason(err, input.secrets);
    return sourceResult(
      "s3-trail",
      "failed",
      `listing worked, reading a trail file failed: ${reason}; ${KMS_HINT}`,
    );
  }
}

/** Runs the AWS check: sign in, then one read per selected source, in order. */
export async function runAwsReadCheck(
  clients: AwsCheckClients,
  input: AwsCheckInput,
): Promise<AwsCheckOutcome> {
  let signedInAs: string | undefined;
  try {
    const who = (await send(clients.sts, new GetCallerIdentityCommand({}))) as { Arn?: string };
    signedInAs = typeof who.Arn === "string" ? who.Arn : undefined;
  } catch (err) {
    const reason = `sign-in failed: ${checkFailureReason(err, input.secrets)}`;
    return { results: input.sources.map((s) => sourceResult(s, "failed", reason)) };
  }
  const results: SourceCheckResult[] = [];
  for (const source of input.sources) {
    results.push(
      source === "cloudtrail-lookup"
        ? await checkLookup(clients, input.secrets)
        : source === "guardduty"
          ? await checkGuardDuty(clients, input.secrets)
          : source === "ec2-regions"
            ? await checkRegions(clients, input.secrets)
            : await checkS3(clients, input),
    );
  }
  return { results, ...(signedInAs ? { signedInAs } : {}) };
}
