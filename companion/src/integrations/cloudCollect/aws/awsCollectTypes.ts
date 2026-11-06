// AWS CloudTrail live collection (#2313) — the shapes and constants its modules share.
//
// The clients are structural (`send(command)`), like the read check's (#2309): production hands in
// real SDK v3 clients over the cloud transport (awsCollectClients.ts), the tests hand in fakes that
// answer by command name, so every request the collector makes can be recorded and asserted.

import { CursorExpiredError, RateLimitedError } from "../collectTypes.js";

/** The structural part of an AWS SDK v3 client the collector uses. */
export interface AwsSender {
  send(command: object, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

export interface AwsCollectClients {
  sts: AwsSender;
  /** One S3 client: the trail bucket may live in any region, the client follows the redirect. */
  s3: AwsSender;
  /** #2363: EC2 in the account's own region — `DescribeRegions` and nothing else. */
  ec2: AwsSender;
  /** A CloudTrail client for `region` (LookupEvents and DescribeTrails are regional). */
  cloudtrail(region: string): AwsSender;
  /** A GuardDuty client for `region` (detectors and findings are regional, #2361). */
  guardduty(region: string): AwsSender;
}

export const S3_TRAIL_SOURCE = "s3-trail";
export const LOOKUP_SOURCE = "cloudtrail-lookup";
export const GUARDDUTY_SOURCE = "guardduty-findings";

/**
 * The FALLBACK region list (#2363), after the account's own region: the commercial regions AWS
 * enables by default. Used only when `ec2:DescribeRegions` cannot list the regions enabled on the
 * account (awsRegions.ts), and disclosed whenever it is; also the list of a collection started
 * before #2363, so its Resume walks the same regions.
 */
export const DEFAULT_AWS_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "ca-central-1",
  "sa-east-1",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-central-1",
  "eu-north-1",
  "ap-south-1",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-southeast-1",
  "ap-southeast-2",
] as const;

/** One SDK call may not hang a collection: a call that takes longer than this fails its window. */
export const AWS_CALL_TIMEOUT_MS = 120_000;

type AwsErrorShape = {
  name?: unknown;
  code?: unknown;
  message?: unknown;
  $metadata?: { httpStatusCode?: unknown };
};

export function errorName(err: unknown): string {
  const e = (err ?? {}) as AwsErrorShape;
  if (typeof e.name === "string" && e.name !== "Error") return e.name;
  return typeof e.code === "string" ? e.code : "Error";
}

export function httpStatus(err: unknown): number | undefined {
  const status = ((err ?? {}) as AwsErrorShape).$metadata?.httpStatusCode;
  return typeof status === "number" ? status : undefined;
}

/** S3 says slow down with `SlowDown` / 503, a name the engine's throttle check does not know. */
export function asThrottle(err: unknown): unknown {
  const name = errorName(err);
  if (name === "SlowDown" || name === "ServiceUnavailable" || httpStatus(err) === 503)
    return new RateLimitedError(undefined, `rate limited by AWS (${name})`);
  if (name === "InvalidNextTokenException") return new CursorExpiredError("LookupEvents NextToken expired");
  return err;
}

/** Send one command with the run's cancel signal and a per-call timeout that is not a cancel. */
export async function sendAws<T>(client: AwsSender, command: object, signal?: AbortSignal): Promise<T> {
  const timeout = AbortSignal.timeout(AWS_CALL_TIMEOUT_MS);
  const abortSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
  try {
    return (await client.send(command, { abortSignal })) as T;
  } catch (err) {
    if (timeout.aborted && !signal?.aborted)
      throw new Error(`AWS call timed out after ${AWS_CALL_TIMEOUT_MS / 1000} s`);
    throw asThrottle(err);
  }
}

/**
 * The answers AWS gives for a region the account has not enabled — definitive service responses
 * only. A transport failure (DNS, reset, timeout) is NEVER read as "region off": it fails the window
 * with its page token kept, so a Resume carries on from the same page.
 */
const REGION_OFF = new Set(["UnrecognizedClientException", "OptInRequired"]);

export function regionOff(err: unknown): boolean {
  return REGION_OFF.has(errorName(err)) && httpStatus(err) !== undefined;
}

/** A short reason from an AWS error: its name and status, never the request. */
export function awsReason(err: unknown): string {
  const status = httpStatus(err);
  return `${errorName(err)}${status ? ` (HTTP ${status})` : ""}`;
}
