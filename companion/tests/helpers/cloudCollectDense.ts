// A density-model fake provider for the #2312 tests: records at fixed times (and regions); a query
// whose window holds more than `cap` records answers with the first `cap` and `capped: true`.

import type {
  CloudCollectSession,
  CollectPage,
  CollectPageRequest,
  CollectSourceInfo,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import type { CollectClock } from "../../src/integrations/cloudCollect/collectRateLimit.js";

export interface DenseRecord {
  at: number;
  region: string;
}

/** A CloudTrail record at `at`. Synthetic: documentation account id, TEST-NET source address. */
function record(i: number, r: DenseRecord) {
  return {
    eventVersion: "1.09",
    eventID: `00000000-0000-4000-c000-${String(i).padStart(12, "0")}`,
    eventTime: new Date(r.at).toISOString().replace(/\.\d{3}Z$/, "Z"),
    eventSource: "iam.amazonaws.com",
    eventName: i % 2 ? "StopLogging" : "DeleteTrail",
    awsRegion: r.region,
    sourceIPAddress: "198.51.100.9",
    userIdentity: {
      type: "IAMUser",
      arn: `arn:aws:iam::123456789012:user/dense${i}`,
      accountId: "123456789012",
      userName: `dense${i}`,
    },
  };
}

export interface DenseOptions {
  records: DenseRecord[];
  /** Records one query may return before the cloud caps it. */
  cap: number;
  perPage?: number;
  /** Thrown before the call with this index (0-based) is answered. */
  throwOn?: Map<number, () => Error>;
  partitionValues?: string[];
  acquiredUntil?: string;
}

export function denseSession(opts: DenseOptions): CloudCollectSession & { calls: CollectPageRequest[] } {
  const perPage = opts.perPage ?? 50;
  const calls: CollectPageRequest[] = [];
  const indexed = opts.records.map((r, i) => ({ r, i }));
  return {
    calls,
    identity: async () => ({
      accountRef: "123456789012",
      caller: "arn:aws:iam::123456789012:role/collector",
      sdkVersions: { fake: "1.0.0" },
    }),
    ...(opts.partitionValues ? { partitionValues: async () => opts.partitionValues ?? [] } : {}),
    fetchPage: async (req): Promise<CollectPage> => {
      const n = calls.length;
      calls.push(req);
      const thrower = opts.throwOn?.get(n);
      if (thrower) throw thrower();
      const start = Date.parse(req.window.start);
      const end = Date.parse(req.window.end);
      const region = req.partition?.region;
      const inWindow = indexed.filter(
        ({ r }) => r.at >= start && r.at < end && (!region || r.region === region),
      );
      const capped = inWindow.length > opts.cap;
      const visible = capped ? inWindow.slice(0, opts.cap) : inWindow;
      const offset = req.pageToken ? Number(req.pageToken.slice(1)) : 0;
      const slice = visible.slice(offset, offset + perPage);
      const next = !capped && offset + perPage < visible.length ? `o${offset + perPage}` : undefined;
      return {
        body: Buffer.from(JSON.stringify({ Records: slice.map(({ r, i }) => record(i, r)) })),
        extension: "json",
        recordCount: slice.length,
        ...(next ? { nextPageToken: next } : {}),
        ...(capped ? { capped: true } : {}),
        ...(opts.acquiredUntil ? { acquiredUntil: opts.acquiredUntil } : {}),
        requestParams: { start: req.window.start, end: req.window.end, ...(region ? { region } : {}) },
      };
    },
  };
}

/** A clock that never waits: sleeps advance it and are recorded. */
export function fakeClock(startMs = Date.UTC(2026, 9, 5)): CollectClock & { sleeps: number[]; t: number } {
  const clock = {
    t: startMs,
    sleeps: [] as number[],
    now: () => clock.t,
    sleep: async (ms: number) => {
      clock.sleeps.push(ms);
      clock.t += ms;
    },
  };
  return clock;
}

export const denseSource = (extra: Partial<CollectSourceInfo> = {}): CollectSourceInfo => ({
  id: "ct",
  label: "CloudTrail",
  streamKind: "aws",
  ...extra,
});
