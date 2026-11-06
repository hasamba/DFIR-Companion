// The GuardDuty findings source (#2361): findings updated inside the window, region by region, in
// every region where the account has a GuardDuty detector. Read-only: ListDetectors, ListFindings,
// GetFindings — the optional GuardDuty statement of the minimum policy.
//
// REGIONS. Findings are regional and the minimum policy grants no region listing, so the walk asks
// a fixed list: the account's own region, AWS's default regions and the opt-in commercial regions
// (GUARDDUTY_REGIONS). A region that answers "not enabled for this account" cannot hold a detector:
// for this source that is not a skip and does not make the collection partial — it is named in the
// page's `regionsNotEnabled`. A region with no detector (GuardDuty off there) is named in
// `noDetectorRegions`. A transport failure is never read as either: it fails the window with its
// page token kept, so Resume carries on from the same page.
//
// THE PAGE BODY is `{"Findings":[…]}` — GetFindings' findings as the AWS SDK returns them, the
// shape `aws guardduty get-findings` prints and the GuardDuty importer reads. It is the SDK's JSON,
// not the wire bytes, and `requestParams.adaptation` says so on every page.
//
// SELECTION is by the finding's last update time (`updatedAt`, ≥ start, < end), archived findings
// included. GetFindings returns each finding as it is NOW: one updated again between the two calls is
// kept (counted in `updatedAfterWindow`; its observation key makes a later window's copy a
// duplicate), and an id listed but not returned (expired in between) is counted in `notReturned`.
//
// The token is `{r: region, d: detectorId, n: NextToken}`. A region with no finding in the window is
// not saved as a page of its own — the walk goes on — except the last, which closes the source.

import { GetFindingsCommand, ListDetectorsCommand, ListFindingsCommand } from "@aws-sdk/client-guardduty";
import { DEFAULT_AWS_REGION } from "../../cloudTransport/awsCredentials.js";
import { CursorExpiredError, type CollectPage, type CollectPageRequest } from "../collectTypes.js";
import {
  awsReason,
  DEFAULT_AWS_REGIONS,
  errorName,
  regionOff,
  sendAws,
  type AwsCollectClients,
} from "./awsCollectTypes.js";

export const GUARDDUTY_ADAPTATION =
  'GetFindings Findings[] as the AWS SDK returns them, saved as a {"Findings":[...]} document';
const PAGE_SIZE = 50; // ListFindings' and GetFindings' maximum

/** The opt-in commercial regions: off unless the account enabled them; a disabled one says so. */
export const OPT_IN_AWS_REGIONS = [
  "af-south-1",
  "ap-east-1",
  "ap-south-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ap-southeast-5",
  "ap-southeast-7",
  "ca-west-1",
  "eu-central-2",
  "eu-south-1",
  "eu-south-2",
  "il-central-1",
  "me-central-1",
  "me-south-1",
  "mx-central-1",
] as const;

/** A region outside the commercial partition (China, GovCloud, ISO) is asked alone. */
const OTHER_PARTITION = /^(?:cn-|us-gov-|us-iso)/;

/** The regions the GuardDuty walk asks: the account's own first, then every commercial region. */
export function guardDutyRegions(accountRegion?: string): string[] {
  const own = accountRegion || DEFAULT_AWS_REGION;
  if (OTHER_PARTITION.test(own)) return [own];
  return [...new Set([own, ...DEFAULT_AWS_REGIONS, ...OPT_IN_AWS_REGIONS])];
}

interface GdToken {
  r: string;
  d?: string;
  n?: string;
}

interface ListOut {
  FindingIds?: string[];
  NextToken?: string;
  $metadata?: { requestId?: string };
}

type Finding = Record<string, unknown>;

/** A GuardDuty refusal or a stale token, in words the result can show. */
function guardDutyError(err: unknown): unknown {
  const name = errorName(err);
  const message = String((err as { message?: unknown })?.message ?? "");
  if (name === "BadRequestException" && /token/i.test(message))
    return new CursorExpiredError("GuardDuty NextToken no longer accepted");
  if (name === "AccessDeniedException" || name === "AccessDenied")
    return new Error(
      `GuardDuty read refused (${awsReason(err)}): grant the GuardDuty statement of the minimum policy ` +
        "(guardduty:ListDetectors, ListFindings, GetFindings)",
    );
  return err;
}

async function gd<T>(clients: AwsCollectClients, region: string, command: object, signal?: AbortSignal) {
  try {
    return await sendAws<T>(clients.guardduty(region), command, signal);
  } catch (err) {
    throw guardDutyError(err);
  }
}

function parseToken(regions: readonly string[], token?: string): { index: number; d?: string; n?: string } {
  if (!token) return { index: 0 };
  let t: GdToken;
  try {
    t = JSON.parse(token) as GdToken;
  } catch {
    throw new CursorExpiredError("unreadable GuardDuty token");
  }
  const index = regions.indexOf(t.r);
  if (index < 0) throw new CursorExpiredError("the region list changed");
  return { index, ...(t.d ? { d: t.d } : {}), ...(t.n ? { n: t.n } : {}) };
}

const tokenFor = (region: string, detector?: string, next?: string): string =>
  JSON.stringify({ r: region, ...(detector ? { d: detector } : {}), ...(next ? { n: next } : {}) });

/** The region's detector id; null when GuardDuty is off there; "off" when the region is not enabled. */
async function detectorOf(
  clients: AwsCollectClients,
  region: string,
  signal?: AbortSignal,
): Promise<{ id: string | null; extra: string[] } | "off"> {
  try {
    const out = await sendAws<{ DetectorIds?: string[] }>(
      clients.guardduty(region),
      new ListDetectorsCommand({}),
      signal,
    );
    const ids = (out.DetectorIds ?? []).filter((d) => typeof d === "string" && d);
    return { id: ids[0] ?? null, extra: ids.slice(1) };
  } catch (err) {
    if (regionOff(err)) return "off";
    throw guardDutyError(err);
  }
}

interface WalkNotes {
  notEnabled: string[];
  noDetector: string[];
  empty: string[];
  extraDetectors: string[];
}

function pageOf(
  request: CollectPageRequest,
  region: string,
  detector: string,
  findings: Finding[],
  listed: number,
  list: ListOut | undefined,
  notes: WalkNotes,
  nextPageToken: string | undefined,
): CollectPage {
  const end = Date.parse(request.window.end);
  const later = findings.filter((f) => Date.parse(String(f.UpdatedAt ?? "")) >= end).length;
  const list2 = (k: keyof WalkNotes, label: string) =>
    notes[k].length ? { [label]: notes[k].join(",") } : {};
  return {
    body: Buffer.from(JSON.stringify({ Findings: findings }), "utf8"),
    extension: "json",
    recordCount: findings.length,
    ...(nextPageToken ? { nextPageToken } : {}),
    ...(list?.$metadata?.requestId ? { requestId: list.$metadata.requestId } : {}),
    requestParams: {
      api: "guardduty:ListFindings+GetFindings",
      region,
      ...(detector ? { detectorId: detector } : {}),
      criterion: "updatedAt >= startTime and < endTime",
      startTime: request.window.start,
      endTime: request.window.end,
      maxResults: String(PAGE_SIZE),
      listed: String(listed),
      fetched: String(findings.length),
      ...(listed > findings.length ? { notReturned: String(listed - findings.length) } : {}),
      ...(later ? { updatedAfterWindow: String(later) } : {}),
      adaptation: GUARDDUTY_ADAPTATION,
      ...list2("notEnabled", "regionsNotEnabled"),
      ...list2("noDetector", "noDetectorRegions"),
      ...list2("empty", "emptyRegions"),
      ...list2("extraDetectors", "otherDetectors"),
    },
  };
}

async function listPage(
  clients: AwsCollectClients,
  region: string,
  detector: string,
  request: CollectPageRequest,
  next?: string,
): Promise<{ list: ListOut; findings: Finding[] }> {
  const list = await gd<ListOut>(
    clients,
    region,
    new ListFindingsCommand({
      DetectorId: detector,
      FindingCriteria: {
        Criterion: {
          updatedAt: {
            GreaterThanOrEqual: Date.parse(request.window.start),
            LessThan: Date.parse(request.window.end),
          },
        },
      },
      SortCriteria: { AttributeName: "updatedAt", OrderBy: "ASC" },
      MaxResults: PAGE_SIZE,
      ...(next ? { NextToken: next } : {}),
    }),
    request.signal,
  );
  const ids = (list.FindingIds ?? []).filter((id) => typeof id === "string" && id);
  if (!ids.length) return { list, findings: [] };
  const got = await gd<{ Findings?: Finding[] }>(
    clients,
    region,
    new GetFindingsCommand({ DetectorId: detector, FindingIds: ids }),
    request.signal,
  );
  return { list: { ...list, FindingIds: ids }, findings: got.Findings ?? [] };
}

/** One GuardDuty findings page, walking on past regions with nothing to save. */
export async function fetchGuardDutyPage(
  clients: AwsCollectClients,
  allRegions: readonly string[],
  request: CollectPageRequest,
): Promise<CollectPage> {
  const only = request.partition?.region;
  const regions = only ? [only] : allRegions;
  let { index, d, n } = parseToken(regions, request.pageToken);
  const notes: WalkNotes = { notEnabled: [], noDetector: [], empty: [], extraDetectors: [] };
  for (;;) {
    const region = regions[index];
    const following = regions[index + 1];
    let detector = d;
    if (!detector) {
      const found = await detectorOf(clients, region, request.signal);
      if (found === "off") notes.notEnabled.push(region);
      else if (!found.id) notes.noDetector.push(region);
      else {
        detector = found.id;
        notes.extraDetectors.push(...found.extra.map((x) => `${region}:${x}`));
      }
    }
    if (!detector) {
      if (!following) return pageOf(request, region, "", [], 0, undefined, notes, undefined);
      index++;
      d = n = undefined;
      continue;
    }
    const { list, findings } = await listPage(clients, region, detector, request, n);
    const listed = list.FindingIds?.length ?? 0;
    const nextPageToken = list.NextToken
      ? tokenFor(region, detector, list.NextToken)
      : following
        ? tokenFor(following)
        : undefined;
    if (!listed && !list.NextToken && following) {
      notes.empty.push(region);
      index++;
      d = n = undefined;
      continue;
    }
    return pageOf(request, region, detector, findings, listed, list, notes, nextPageToken);
  }
}
