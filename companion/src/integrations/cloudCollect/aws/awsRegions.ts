// The regions an AWS collection walks (#2363): the regions enabled on the account, asked with the
// read-only `ec2:DescribeRegions` (AllRegions=false — opt-in regions the account turned on are
// listed too), minus what the analyst unticked in the panel's region picker.
//
// Without the permission (or on any other failure to list) the companion falls back to the list it
// used before #2363 — the account's own region and the regions AWS enables by default — and says so,
// in the picker, the pre-check and the result. Never silent.
//
// The scope a collection walks is decided ONCE, at start, and written to the manifest header's
// `filters` (FILTER_* below), so a Resume walks exactly the same regions: the LookupEvents page
// token names its region, and a region list that changed would restart the window.

import { DescribeRegionsCommand } from "@aws-sdk/client-ec2";
import type { AwsSettings } from "../../cloudAccounts/types.js";
import { DEFAULT_AWS_REGION } from "../../cloudTransport/awsCredentials.js";
import type { CollectRegionChoice, CollectRegionListing } from "../collectTypes.js";
import { awsReason, DEFAULT_AWS_REGIONS, httpStatus, sendAws, type AwsSender } from "./awsCollectTypes.js";

/** An AWS region name: `us-east-1`, `ap-southeast-5`, `us-gov-west-1`. */
export const AWS_REGION_NAME = /^[a-z]{2}(-[a-z]+)+-\d{1,2}$/;

export const REGION_LIST_API = "ec2:DescribeRegions";

/** The manifest header filters an AWS collection records its region scope in. */
export const FILTER_REGIONS = "regions";
export const FILTER_SKIPPED_BY_CHOICE = "regionsSkippedByChoice";
export const FILTER_NO_LONGER_ENABLED = "regionsNoLongerEnabled";
export const FILTER_REGION_LIST = "regionList";
export const FILTER_REGION_LIST_REASON = "regionListReason";

const ENABLED_STATUS = new Set(["opt-in-not-required", "opted-in"]);

/** The list before #2363: the account's own region, then the regions AWS enables by default. */
export function fallbackRegions(settings: AwsSettings): string[] {
  return [...new Set([settings.region || DEFAULT_AWS_REGION, ...DEFAULT_AWS_REGIONS])];
}

/** The account's own region first, then the rest sorted; each once. Pure. */
export function orderRegions(home: string, regions: readonly string[]): string[] {
  const set = new Set(regions);
  const rest = [...set].filter((r) => r !== home).sort();
  return set.has(home) ? [home, ...rest] : rest;
}

/** The disclosure for a fallback list, with the reason AWS gave. */
export function fallbackNote(reason: string): string {
  return (
    `The regions enabled on this account could not be listed (${reason}) — grant ${REGION_LIST_API}. ` +
    "The default region list was used instead (the account's own region and the regions AWS enables " +
    "by default), so an opt-in region enabled on this account may be missing from it."
  );
}

function failureReason(err: unknown): string {
  if (httpStatus(err) !== undefined) return awsReason(err);
  const message = err instanceof Error ? err.message : String(err);
  return message.slice(0, 160) || "error";
}

function fallback(settings: AwsSettings, reason: string): CollectRegionListing {
  const home = settings.region || DEFAULT_AWS_REGION;
  return {
    regions: fallbackRegions(settings),
    home,
    source: "fallback",
    reason,
    note: fallbackNote(reason),
  };
}

interface DescribeRegionsOut {
  Regions?: { RegionName?: unknown; OptInStatus?: unknown }[];
}

/** The regions enabled on the account, or the fallback list with its disclosure. Throws only on cancel. */
export async function listEnabledRegions(
  ec2: AwsSender,
  settings: AwsSettings,
  signal?: AbortSignal,
): Promise<CollectRegionListing> {
  const home = settings.region || DEFAULT_AWS_REGION;
  let out: DescribeRegionsOut;
  try {
    out = await sendAws<DescribeRegionsOut>(ec2, new DescribeRegionsCommand({ AllRegions: false }), signal);
  } catch (err) {
    if (signal?.aborted) throw err;
    return fallback(settings, failureReason(err));
  }
  const names = (out.Regions ?? [])
    .filter((r) => typeof r.OptInStatus !== "string" || ENABLED_STATUS.has(r.OptInStatus))
    .map((r) => r.RegionName)
    .filter((n): n is string => typeof n === "string" && AWS_REGION_NAME.test(n));
  if (!names.length) return fallback(settings, "DescribeRegions listed no region");
  return { regions: orderRegions(home, names), home, source: REGION_LIST_API };
}

const csv = (list: readonly string[]): string => list.join(",");

/**
 * The header filters for a start, from the start-time listing and the analyst's picker. Pure.
 *
 * walked = ticked ∪ (listed − unticked). Only what the analyst UNTICKED is "skipped by choice": a
 * region listed now but not shown in the picker (the picker had the fallback list) is walked. A
 * ticked region a successful listing no longer names is not called (it is off, or not a region) and
 * is named in the result; against a fallback listing a ticked region is kept — the picker's listing
 * may have been the real one.
 */
export function regionScope(
  listing: CollectRegionListing,
  choice: CollectRegionChoice,
): Record<string, string> {
  const unticked = new Set(choice.excludeRegions ?? []);
  const listed = new Set(listing.regions);
  const ticked = (choice.regions ?? []).filter((r) => !unticked.has(r));
  const verified = listing.source === REGION_LIST_API;
  const noLonger = verified ? ticked.filter((r) => !listed.has(r)) : [];
  // The listing's own order (account region first), then any ticked region it does not name.
  const walked = [
    ...new Set([
      ...listing.regions.filter((r) => !unticked.has(r)),
      ...ticked.filter((r) => !noLonger.includes(r)),
    ]),
  ];
  if (!walked.length)
    throw new Error("No region is left to collect: every region was unticked or is no longer enabled.");
  const skipped = orderRegions(listing.home, [...unticked]);
  return {
    [FILTER_REGIONS]: csv(walked),
    [FILTER_REGION_LIST]: listing.source,
    ...(listing.reason ? { [FILTER_REGION_LIST_REASON]: listing.reason } : {}),
    ...(skipped.length ? { [FILTER_SKIPPED_BY_CHOICE]: csv(skipped) } : {}),
    ...(noLonger.length ? { [FILTER_NO_LONGER_ENABLED]: csv(orderRegions(listing.home, noLonger)) } : {}),
  };
}

export const splitRegions = (value: string | undefined): string[] =>
  (value ?? "").split(",").filter((r) => AWS_REGION_NAME.test(r));

/** The result's region sentences from the header filters; empty for a collection without a scope. Pure. */
export function regionScopeNotes(filters: Readonly<Record<string, string>>): string[] {
  const notes: string[] = [];
  const skipped = splitRegions(filters[FILTER_SKIPPED_BY_CHOICE]);
  if (skipped.length) notes.push(`Regions skipped by choice (unticked): ${skipped.join(", ")}.`);
  const gone = splitRegions(filters[FILTER_NO_LONGER_ENABLED]);
  if (gone.length)
    notes.push(
      `Ticked but not enabled on the account when the collection started, not collected: ${gone.join(", ")}.`,
    );
  if (filters[FILTER_REGION_LIST] === "fallback")
    notes.push(fallbackNote(filters[FILTER_REGION_LIST_REASON] || "unknown error"));
  return notes;
}
