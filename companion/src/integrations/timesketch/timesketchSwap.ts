// Upload-first replace of a managed Timesketch timeline (#2414). The old flow deleted the managed
// timeline and THEN uploaded, so a network or server failure mid-upload left the analyst with no
// timeline at all. The swap now runs in three steps:
//
//   1. begin   — note the ids of the managed timelines that exist now (the managed name plus any
//                "(staging …)" leftovers of an earlier run), and pick a staging name and a unique
//                data label for this push.
//   2. upload  — the caller uploads under the staging name with that label. The unique label
//                matters: Timesketch reuses any sketch index that carries the same label, so a
//                shared label would append the new events INTO the old timeline's index.
//   3. commit  — only after every upload request was accepted: delete the noted ids, then rename
//                the staging timeline to the managed name. Or abort — on any upload failure, delete
//                the partial staging timeline (best effort) and leave the old one untouched.
//
// The swap does not wait for Timesketch to finish indexing (the user's Option B): it covers a failed
// upload request, not a background indexing failure inside Timesketch.

import { randomBytes } from "node:crypto";
import { TimesketchApiError } from "./timesketchClient.js";
import type { TimesketchTimelineRef } from "./timesketchClient.js";

/** The client calls the swap needs — a subset of TimesketchClientLike. */
export interface TimesketchSwapClient {
  listTimelines(sketchId: number): Promise<TimesketchTimelineRef[]>;
  deleteTimeline(sketchId: number, timelineId: number): Promise<void>;
  renameTimeline(
    sketchId: number,
    timelineId: number,
    name: string,
    opts?: { color?: string },
  ): Promise<void>;
}

export interface TimelineSwap {
  sketchId: number;
  timelineName: string; // the managed name the analyst sees
  stagingName: string; // what this push uploads under until the swap completes
  dataLabel: string; // unique per push, so the upload opens its OWN index
  oldIds: number[]; // managed timelines that existed before this push's upload
}

/** What the upload reported about the staging timeline it created. */
export interface StagedTimeline {
  timelineId?: number;
  color?: string;
}

export interface SwapOutcome {
  timelineName: string; // the name actually in place when the push ends
  replacedTimeline: boolean; // true only when old copies were removed AND the rename landed
}

const TIMESKETCH_NAME_MAX = 255; // TimelineForm and the upload both cap names at 255
const STAGING_TAIL = /^ \(staging [0-9a-f]{6}\)$/;

function stagingBase(timelineName: string): string {
  return timelineName.slice(0, TIMESKETCH_NAME_MAX - " (staging 000000)".length);
}

/** True for the managed name itself and for any staging leftover of it. */
export function isManagedTimeline(name: string, timelineName: string): boolean {
  if (name === timelineName) return true;
  const base = stagingBase(timelineName);
  return name.startsWith(base) && STAGING_TAIL.test(name.slice(base.length));
}

/** Step 1. A list failure is not fatal: the push still uploads, but old copies may remain. */
export async function beginSwap(
  client: TimesketchSwapClient,
  sketchId: number,
  timelineName: string,
  warnings: string[],
): Promise<TimelineSwap> {
  const tag = randomBytes(3).toString("hex");
  let oldIds: number[] = [];
  try {
    oldIds = (await client.listTimelines(sketchId))
      .filter((t) => isManagedTimeline(t.name, timelineName))
      .map((t) => t.id);
  } catch (err) {
    warnings.push(
      `timeline list: ${(err as Error).message} — an older copy of "${timelineName}" may remain next to the new one`,
    );
  }
  return {
    sketchId,
    timelineName,
    stagingName: `${stagingBase(timelineName)} (staging ${tag})`,
    dataLabel: `dfir-companion-${tag}`,
    oldIds,
  };
}

/** Abort: remove the partial staging timeline (best effort), then rethrow the upload error. */
export async function abortSwap(
  client: TimesketchSwapClient,
  swap: TimelineSwap,
  err: unknown,
): Promise<never> {
  let cleanupNote = "";
  try {
    for (const t of await client.listTimelines(swap.sketchId)) {
      if (t.name === swap.stagingName && !swap.oldIds.includes(t.id)) {
        await client.deleteTimeline(swap.sketchId, t.id);
      }
    }
  } catch (cleanupErr) {
    cleanupNote = ` (the partial staging timeline "${swap.stagingName}" could not be removed: ${(cleanupErr as Error).message}; the next push will tidy it)`;
  }
  if (!cleanupNote) throw err;
  const message = `${err instanceof Error ? err.message : String(err)}${cleanupNote}`;
  if (err instanceof TimesketchApiError) throw new TimesketchApiError(message, err.status, err.kind);
  throw new Error(message, { cause: err });
}

/** Step 3: delete the old copies, then rename the staging timeline. Failures become warnings. */
export async function commitSwap(
  client: TimesketchSwapClient,
  swap: TimelineSwap,
  staged: StagedTimeline,
  warnings: string[],
): Promise<SwapOutcome> {
  const keptAsStaging: SwapOutcome = { timelineName: swap.stagingName, replacedTimeline: false };
  if (!(await deleteOldCopies(client, swap, warnings))) {
    warnings.push(
      `the new timeline is kept under "${swap.stagingName}" because an older copy could not be removed — the next push will tidy both`,
    );
    return keptAsStaging;
  }
  const timelineId = staged.timelineId ?? (await findStaging(client, swap));
  try {
    if (timelineId === undefined) throw new Error("the staging timeline was not found in the sketch");
    await client.renameTimeline(swap.sketchId, timelineId, swap.timelineName, { color: staged.color });
  } catch (err) {
    warnings.push(
      `timeline rename: ${(err as Error).message} — the new timeline is kept under its staging name "${swap.stagingName}"; the next push will tidy it`,
    );
    return keptAsStaging;
  }
  return { timelineName: swap.timelineName, replacedTimeline: swap.oldIds.length > 0 };
}

async function deleteOldCopies(
  client: TimesketchSwapClient,
  swap: TimelineSwap,
  warnings: string[],
): Promise<boolean> {
  let allDeleted = true;
  for (const id of swap.oldIds) {
    try {
      await client.deleteTimeline(swap.sketchId, id);
    } catch (err) {
      allDeleted = false;
      warnings.push(`old timeline #${id}: ${(err as Error).message}`);
    }
  }
  return allDeleted;
}

async function findStaging(client: TimesketchSwapClient, swap: TimelineSwap): Promise<number | undefined> {
  try {
    return (await client.listTimelines(swap.sketchId)).find((t) => t.name === swap.stagingName)?.id;
  } catch {
    return undefined; // the rename step reports the missing id as its warning
  }
}
