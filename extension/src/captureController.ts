import type { CompanionClient } from "./companionClient.js";
import type { CaptureQueue, QueueSendResult } from "./captureQueue.js";
import type { CapturePayload, ConnectionStatus, TriggerType } from "./types.js";
import { isLockedRejection } from "./casePasswordSession.js";
import { isHeldRefusal, isKeptQueuedRefusal } from "./captureRefusal.js";

// Is this HTTP status worth retrying later? A 4xx is normally the companion's considered answer
// about THIS capture (404 case gone, 423 case closed, 410 deleted) and will say the same thing
// tomorrow, so a queued capture that gets one must be discarded rather than retried forever.
// Refusals about WHO is asking (401/403, team auth's access-denied 404) are not such an answer —
// see captureRefusal.ts (#2254) — and are classified before this check.
// The exceptions are 408 (request timeout) and 429 (rate limited — e.g. a case-password lockout,
// which rejects even a valid capture until the window passes): those mean "try again later", so
// they are transient like 5xx and 0 for "fetch threw / companion unreachable" (#215, #2174).
const TRANSIENT_4XX: ReadonlySet<number> = new Set([408, 429]);

function isPermanent(status: number): boolean {
  return status >= 400 && status < 500 && !TRANSIENT_4XX.has(status);
}

export interface TabSnapshot {
  url: string;
  tabTitle: string;
  imageBase64: string;
}

export class CaptureController {
  constructor(private readonly client: CompanionClient, private readonly queue: CaptureQueue) {}

  async capture(caseId: string, trigger: TriggerType, snapshot: TabSnapshot): Promise<ConnectionStatus> {
    const payload: CapturePayload = {
      caseId,
      timestamp: new Date().toISOString(),
      url: snapshot.url,
      tabTitle: snapshot.tabTitle,
      triggerType: trigger,
      imageBase64: snapshot.imageBase64,
    };

    const result = await this.client.postCapture(payload);

    if (result.ok) {
      // Online: opportunistically drain anything queued during an outage. Each queued capture is
      // classified rather than reduced to a boolean, so one that has become permanently
      // unsendable is discarded (and reported) instead of blocking the queue behind it.
      // A locked answer here is always for ANOTHER case: a queued capture for the selected case
      // carries the same, just-accepted password. Record which case, for the amber badge (#2185).
      let lockedQueuedCaseId: string | undefined;
      const drained = await this.queue.drain(async (p): Promise<QueueSendResult> => {
        const r = await this.client.postCapture(p);
        if (r.ok) return { outcome: "sent" };
        // Still waiting for its case password (#2135) — keep it, never drop evidence for this.
        if (isLockedRejection(r.status, r.errorMessage)) {
          lockedQueuedCaseId = p.caseId;
          return { outcome: "retry", status: r.status };
        }
        const detail = {
          status: r.status,
          ...(r.errorMessage ? { errorMessage: r.errorMessage } : {}),
          ...(r.errorCode ? { errorCode: r.errorCode } : {}),
        };
        // Refused for access (e.g. a capture for the old case after a token switch) — keep it, and
        // SKIP rather than retry, so the valid captures behind it still go out (#2254, #215).
        if (isKeptQueuedRefusal(r.status, r.errorMessage, r.errorCode)) return { outcome: "skip", ...detail };
        return { outcome: isPermanent(r.status) ? "drop" : "retry", ...detail };
      });
      return {
        online: true,
        queued: await this.queue.size(),
        ...(drained.dropped.length ? { dropped: drained.dropped } : {}),
        ...(drained.kept.length ? { kept: drained.kept } : {}),
        ...(lockedQueuedCaseId ? { lockedQueuedCaseId } : {}),
      };
    }

    // The case is password-locked and the capture carried no (or a wrong) password (#2135). Not a
    // verdict on the screenshot: queue it, so it uploads once the analyst enters the password.
    if (isLockedRejection(result.status, result.errorMessage)) {
      return this.keep(payload, { online: true, locked: true });
    }

    // Refused for WHO is asking — a missing/rotated service token (401), a case role that cannot
    // capture (403) — or a capture log that needs repair (409, #2252). Not a verdict on the
    // screenshot: keep it, so it uploads once the analyst fixes the token / role / log (#2254).
    if (isHeldRefusal(result.status, result.errorMessage, result.errorCode)) {
      return this.keep(payload, {
        online: true,
        held: result.status,
        ...(result.errorMessage ? { heldMessage: result.errorMessage } : {}),
        ...(result.errorCode ? { heldCode: result.errorCode } : {}),
      });
    }

    // The companion responded but rejected the capture (4xx — typically 404, the case
    // doesn't exist, or 423 — the case is closed). Retrying won't help, so don't queue.
    // 408/429 are not rejections and fall through to the queue below (#2174).
    if (isPermanent(result.status)) {
      return { online: true, queued: await this.queue.size(), rejected: result.status, rejectedMessage: result.errorMessage };
    }

    // Transient failure (unreachable / 5xx / 408 / 429) — queue for retry when the companion is back.
    return this.keep(payload, { online: false });
  }

  /**
   * Queue the capture and report `status` with the new queue size. A failed queue write (quota,
   * aborted transaction) is REPORTED, never thrown: automatic triggers call capture() with `void`,
   * so a rejection went unhandled and the screenshot vanished without a trace (#2256).
   */
  private async keep(payload: CapturePayload, status: Omit<ConnectionStatus, "queued">): Promise<ConnectionStatus> {
    try {
      await this.queue.enqueue(payload);
      return { ...status, queued: await this.queue.size() };
    } catch (err) {
      // `locked` is kept so a refused case password is still forgotten (#2135); `held` is not —
      // nothing is waiting in the queue for the token / role to be fixed.
      return {
        online: status.online,
        queued: await this.queue.size().catch(() => 0),
        ...(status.locked ? { locked: true } : {}),
        queueWriteFailed: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
