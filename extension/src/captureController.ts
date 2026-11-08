import type { CompanionClient } from "./companionClient.js";
import type { CaptureQueue, QueueSendResult } from "./captureQueue.js";
import type { CapturePayload, ConnectionStatus, DroppedCapture, TriggerType } from "./types.js";
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

/** What one drain of the offline queue did, for the badge and the popup (#2396). */
export interface QueueDrainStatus {
  queued: number;
  sent: number;
  dropped: DroppedCapture[];
  kept: DroppedCapture[];
  elsewhere: number;
  lockedQueuedCaseId?: string;
  credentialRefused: boolean;
  /** Another drain was already running; this one did nothing. */
  busy?: boolean;
  /** The drain stopped on an error part-way; what it did before is still reported. */
  error?: string;
  /** The status that stopped the drain; 0 means the companion could not be reached. */
  stoppedStatus?: number;
}

export interface CaptureControllerHooks {
  /**
   * Runs once a capture is durably queued and BEFORE it is uploaded (#2396): the worker uses it to
   * make sure a retry is scheduled even if it is suspended while the upload is still open.
   */
  onQueued?: () => Promise<void>;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export class CaptureController {
  constructor(
    private readonly client: CompanionClient,
    private readonly queue: CaptureQueue,
    private readonly hooks: CaptureControllerHooks = {},
  ) {}

  /**
   * Upload one capture. It is written to the offline queue FIRST (#2396) and removed only once the
   * companion has accepted it or refused it for good — a capture used to be queued only after its
   * upload failed, so a worker suspended mid-upload lost it without a trace.
   */
  async capture(caseId: string, trigger: TriggerType, snapshot: TabSnapshot): Promise<ConnectionStatus> {
    const payload: CapturePayload = {
      caseId,
      timestamp: new Date().toISOString(),
      url: snapshot.url,
      tabTitle: snapshot.tabTitle,
      triggerType: trigger,
      imageBase64: snapshot.imageBase64,
    };

    let key: number | undefined;
    let writeError: string | undefined;
    try {
      key = await this.queue.enqueue(payload, { companionUrl: this.client.companionUrl, live: true });
    } catch (err) {
      // Quota, an aborted transaction, or the queue cap. The upload is still tried — a capture the
      // companion accepts is not lost — and the failure is reported only if it had to be kept.
      writeError = errorText(err);
    }
    try {
      if (key !== undefined) await this.hooks.onQueued?.().catch(() => undefined);
      return await this.upload(payload, key, writeError);
    } finally {
      if (key !== undefined) this.queue.endLive(key);
    }
  }

  private async upload(payload: CapturePayload, key: number | undefined, writeError?: string): Promise<ConnectionStatus> {
    const result = await this.client.postCapture(payload);

    if (result.ok) {
      await this.forget(key);
      // Online: drain anything queued during an outage.
      // drainQueue reports a part-way failure in its result; only a failure before it did anything
      // (the queue could not be opened) lands here, and that is reported too.
      const drained = await this.drainQueue().catch((err: unknown) => ({ error: errorText(err) }) as Partial<QueueDrainStatus>);
      const queued = drained.queued ?? (await this.queue.size().catch(() => 0));
      return {
        online: true,
        queued,
        ...(drained.dropped?.length ? { dropped: drained.dropped } : {}),
        ...(drained.kept?.length ? { kept: drained.kept } : {}),
        ...(drained.elsewhere ? { queuedElsewhere: drained.elsewhere } : {}),
        ...(drained.lockedQueuedCaseId ? { lockedQueuedCaseId: drained.lockedQueuedCaseId } : {}),
        ...(drained.credentialRefused ? { credentialRefused: true } : {}),
        ...(drained.error ? { queueDrainError: drained.error } : {}),
      };
    }

    // The case is password-locked and the capture carried no (or a wrong) password (#2135). Not a
    // verdict on the screenshot: keep it queued, so it uploads once the analyst enters the password.
    if (isLockedRejection(result.status, result.errorMessage)) {
      return this.kept(key, writeError, { online: true, locked: true });
    }

    // Refused for WHO is asking — a missing/rotated service token (401), a case role that cannot
    // capture (403) — or a capture log that needs repair (409, #2252). Not a verdict on the
    // screenshot: keep it, so it uploads once the analyst fixes the token / role / log (#2254).
    if (isHeldRefusal(result.status, result.errorMessage, result.errorCode)) {
      return this.kept(key, writeError, {
        online: true,
        held: result.status,
        ...(result.errorMessage ? { heldMessage: result.errorMessage } : {}),
        ...(result.errorCode ? { heldCode: result.errorCode } : {}),
      });
    }

    // The companion responded but rejected the capture (4xx — typically 404, the case
    // doesn't exist, or 423 — the case is closed). Retrying won't help, so don't keep it.
    // 408/429 are not rejections and fall through to the queue below (#2174).
    if (isPermanent(result.status)) {
      await this.forget(key);
      return {
        online: true,
        queued: await this.queue.size().catch(() => 0),
        rejected: result.status,
        rejectedMessage: result.errorMessage,
      };
    }

    // Transient failure (unreachable / timed out / 5xx / 408 / 429) — it stays queued for retry.
    return this.kept(key, writeError, { online: false });
  }

  /** Remove the capture's queue row once it no longer needs keeping. */
  private async forget(key: number | undefined): Promise<void> {
    if (key === undefined) return;
    // A row that cannot be removed is re-sent by a later drain: a duplicate, never a loss.
    await this.queue.remove(key).catch((err: unknown) => {
      console.error("[dfir] could not remove a delivered capture from the queue", err);
    });
  }

  /**
   * Report a capture that must wait. It is already in the queue unless the write-ahead failed;
   * that failure is REPORTED, never thrown (#2256): the screenshot is not saved anywhere.
   */
  private async kept(
    key: number | undefined,
    writeError: string | undefined,
    status: Omit<ConnectionStatus, "queued">,
  ): Promise<ConnectionStatus> {
    const queued = await this.queue.size().catch(() => 0);
    if (key !== undefined) return { ...status, queued };
    // `locked` is kept so a refused case password is still forgotten (#2135); `held` is not —
    // nothing is waiting in the queue for the token / role to be fixed.
    return {
      online: status.online,
      queued,
      ...(status.locked ? { locked: true } : {}),
      queueWriteFailed: writeError ?? "the capture could not be queued",
    };
  }

  /**
   * Send what the offline queue holds to this client's companion. Each queued capture is classified
   * rather than reduced to a boolean, so one that has become permanently unsendable is discarded
   * (and reported) instead of blocking the queue behind it. Runs after a successful capture AND on
   * its own schedule (#2396).
   */
  async drainQueue(): Promise<QueueDrainStatus> {
    let lockedQueuedCaseId: string | undefined;
    let credentialRefused = false;
    const drained = await this.queue.drain(async (p): Promise<QueueSendResult> => {
      const r = await this.client.postCapture(p);
      if (r.ok) return { outcome: "sent" };
      // Still waiting for its case password (#2135) — keep it, never drop evidence for this.
      if (isLockedRejection(r.status, r.errorMessage)) {
        lockedQueuedCaseId = p.caseId;
        // It carried the stored password and was still refused: that password is wrong (#2396).
        if (this.client.sendsCredentialFor(p.caseId)) credentialRefused = true;
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
    }, { companionUrl: this.client.companionUrl });
    let queued = 0;
    let error = drained.error;
    try {
      queued = await this.queue.size();
    } catch (err) {
      error = error ?? errorText(err);
    }
    return {
      queued,
      sent: drained.sent,
      dropped: drained.dropped,
      kept: drained.kept,
      elsewhere: drained.elsewhere,
      credentialRefused,
      ...(lockedQueuedCaseId ? { lockedQueuedCaseId } : {}),
      ...(drained.stoppedStatus !== undefined ? { stoppedStatus: drained.stoppedStatus } : {}),
      ...(drained.busy ? { busy: true } : {}),
      ...(error ? { error } : {}),
    };
  }
}
