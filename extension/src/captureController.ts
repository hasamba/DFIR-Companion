import type { CompanionClient } from "./companionClient.js";
import type { CaptureQueue, QueueSendResult } from "./captureQueue.js";
import type { CapturePayload, ConnectionStatus, TriggerType } from "./types.js";

// Is this HTTP status worth retrying later? A 4xx is normally the companion's considered answer
// about THIS capture (404 case gone, 423 case closed, 410 deleted) and will say the same thing
// tomorrow, so a queued capture that gets one must be discarded rather than retried forever.
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
      const drained = await this.queue.drain(async (p): Promise<QueueSendResult> => {
        const r = await this.client.postCapture(p);
        if (r.ok) return { outcome: "sent" };
        return {
          outcome: isPermanent(r.status) ? "drop" : "retry",
          status: r.status,
          ...(r.errorMessage ? { errorMessage: r.errorMessage } : {}),
        };
      });
      return {
        online: true,
        queued: await this.queue.size(),
        ...(drained.dropped.length ? { dropped: drained.dropped } : {}),
      };
    }

    // The companion responded but rejected the capture (4xx — typically 404, the case
    // doesn't exist, or 423 — the case is closed). Retrying won't help, so don't queue.
    // 408/429 are not rejections and fall through to the queue below (#2174).
    if (isPermanent(result.status)) {
      return { online: true, queued: await this.queue.size(), rejected: result.status, rejectedMessage: result.errorMessage };
    }

    // Transient failure (unreachable / 5xx / 408 / 429) — queue for retry when the companion is back.
    await this.queue.enqueue(payload);
    return { online: false, queued: await this.queue.size() };
  }
}
