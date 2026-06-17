import type { CompanionClient } from "./companionClient.js";
import type { CaptureQueue } from "./captureQueue.js";
import type { CapturePayload, ConnectionStatus, TriggerType } from "./types.js";

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
      // Online: opportunistically drain anything queued during an outage.
      await this.queue.drain((p) => this.client.postCapture(p).then((r) => r.ok));
      return { online: true, queued: await this.queue.size() };
    }

    // The companion responded but rejected the capture (4xx — typically 404, the case
    // doesn't exist, or 423 — the case is closed). Retrying won't help, so don't queue.
    if (result.status >= 400 && result.status < 500) {
      return { online: true, queued: await this.queue.size(), rejected: result.status, rejectedMessage: result.errorMessage };
    }

    // Transient failure (unreachable / 5xx) — queue for retry when the companion is back.
    await this.queue.enqueue(payload);
    return { online: false, queued: await this.queue.size() };
  }
}
