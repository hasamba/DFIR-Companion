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

    const ok = await this.client.postCapture(payload);
    if (!ok) {
      await this.queue.enqueue(payload);
      return { online: false, queued: await this.queue.size() };
    }

    // Online: opportunistically drain anything queued during an outage.
    await this.queue.drain((p) => this.client.postCapture(p));
    return { online: true, queued: await this.queue.size() };
  }
}
