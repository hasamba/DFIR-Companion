import type { HuntEventPage, HuntEventSource, HuntSourceRequest } from "./huntQueryExecutor.js";
import type { StateStore } from "./stateStore.js";
import type { SuperTimelineStore } from "./superTimelineStore.js";

export class SqliteHuntEventSource implements HuntEventSource {
  constructor(
    private readonly stateStore: StateStore,
    private readonly superTimelineStore?: SuperTimelineStore,
  ) {}

  async readPage(request: HuntSourceRequest): Promise<HuntEventPage> {
    const query = {
      cursor: request.cursor ?? undefined,
      limit: request.limit,
      ...request.plan,
      includeTotal: false,
    };
    if (request.dataset === "forensic") {
      const page = await this.stateStore.queryForensicTimeline(request.caseId, query);
      return { events: page.entities, nextCursor: page.nextCursor };
    }
    if (!this.superTimelineStore) {
      throw new Error("super-timeline is not configured");
    }
    const page = await this.superTimelineStore.queryIndexed(request.caseId, query);
    return { events: page.entities, nextCursor: page.nextCursor };
  }
}
