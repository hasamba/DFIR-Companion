// #2400: an abandoned panel request must never leave the tag list locked.
//
// The case load (and the reconnect catch-up) hands an ABANDONED request a promise that never
// settles, so its loader draws nothing. loadTags used to release its one-fetch-at-a-time lock only
// when its request settled, so one cancelled or switched-away case load left tags — and stars, which
// are tags — frozen for the rest of the session, in every case. runPanelLoaders now announces an
// abandonment and the tag module drops its lock.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface TagsApi {
  loadTags(caseId: string): void;
  tagsForTarget(key: string): unknown[];
}

const ABANDONED = "dfir:panel-requests-abandoned";

function harness() {
  const urls: string[] = [];
  const pending: Array<(list: unknown[]) => void> = [];
  const listeners: Record<string, Array<() => void>> = {};
  const api = loadDashboardModule<TagsApi>("dashboard-tags.js", ["dashboard-state.js"], {
    targetKey: (type: string, id: string) => `${type}:${id}`,
    deriveStarred: () => {},
    migrateLocalStars: () => {},
    render: () => {},
    addEventListener: (type: string, fn: () => void) => {
      (listeners[type] ||= []).push(fn);
    },
    fetch: (url: string) => {
      urls.push(url);
      return new Promise((resolve) =>
        pending.push((list) => resolve({ ok: true, headers: { get: () => "0:0" }, json: async () => list })),
      );
    },
  });
  const abandon = () => (listeners[ABANDONED] || []).forEach((fn) => fn());
  return { api, urls, pending, abandon };
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const tag = (id: string) => ({ targetType: "event", targetId: id, tag: "x" });

describe("tags after an abandoned load (#2400)", () => {
  it("an abandoned fetch no longer blocks the next case's tags", async () => {
    const { api, urls, abandon } = harness();
    api.loadTags("A"); // this one is abandoned — its promise never settles
    abandon();
    api.loadTags("B");
    expect(urls).toEqual(["/cases/A/tags", "/cases/B/tags"]);
  });

  it("the same case can be reloaded after its load was cancelled", async () => {
    const { api, urls, abandon } = harness();
    api.loadTags("A");
    abandon();
    api.loadTags("A");
    expect(urls).toEqual(["/cases/A/tags", "/cases/A/tags"]);
  });

  it("a stale fetch that does settle neither paints, unlocks, nor steals the trailing fetch", async () => {
    const { api, urls, pending, abandon } = harness();
    api.loadTags("A");
    abandon();
    api.loadTags("B"); // in flight, holds the lock
    api.loadTags("B"); // queued as the trailing fetch
    expect(urls).toHaveLength(2);
    pending[0]([tag("from-A")]); // A's old answer arrives late
    await settle();
    expect(api.tagsForTarget("event:from-A")).toEqual([]);
    expect(urls).toHaveLength(2); // B is still in flight: no extra fetch, the trailing one still owed
    pending[1]([tag("from-B")]);
    await settle();
    expect(api.tagsForTarget("event:from-B")).toHaveLength(1);
    expect(urls).toEqual(["/cases/A/tags", "/cases/B/tags", "/cases/B/tags"]);
  });
});
