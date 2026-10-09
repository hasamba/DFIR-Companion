// #2059: every tag change broadcasts tags_changed, and each one made every open dashboard re-read the
// tag list — a bulk star of N events meant N full reloads per dashboard. A burst now costs at most the
// fetch in flight plus one trailing fetch.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface TagsApi {
  loadTags(caseId: string): void;
}

function harness() {
  const urls: string[] = [];
  const pending: Array<() => void> = [];
  const api = loadDashboardModule<TagsApi>("dashboard-tags.js", ["dashboard-state.js"], {
    targetKey: (type: string, id: string) => `${type}:${id}`,
    deriveStarred: () => {},
    migrateLocalStars: () => {},
    render: () => {},
    fetch: (url: string) => {
      urls.push(url);
      return new Promise((resolve) =>
        pending.push(() => resolve({ ok: true, headers: { get: () => "0:0" }, json: async () => [] })),
      );
    },
  });
  return { api, urls, pending };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe("loadTags coalesces a burst of tag changes (#2059)", () => {
  it("ten tags_changed while one fetch is in flight cost one trailing fetch", async () => {
    const { api, urls, pending } = harness();
    for (let i = 0; i < 10; i++) api.loadTags("c1");
    expect(urls).toEqual(["/cases/c1/tags"]);
    pending.shift()!();
    await settle();
    expect(urls).toHaveLength(2);
    pending.shift()!();
    await settle();
    expect(urls).toHaveLength(2);
  });

  it("a single change still loads once, and a later one loads again", async () => {
    const { api, urls, pending } = harness();
    api.loadTags("c1");
    pending.shift()!();
    await settle();
    api.loadTags("c1");
    pending.shift()!();
    await settle();
    expect(urls).toEqual(["/cases/c1/tags", "/cases/c1/tags"]);
  });
});
