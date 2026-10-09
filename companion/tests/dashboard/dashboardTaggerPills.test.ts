// #2059: the tag list carries analyst tags only; the automatic tagger's labels arrive with the page
// that shows their rows (/state and /super-timeline carry `eventTaggerTags`). The pills an analyst sees
// on a row are unchanged — rendered from the page data plus the analyst list.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Tag {
  id: string;
  targetType: string;
  targetId: string;
  label: string;
  author: string;
}

interface Api {
  loadTags(caseId: string): void;
  tagPills(type: string, id: string): string;
  tagsForTarget(key: string): Tag[];
  DfirState: {
    lastState(): unknown;
    setLastState(s: unknown): void;
    setLastSuperData(d: unknown): void;
  };
}

interface Reply {
  version?: string;
  list?: Tag[];
}

function harness(replies: { tags?: Reply[]; taggerFor?: Record<string, unknown>[] } = {}) {
  const calls: Array<{ url: string; body?: unknown }> = [];
  const tagReplies = [...(replies.tags ?? [])];
  const taggerReplies = [...(replies.taggerFor ?? [])];
  let renders = 0;
  const api = loadDashboardModule<Api>("dashboard-tags.js", ["dashboard-state.js", "dashboard-escape.js"], {
    targetKey: (type: string, id: string) => `${type}:${id}`,
    tagColor: () => "#888",
    ICON_TAG: "",
    deriveStarred: () => {},
    migrateLocalStars: () => {},
    render: () => {
      renders++;
    },
    fetch: async (url: string, init?: { body?: string }) => {
      calls.push({ url, body: init?.body ? JSON.parse(init.body) : undefined });
      if (url.endsWith("/tags/tagger-for")) {
        const eventTaggerTags = taggerReplies.shift() ?? {};
        return { ok: true, json: async () => ({ eventTaggerTags }) };
      }
      const r = tagReplies.shift() ?? {};
      return { ok: true, headers: { get: () => r.version ?? "0:0" }, json: async () => r.list ?? [] };
    },
  });
  return { api, calls, renders: () => renders };
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const tt = (id: string, label: string) => ({ id, label, author: "tagger:svc" });
const row = (id: string) => ({ id, timestamp: "2026-06-10T12:00:00Z", description: id, severity: "Low" });

describe("tagger pills render from the page data (#2059)", () => {
  it("a forensic row shows its tagger labels from the /state page beside the analyst's", async () => {
    const analyst = { id: "a1", targetType: "event", targetId: "e1", label: "key-evidence", author: "alice" };
    const { api } = harness({ tags: [{ list: [analyst] }] });
    api.loadTags("c1");
    await settle();
    api.DfirState.setLastState({
      caseId: "c1",
      forensicTimeline: [row("e1"), row("e2")],
      eventTaggerTags: { e1: [tt("t1", "win-service"), tt("t2", "persistence")] },
    });
    const pills = api.tagPills("event", "e1");
    expect(pills).toContain("win-service");
    expect(pills).toContain("persistence");
    expect(pills).toContain("key-evidence");
    expect(pills).toContain("tag by tagger:svc");
    expect(api.tagPills("event", "e2")).toBe("");
  });

  it("a super-timeline row's pills (tagsForTarget) include the tagger labels its page carried", () => {
    const { api } = harness();
    api.DfirState.setLastSuperData({
      events: [row("raw1")],
      eventTaggerTags: { raw1: [tt("t9", "web-scanner")] },
    });
    const list = api.tagsForTarget("event:raw1");
    expect(list.map((t) => t.label)).toEqual(["web-scanner"]);
    expect(list[0]).toMatchObject({ id: "t9", targetType: "event", targetId: "raw1", author: "tagger:svc" });
  });

  it("a state push without page tags keeps the labels the rows already had", () => {
    const { api } = harness();
    api.DfirState.setLastState({
      caseId: "c1",
      forensicTimeline: [row("e1")],
      eventTaggerTags: { e1: [tt("t1", "x")] },
    });
    api.DfirState.setLastState({ caseId: "c1", forensicTimeline: [row("e1")] });
    expect(api.tagPills("event", "e1")).toContain(">x<");
  });

  it("a page that carries tagger tags drops the cached labels of a listed row it no longer tags", () => {
    const { api } = harness();
    api.DfirState.setLastSuperData({
      events: [row("raw1")],
      eventTaggerTags: { raw1: [tt("t9", "persistence")] },
    });
    api.DfirState.setLastSuperData({ events: [row("raw2")], eventTaggerTags: {} }); // paged away
    // the tag was removed while raw1 was off-page; the page that shows it again carries none
    api.DfirState.setLastSuperData({ events: [row("raw1")], eventTaggerTags: {} });
    expect(api.tagsForTarget("event:raw1")).toEqual([]);
    expect(api.tagPills("event", "raw1")).toBe("");
  });

  it("asks for the tagger tags of rows a push brought that no page has described", async () => {
    const { api, calls } = harness({ taggerFor: [{ e9: [tt("t5", "lateral-movement")] }] });
    api.DfirState.setLastState({ caseId: "c1", forensicTimeline: [row("e1")], eventTaggerTags: {} });
    api.DfirState.setLastState({ caseId: "c1", forensicTimeline: [row("e1"), row("e9")] });
    await settle();
    await settle();
    const asked = calls.filter((c) => c.url === "/cases/c1/tags/tagger-for");
    expect(asked).toHaveLength(1);
    expect(asked[0].body).toEqual({ ids: ["e9"] });
    expect(api.tagPills("event", "e9")).toContain("lateral-movement");
  });

  it("re-asks every row it holds when the tagger version moves, and drops cleared labels", async () => {
    const { api, calls } = harness({ tags: [{ version: "1:1" }, { version: "0:1" }], taggerFor: [{}] });
    api.loadTags("c1");
    await settle();
    api.DfirState.setLastState({
      caseId: "c1",
      forensicTimeline: [row("e1")],
      eventTaggerTags: { e1: [tt("t1", "x")] },
    });
    expect(calls.filter((c) => c.url.endsWith("/tagger-for"))).toHaveLength(0);
    api.loadTags("c1"); // the tagger's tags were cleared
    await settle();
    await settle();
    const asked = calls.filter((c) => c.url.endsWith("/tagger-for"));
    expect(asked).toHaveLength(1);
    expect(asked[0].body).toEqual({ ids: ["e1"] });
    expect(api.tagPills("event", "e1")).toBe("");
  });
});
