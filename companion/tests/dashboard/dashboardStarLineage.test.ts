// #1715: a star the analyst put on an event that correlation later folded into another arrives with
// `resolvedTargetId`. The star shows on both ids, and unstarring the surviving event removes every
// star tag it holds — an event can hold two when two starred rows folded into it.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface StarApi {
  deriveStarred(): void;
  unstarAll(caseId: string, id: string): Promise<{ ok: boolean; status: number }>;
  starredTagIds: Map<string, string[]>;
  DfirStarred: { ids(): string[] };
}

type Tag = { id: string; targetType: string; targetId: string; label: string; resolvedTargetId?: string };

function load(tags: Tag[], fetched: string[] = []) {
  const byKey = new Map<string, Tag[]>();
  for (const t of tags)
    for (const id of [t.targetId, t.resolvedTargetId].filter(Boolean) as string[]) {
      const k = `${t.targetType}:${id}`;
      byKey.set(k, [...(byKey.get(k) ?? []), t]);
    }
  return loadDashboardModule<StarApi>(
    "dashboard-starred.js",
    ["dashboard-state.js", "dashboard-selection.js"],
    {
      starredTagIds: new Map(),
      eachTagList: (fn: (list: Tag[]) => void) => byKey.forEach(fn),
      fetch: async (url: string) => {
        fetched.push(url);
        return { ok: true, status: 204 };
      },
    },
  );
}

const star = (id: string, targetId: string, resolvedTargetId?: string): Tag => ({
  id,
  targetType: "event",
  targetId,
  label: "starred",
  ...(resolvedTargetId ? { resolvedTargetId } : {}),
});

describe("stars follow a folded event (#1715)", () => {
  it("stars both the id the analyst starred and the event it lives on now", () => {
    const api = load([star("tag1", "m1e1", "t2e5")]);
    api.deriveStarred();
    expect([...api.DfirStarred.ids()].sort()).toEqual(["m1e1", "t2e5"]);
    expect(api.starredTagIds.get("t2e5")).toEqual(["tag1"]);
  });

  it("keeps every star tag a survivor holds, once each", () => {
    const api = load([star("tag1", "a", "c"), star("tag2", "b", "c"), star("tag3", "c")]);
    api.deriveStarred();
    expect([...(api.starredTagIds.get("c") ?? [])].sort()).toEqual(["tag1", "tag2", "tag3"]);
  });

  it("unstarring the survivor deletes every star tag on it", async () => {
    const fetched: string[] = [];
    const api = load([star("tag1", "a", "c"), star("tag2", "b", "c")], fetched);
    api.deriveStarred();
    const r = await api.unstarAll("c1", "c");
    expect(r.ok).toBe(true);
    expect(fetched.sort()).toEqual(["/cases/c1/tags/tag1", "/cases/c1/tags/tag2"]);
  });
});

interface CommentApi {
  loadComments(caseId: string): void;
  eachCommentList(fn: (list: Array<{ id: string }>) => void): void;
  commentChip(type: string, id: string): string;
}

describe("comments follow a folded event, and are enumerated once (#1715)", () => {
  it("shows the comment on both ids but hands the Investigation Log one row", async () => {
    const comment = {
      id: "c-1",
      targetType: "event",
      targetId: "m1e1",
      resolvedTargetId: "t2e5",
      text: "⚑ checked with the owner",
      author: "an",
      createdAt: "2026-05-28T09:00:00Z",
    };
    const api = loadDashboardModule<CommentApi>("dashboard-comments.js", ["dashboard-escape.js"], {
      ICON_COMMENT: "",
      targetKey: (type: string, id: string) => `${type}:${id}`,
      refreshSuperRows: () => {},
      DfirState: { lastState: () => null },
      fetch: async () => ({ json: async () => [comment] }),
    });
    api.loadComments("c1");
    await new Promise((r) => setTimeout(r, 0));
    expect(api.commentChip("event", "m1e1")).toContain(" 1");
    expect(api.commentChip("event", "t2e5")).toContain(" 1");
    const seen: string[] = [];
    api.eachCommentList((list) => list.forEach((c) => seen.push(c.id)));
    expect(seen).toEqual(["c-1"]);
  });
});
