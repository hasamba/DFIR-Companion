// #2561: the whole-case recompute keeps the trusted tags equal to what the current marks decide.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import type { IocAttributionMap } from "../../src/analysis/iocAttribution.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { NewTag, Tag } from "../../src/analysis/tags.js";
import { syncTrustedActivity, type TrustedSyncDeps } from "../../src/analysis/trustedActivitySync.js";
import { TRUSTED_AUTHOR_PREFIX } from "../../src/analysis/trustedSourceMarks.js";
import { COMPANY_IP, sans504Records } from "./fixtures/sans504Lab.js";

const rows = parseCloudTrail(JSON.stringify({ Records: sans504Records() }), { aggregate: false }).events.map(
  (e, i) => ({ ...e, id: `ev${i}` }) as unknown as ForensicEvent,
);

function harness(initial: IocAttributionMap) {
  let marks = initial;
  let tags: Tag[] = [];
  let n = 0;
  const deps: TrustedSyncDeps = {
    loadMarks: async () => marks,
    loadRows: async () => rows,
    tags: {
      taggerTagsFor: async (_c, ids) =>
        tags.filter((t) => ids.includes(t.targetId) && t.author.startsWith("tagger:")),
      addMany: async (_c, inputs: readonly NewTag[]) => {
        const fresh = inputs
          .filter((i) => !tags.some((t) => t.targetId === i.targetId && t.label === i.label))
          .map((i) => ({ ...i, id: `t${++n}`, createdAt: "" }));
        tags = [...tags, ...fresh];
        return fresh;
      },
      remove: async (_c, id) => {
        const hit = tags.find((t) => t.id === id) ?? null;
        tags = tags.filter((t) => t.id !== id);
        return hit;
      },
    },
  };
  return {
    deps,
    setMarks: (m: IocAttributionMap) => (marks = m),
    tags: () => tags,
    addTag: (t: Tag) => (tags = [...tags, t]),
  };
}

const mark = (label: "ours" | "responder" | "attacker"): IocAttributionMap => ({
  [COMPANY_IP]: { value: COMPANY_IP, label, setAt: "", setBy: "a" },
});

describe("syncTrustedActivity", () => {
  it("adds the tags a mark decides, and is idempotent", async () => {
    const h = harness(mark("responder"));
    const first = await syncTrustedActivity(h.deps, "c1");
    expect(first.added).toBeGreaterThan(0);
    expect(first.tagged).toBe(first.added);
    const again = await syncTrustedActivity(h.deps, "c1");
    expect(again).toEqual({ added: 0, removed: 0, tagged: first.added });
  });

  it("removes every trusted tag when the mark is cleared, and relabels on a label change", async () => {
    const h = harness(mark("responder"));
    const { tagged } = await syncTrustedActivity(h.deps, "c1");
    h.setMarks(mark("ours"));
    const relabel = await syncTrustedActivity(h.deps, "c1");
    expect(relabel).toEqual({ added: tagged, removed: tagged, tagged });
    expect(h.tags().every((t) => t.author.startsWith(`${TRUSTED_AUTHOR_PREFIX}ours:`))).toBe(true);
    h.setMarks({});
    expect((await syncTrustedActivity(h.deps, "c1")).removed).toBe(tagged);
    expect(h.tags()).toEqual([]);
  });

  it("leaves other taggers' and analysts' tags alone", async () => {
    const h = harness({});
    h.addTag({
      id: "x1",
      targetType: "event",
      targetId: "ev0",
      label: "key-evidence",
      author: "tagger:rule:1",
      createdAt: "",
    });
    h.addTag({
      id: "x2",
      targetType: "event",
      targetId: "ev1",
      label: "pivot",
      author: "alice",
      createdAt: "",
    });
    await syncTrustedActivity(h.deps, "c1");
    expect(h.tags().map((t) => t.id)).toEqual(["x1", "x2"]);
  });

  it("runs calls for one case one after another, ending on the latest marks", async () => {
    const h = harness(mark("responder"));
    const a = syncTrustedActivity(h.deps, "c1");
    h.setMarks({});
    const b = syncTrustedActivity(h.deps, "c1");
    await Promise.all([a, b]);
    expect(h.tags()).toEqual([]);
  });

  it("never throws: a failing store is logged and reported as no change", async () => {
    const lines: string[] = [];
    const h = harness(mark("ours"));
    const deps = {
      ...h.deps,
      loadRows: async () => Promise.reject(new Error("boom")),
      logLine: (m: string) => lines.push(m),
    };
    expect(await syncTrustedActivity(deps, "c1")).toEqual({ added: 0, removed: 0, tagged: 0 });
    expect(lines[0]).toMatch(/boom/);
  });
});
