import { describe, expect, it } from "vitest";
import {
  IDEMPOTENCY_KEY_RE,
  WATSON_IDEMPOTENCY_MAX,
  WATSON_IDEMPOTENCY_WINDOW_MS,
  WatsonMessageDedupe,
  type DedupeClaim,
} from "../../src/routes/watsonIdempotency.js";

// The Idempotency-Key dedupe of POST /watson/message: one round per key, scoped per case and user.

type Result = { disposition: "answered" | "cancelled" | "failed"; n?: number };

const K = "key-fake-0001"; // trufflehog:ignore
const S1 = { caseId: "c1", identityId: "local" };

const promiseOf = (c: DedupeClaim<Result>): Promise<Result> => {
  if (c.kind === "conflict") throw new Error("expected a claim with a promise");
  return c.promise;
};

/** Lets the settle handlers run (they are attached before the caller's await). */
const flush = () => new Promise((r) => setTimeout(r, 0));

describe("WatsonMessageDedupe", () => {
  it("a repeat with the same key and text shares the first promise (one start)", async () => {
    const d = new WatsonMessageDedupe<Result>();
    let starts = 0;
    const start = async (): Promise<Result> => ({ disposition: "answered", n: ++starts });
    const a = d.run(S1, K, "hi", start);
    const b = d.run(S1, K, "hi", start);
    expect(a.kind).toBe("first");
    expect(b.kind).toBe("repeat");
    expect(await promiseOf(b)).toEqual({ disposition: "answered", n: 1 });
    expect(starts).toBe(1);
  });

  it("the same key with another text is a conflict; another case is independent", () => {
    const d = new WatsonMessageDedupe<Result>();
    const start = async (): Promise<Result> => ({ disposition: "answered" });
    expect(d.run(S1, K, "hi", start).kind).toBe("first");
    expect(d.run(S1, K, "other", start).kind).toBe("conflict");
    expect(d.run({ caseId: "c2", identityId: "local" }, K, "hi", start).kind).toBe("first");
  });

  it("a failed first run (a rejection) is forgotten after it settles; waiters share it", async () => {
    const d = new WatsonMessageDedupe<Result>();
    let starts = 0;
    const failing = async (): Promise<Result> => {
      starts++;
      throw new Error("refused");
    };
    const a = d.run(S1, K, "hi", failing);
    const b = d.run(S1, K, "hi", failing);
    await expect(promiseOf(a)).rejects.toThrow("refused");
    await expect(promiseOf(b)).rejects.toThrow("refused");
    await flush();
    const c = d.run(S1, K, "hi", async () => ({ disposition: "answered", n: ++starts }));
    expect(c.kind).toBe("first");
    expect(starts).toBe(2);
  });

  it("a result expires after the window", async () => {
    let now = 1_000;
    const d = new WatsonMessageDedupe<Result>(() => now);
    let starts = 0;
    const start = async (): Promise<Result> => ({ disposition: "answered", n: ++starts });
    await promiseOf(d.run(S1, K, "hi", start));
    await flush();
    now += WATSON_IDEMPOTENCY_WINDOW_MS - 1;
    expect(d.run(S1, K, "hi", start).kind).toBe("repeat");
    now += 2;
    expect(d.run(S1, K, "hi", start).kind).toBe("first");
    expect(starts).toBe(2);
  });

  it("a running entry is never evicted past the cap; the oldest settled entry is", async () => {
    let now = 0;
    const d = new WatsonMessageDedupe<Result>(() => ++now);
    const pending = d.run(S1, "key-fake-pending", "hi", () => new Promise<Result>(() => undefined));
    expect(pending.kind).toBe("first");
    const settled = async (): Promise<Result> => ({ disposition: "answered" });
    for (let i = 0; i <= WATSON_IDEMPOTENCY_MAX; i++) {
      await promiseOf(d.run(S1, `key-fake-${String(i).padStart(4, "0")}`, "hi", settled));
      await flush();
    }
    expect(d.run(S1, "key-fake-pending", "hi", settled).kind).toBe("repeat");
    expect(d.run(S1, "key-fake-0000", "hi", settled).kind).toBe("first"); // the oldest settled one
    expect(d.run(S1, `key-fake-${String(WATSON_IDEMPOTENCY_MAX).padStart(4, "0")}`, "hi", settled).kind).toBe(
      "repeat",
    );
  });

  it("two identities with the same key and text do not share a round (Codex #8)", () => {
    const d = new WatsonMessageDedupe<Result>();
    const start = async (): Promise<Result> => ({ disposition: "answered" });
    expect(d.run({ caseId: "c1", identityId: "u-fake1" }, K, "hi", start).kind).toBe("first");
    expect(d.run({ caseId: "c1", identityId: "u-fake2" }, K, "hi", start).kind).toBe("first");
  });

  it.each([
    ["failed", "first"],
    ["answered", "repeat"],
    ["cancelled", "repeat"],
  ] as const)("a '%s' disposition gives a later resend kind '%s' (Codex #7)", async (disposition, kind) => {
    const d = new WatsonMessageDedupe<Result>();
    await promiseOf(d.run(S1, K, "hi", async () => ({ disposition })));
    await flush();
    expect(d.run(S1, K, "hi", async () => ({ disposition: "answered" })).kind).toBe(kind);
  });

  it("the key pattern takes 8 to 64 letters, digits, '-' and '_'", () => {
    expect(IDEMPOTENCY_KEY_RE.test("key-fake_01")).toBe(true);
    expect(IDEMPOTENCY_KEY_RE.test("short")).toBe(false);
    expect(IDEMPOTENCY_KEY_RE.test("a".repeat(65))).toBe(false);
    expect(IDEMPOTENCY_KEY_RE.test("key fake 01")).toBe(false);
  });
});
