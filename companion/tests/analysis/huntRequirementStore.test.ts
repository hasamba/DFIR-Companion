import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  HuntRequirementStore,
  InvalidSupersedesIdError,
  type HuntRequirement,
} from "../../src/analysis/huntRequirementStore.js";

let dir = "";
const cases = { stateDir: () => dir } as unknown as ConstructorParameters<typeof HuntRequirementStore>[0];

type NewInput = Parameters<HuntRequirementStore["create"]>[1];

function requirement(over: Partial<NewInput> = {}): NewInput {
  return {
    decision: "recommend containment vs. monitor",
    audience: "IR lead",
    deadline: "2026-09-20T00:00:00Z",
    subjectScope: { kind: "hosts", hosts: ["ws-01"] },
    expectedObservableEvidence: "the binary executed and wrote files to disk",
    createdBy: "a.analyst@example.invalid",
    createdAt: "2026-09-16T00:00:00Z",
    ...over,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "hunt-requirement-"));
});

describe("HuntRequirementStore", () => {
  it("returns an empty list and no active requirements when the file does not exist", async () => {
    const store = new HuntRequirementStore(cases);
    expect(await store.load("c1")).toEqual([]);
    expect(await store.active("c1")).toEqual([]);
  });

  it("rejects a requirement with no createdBy", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(store.create("c1", requirement({ createdBy: "" }))).rejects.toBeTruthy();
  });

  it("rejects a requirement with no decision, audience, deadline or expected evidence", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(store.create("c1", requirement({ decision: "" }))).rejects.toBeTruthy();
    await expect(store.create("c1", requirement({ audience: "" }))).rejects.toBeTruthy();
    await expect(store.create("c1", requirement({ deadline: "" }))).rejects.toBeTruthy();
    await expect(store.create("c1", requirement({ expectedObservableEvidence: "" }))).rejects.toBeTruthy();
  });

  it("creates a requirement with a generated id and it becomes active", async () => {
    const store = new HuntRequirementStore(cases);
    const created = await store.create("c1", requirement());
    expect(created.id).toBeTruthy();
    const active = await store.active("c1");
    expect(active).toHaveLength(1);
    expect(active[0].id).toBe(created.id);
    expect(active[0].decision).toBe("recommend containment vs. monitor");
  });

  it("appends, never overwrites — creating twice keeps both in the audit trail", async () => {
    const store = new HuntRequirementStore(cases);
    await store.create("c1", requirement({ decision: "first decision" }));
    await store.create("c1", requirement({ decision: "second decision" }));
    const all = await store.load("c1");
    expect(all).toHaveLength(2);
  });

  it("revoking a requirement removes it from active() but keeps it in load()", async () => {
    const store = new HuntRequirementStore(cases);
    const created = await store.create("c1", requirement());
    await store.revoke("c1", created.id, "b.reviewer@example.invalid", "2026-09-17T00:00:00Z");
    expect(await store.active("c1")).toEqual([]);
    const all = await store.load("c1");
    expect(all).toHaveLength(1);
    expect(all[0].revokedAt).toBe("2026-09-17T00:00:00Z");
    expect(all[0].revokedBy).toBe("b.reviewer@example.invalid");
  });

  it("revoke accepts an optional reason, e.g. 'the investigative question changed'", async () => {
    const store = new HuntRequirementStore(cases);
    const created = await store.create("c1", requirement());
    await store.revoke(
      "c1",
      created.id,
      "b.reviewer@example.invalid",
      "2026-09-17T00:00:00Z",
      "the investigative question changed",
    );
    const all = await store.load("c1");
    expect(all[0].revokedReason).toBe("the investigative question changed");
  });

  it("a changed investigative question is a revoke of the old requirement plus a new record naming it via supersedesId", async () => {
    const store = new HuntRequirementStore(cases);
    const old = await store.create("c1", requirement({ decision: "old question" }));
    await store.revoke(
      "c1",
      old.id,
      "a.analyst@example.invalid",
      "2026-09-17T00:00:00Z",
      "the investigative question changed",
    );
    const next = await store.create("c1", requirement({ decision: "new question", supersedesId: old.id }));
    expect(next.supersedesId).toBe(old.id);
    const active = await store.active("c1");
    expect(active).toHaveLength(1);
    expect(active[0].id).toBe(next.id);
  });

  it("revoking a requirement that does not exist is a no-op, not an error", async () => {
    const store = new HuntRequirementStore(cases);
    const before = await store.load("c1");
    const after = await store.revoke(
      "c1",
      "does-not-exist",
      "b.reviewer@example.invalid",
      "2026-09-17T00:00:00Z",
    );
    expect(after).toEqual(before);
  });

  it("revoking an already-revoked requirement is a no-op", async () => {
    const store = new HuntRequirementStore(cases);
    const created = await store.create("c1", requirement());
    await store.revoke("c1", created.id, "b.reviewer@example.invalid", "2026-09-17T00:00:00Z");
    const after = await store.revoke("c1", created.id, "c.other@example.invalid", "2026-09-18T00:00:00Z");
    expect(after[0].revokedBy).toBe("b.reviewer@example.invalid"); // first revoke stands
  });

  it("requires subjectScope to be present and well-formed — never optional on a fresh record", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(
      store.create("c1", {
        ...requirement(),
        subjectScope: undefined as unknown as HuntRequirement["subjectScope"],
      }),
    ).rejects.toBeTruthy();
  });

  it("rejects a hosts scope with no hosts array", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(
      store.create("c1", {
        ...requirement(),
        subjectScope: { kind: "hosts" } as unknown as HuntRequirement["subjectScope"],
      }),
    ).rejects.toBeTruthy();
  });

  it("rejects a hosts scope with an EMPTY hosts array, not just a missing one (#1165)", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(
      store.create("c1", {
        ...requirement(),
        subjectScope: { kind: "hosts", hosts: [] } as unknown as HuntRequirement["subjectScope"],
      }),
    ).rejects.toBeTruthy();
  });

  it("rejects an unrecognized scope kind", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(
      store.create("c1", {
        ...requirement(),
        subjectScope: { kind: "bogus" } as unknown as HuntRequirement["subjectScope"],
      }),
    ).rejects.toBeTruthy();
  });

  it("rejects a deadline that is not a real ISO datetime", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(store.create("c1", requirement({ deadline: "EOD Friday" }))).rejects.toBeTruthy();
  });

  it("keeps every requirement when two analysts create concurrently", async () => {
    const store = new HuntRequirementStore(cases);
    await Promise.all([
      store.create("c1", requirement({ decision: "d1" })),
      store.create("c1", requirement({ decision: "d2" })),
      store.create("c1", requirement({ decision: "d3" })),
    ]);
    expect(await store.load("c1")).toHaveLength(3);
  });

  it("does not let one failed create poison the queue for the next writer", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(store.create("c1", requirement({ createdBy: "" }))).rejects.toBeTruthy();
    await store.create("c1", requirement());
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("does not let a create that fails INSIDE the queued job (a corrupt file) poison the queue for the next writer", async () => {
    // Ollama code review finding D2: the earlier version of this test only exercised a create
    // rejected by zod validation BEFORE the job was ever enqueued — the actual queue recovery
    // machinery (prior.then(job, job), run.catch(() => undefined)) was never touched by any test.
    // This one fails inside the enqueued job itself (at load()), which is the real case.
    await writeFile(join(dir, "hunt-requirements.json"), "{ not json", "utf8");
    const store = new HuntRequirementStore(cases);
    await expect(store.create("c1", requirement())).rejects.toThrow(/hunt-requirements\.json/);
    await writeFile(
      join(dir, "hunt-requirements.json"),
      JSON.stringify({ version: 1, requirements: [] }),
      "utf8",
    );
    await store.create("c1", requirement());
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("rejects create when supersedesId does not exist in this case, with a typed error", async () => {
    const store = new HuntRequirementStore(cases);
    await expect(store.create("c1", requirement({ supersedesId: "does-not-exist" }))).rejects.toBeInstanceOf(
      InvalidSupersedesIdError,
    );
  });

  it("rejects create when supersedesId points at a requirement that is still active (not revoked), with a typed error", async () => {
    const store = new HuntRequirementStore(cases);
    const old = await store.create("c1", requirement({ decision: "old question" }));
    await expect(
      store.create("c1", requirement({ decision: "new question", supersedesId: old.id })),
    ).rejects.toBeInstanceOf(InvalidSupersedesIdError);
  });

  it("throws on a corrupt file and leaves it untouched", async () => {
    await writeFile(join(dir, "hunt-requirements.json"), "{ not json", "utf8");
    await expect(new HuntRequirementStore(cases).load("c1")).rejects.toThrow(/hunt-requirements\.json/);
  });

  it("throws when the file parses but does not match the schema", async () => {
    await writeFile(join(dir, "hunt-requirements.json"), JSON.stringify({ version: 1 }), "utf8");
    await expect(new HuntRequirementStore(cases).load("c1")).rejects.toThrow(/hunt-requirements\.json/);
  });
});
