import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AttributionAssertionStore,
  InvalidBuildsOnError,
  type AttributionAssertion,
} from "../../src/analysis/attributionAssertionStore.js";

let dir = "";
const cases = {
  stateDir: () => dir,
} as unknown as ConstructorParameters<typeof AttributionAssertionStore>[0];

type NewInput = Parameters<AttributionAssertionStore["create"]>[1];

function assertion(over: Partial<NewInput> = {}): NewInput {
  return {
    tier: "cluster",
    label: "UNC1234",
    sources: "Internal correlation of C2 infrastructure across three hosts",
    alternatives: "Considered coincidental reuse of a bulletproof host; rejected — shared TLS cert",
    analystAssessment: "Consistent naming and infra reuse across the incident window",
    relatedTechniqueIds: [],
    relatedEventIds: [],
    relatedIocIds: [],
    createdBy: "a.analyst@example.invalid",
    createdAt: "2026-09-16T00:00:00Z",
    ...over,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "attribution-assertion-"));
});

describe("AttributionAssertionStore", () => {
  it("returns an empty list when the file does not exist", async () => {
    const store = new AttributionAssertionStore(cases);
    expect(await store.load("c1")).toEqual([]);
  });

  it("rejects an assertion with no createdBy", async () => {
    const store = new AttributionAssertionStore(cases);
    await expect(store.create("c1", assertion({ createdBy: "" }))).rejects.toBeTruthy();
  });

  it("rejects an assertion missing sources, alternatives or analystAssessment", async () => {
    const store = new AttributionAssertionStore(cases);
    await expect(store.create("c1", assertion({ sources: "" }))).rejects.toBeTruthy();
    await expect(store.create("c1", assertion({ alternatives: "" }))).rejects.toBeTruthy();
    await expect(store.create("c1", assertion({ analystAssessment: "" }))).rejects.toBeTruthy();
  });

  it("rejects an unrecognized tier", async () => {
    const store = new AttributionAssertionStore(cases);
    await expect(
      store.create("c1", { ...assertion(), tier: "bogus" as unknown as AttributionAssertion["tier"] }),
    ).rejects.toBeTruthy();
  });

  it("creates an assertion with no periodStart or periodEnd — never fabricated", async () => {
    const store = new AttributionAssertionStore(cases);
    const created = await store.create("c1", assertion());
    expect(created.periodStart).toBeUndefined();
    expect(created.periodEnd).toBeUndefined();
  });

  it("rejects a periodStart that is not a real ISO datetime", async () => {
    const store = new AttributionAssertionStore(cases);
    await expect(store.create("c1", assertion({ periodStart: "sometime last year" }))).rejects.toBeTruthy();
  });

  it("appends, never overwrites — creating twice for the same target keeps both (conflicting reporting)", async () => {
    const store = new AttributionAssertionStore(cases);
    await store.create("c1", assertion({ tier: "operator", label: "APT29", analystAssessment: "report A" }));
    await store.create("c1", assertion({ tier: "operator", label: "APT29", analystAssessment: "report B" }));
    const all = await store.load("c1");
    expect(all).toHaveLength(2);
  });

  it("retracting an assertion keeps it in load() but marks it retracted", async () => {
    const store = new AttributionAssertionStore(cases);
    const created = await store.create("c1", assertion());
    await store.retract("c1", created.id, "b.reviewer@example.invalid", "2026-09-17T00:00:00Z");
    const all = await store.load("c1");
    expect(all).toHaveLength(1);
    expect(all[0].status).toBe("retracted");
    expect(all[0].retractedAt).toBe("2026-09-17T00:00:00Z");
    expect(all[0].retractedBy).toBe("b.reviewer@example.invalid");
  });

  it("retract accepts an optional reason", async () => {
    const store = new AttributionAssertionStore(cases);
    const created = await store.create("c1", assertion());
    await store.retract(
      "c1",
      created.id,
      "b.reviewer@example.invalid",
      "2026-09-17T00:00:00Z",
      "the source report was withdrawn",
    );
    const all = await store.load("c1");
    expect(all[0].retractedReason).toBe("the source report was withdrawn");
  });

  it("retracting a non-existent id is a no-op, not an error", async () => {
    const store = new AttributionAssertionStore(cases);
    const before = await store.load("c1");
    const after = await store.retract(
      "c1",
      "does-not-exist",
      "b.reviewer@example.invalid",
      "2026-09-17T00:00:00Z",
    );
    expect(after).toEqual(before);
  });

  it("retracting an already-retracted assertion is a no-op", async () => {
    const store = new AttributionAssertionStore(cases);
    const created = await store.create("c1", assertion());
    await store.retract("c1", created.id, "b.reviewer@example.invalid", "2026-09-17T00:00:00Z");
    const after = await store.retract("c1", created.id, "c.other@example.invalid", "2026-09-18T00:00:00Z");
    expect(after[0].retractedBy).toBe("b.reviewer@example.invalid");
  });

  describe("buildsOn tier ordering (structural cycle safety)", () => {
    it("allows buildsOn to reference a strictly weaker tier", async () => {
      const store = new AttributionAssertionStore(cases);
      const cluster = await store.create("c1", assertion({ tier: "cluster", label: "UNC1234" }));
      const campaign = await store.create(
        "c1",
        assertion({ tier: "campaign", label: "Operation Foobar", buildsOn: [cluster.id] }),
      );
      expect(campaign.buildsOn).toEqual([cluster.id]);
    });

    it("rejects buildsOn referencing an equal tier", async () => {
      const store = new AttributionAssertionStore(cases);
      const a = await store.create("c1", assertion({ tier: "cluster", label: "UNC1234" }));
      await expect(
        store.create("c1", assertion({ tier: "cluster", label: "UNC5678", buildsOn: [a.id] })),
      ).rejects.toBeInstanceOf(InvalidBuildsOnError);
    });

    it("rejects buildsOn referencing a stronger tier", async () => {
      const store = new AttributionAssertionStore(cases);
      const sponsor = await store.create("c1", assertion({ tier: "sponsor", label: "State X" }));
      await expect(
        store.create("c1", assertion({ tier: "cluster", label: "UNC1234", buildsOn: [sponsor.id] })),
      ).rejects.toBeInstanceOf(InvalidBuildsOnError);
    });

    it("rejects buildsOn referencing a non-existent id", async () => {
      const store = new AttributionAssertionStore(cases);
      await expect(store.create("c1", assertion({ buildsOn: ["does-not-exist"] }))).rejects.toBeInstanceOf(
        InvalidBuildsOnError,
      );
    });
  });

  it("rejects a supersedesId pointing at an assertion that is not retracted", async () => {
    const store = new AttributionAssertionStore(cases);
    const old = await store.create("c1", assertion());
    await expect(store.create("c1", assertion({ supersedesId: old.id }))).rejects.toBeTruthy();
  });

  it("allows a supersedesId pointing at a retracted assertion", async () => {
    const store = new AttributionAssertionStore(cases);
    const old = await store.create("c1", assertion());
    await store.retract("c1", old.id, "a.analyst@example.invalid", "2026-09-17T00:00:00Z");
    const next = await store.create("c1", assertion({ supersedesId: old.id }));
    expect(next.supersedesId).toBe(old.id);
  });

  it("keeps every assertion when two analysts create concurrently", async () => {
    const store = new AttributionAssertionStore(cases);
    await Promise.all([
      store.create("c1", assertion({ label: "a" })),
      store.create("c1", assertion({ label: "b" })),
      store.create("c1", assertion({ label: "c" })),
    ]);
    expect(await store.load("c1")).toHaveLength(3);
  });

  it("does not let one failed create poison the queue for the next writer", async () => {
    const store = new AttributionAssertionStore(cases);
    await writeFile(join(dir, "attribution-assertions.json"), "{ not json", "utf8");
    await expect(store.create("c1", assertion())).rejects.toThrow(/attribution-assertions\.json/);
    await writeFile(
      join(dir, "attribution-assertions.json"),
      JSON.stringify({ version: 1, assertions: [] }),
      "utf8",
    );
    await store.create("c1", assertion());
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("throws on a corrupt file and leaves it untouched", async () => {
    await writeFile(join(dir, "attribution-assertions.json"), "{ not json", "utf8");
    await expect(new AttributionAssertionStore(cases).load("c1")).rejects.toThrow(
      /attribution-assertions\.json/,
    );
  });

  it("throws when the file parses but does not match the schema", async () => {
    await writeFile(join(dir, "attribution-assertions.json"), JSON.stringify({ version: 1 }), "utf8");
    await expect(new AttributionAssertionStore(cases).load("c1")).rejects.toThrow(
      /attribution-assertions\.json/,
    );
  });
});
