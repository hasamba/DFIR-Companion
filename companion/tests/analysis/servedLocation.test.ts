import { describe, expect, it } from "vitest";
import {
  validateServedLocation,
  servedLocationSchema,
  SENSITIVE_PER_LOCATION_MAX,
  INDEX_FILES_MAX,
} from "../../src/analysis/servedLocation.js";

// #1080: validateServedLocation must reject everything servedLocationSchema rejects — a gap here
// lets a bad declaration reach disk, and every later read of the case's served-location store
// throws a ZodError with no API recovery path (the DELETE route loads before it filters).

const NOW = "2026-06-01T00:00:00.000Z";
const base = { host: "h", urlPrefix: "/", localRoot: "/var/www" };

function accepted(over: Record<string, unknown>) {
  const v = validateServedLocation({ ...base, ...over }, NOW);
  expect(v.ok).toBe(true);
  if (!v.ok) throw new Error("unreachable");
  return v.location;
}

describe("validateServedLocation / servedLocationSchema parity", () => {
  it("every accepted output parses under the schema (fuzz over representative inputs)", () => {
    const samples: Record<string, unknown>[] = [
      {},
      { vhost: "example.com" },
      { indexFiles: ["index.html", "default.htm"] },
      { sensitive: ["a/b.txt", "c.txt"] },
      { sensitiveDigests: ["a".repeat(64)] },
      { note: "n" },
      { caseInsensitive: true },
      { caseInsensitive: false },
      { public: true },
    ];
    for (const over of samples) {
      const location = accepted(over);
      expect(servedLocationSchema.safeParse(location).success).toBe(true);
    }
  });

  it("rejects a urlPrefix longer than the schema's 1024-char bound", () => {
    const v = validateServedLocation({ ...base, urlPrefix: "/" + "a".repeat(2000) }, NOW);
    expect(v.ok).toBe(false);
  });

  it("rejects a vhost longer than the schema's 253-char bound", () => {
    const v = validateServedLocation({ ...base, vhost: "v".repeat(300) }, NOW);
    expect(v.ok).toBe(false);
  });

  it("rejects an index file name longer than the schema's 255-char bound", () => {
    const v = validateServedLocation({ ...base, indexFiles: ["i".repeat(300)] }, NOW);
    expect(v.ok).toBe(false);
  });

  it("rejects a sensitive path longer than the schema's 1024-char bound", () => {
    const v = validateServedLocation({ ...base, sensitive: ["s".repeat(2000)] }, NOW);
    expect(v.ok).toBe(false);
  });

  it("rejects a non-boolean caseInsensitive instead of passing it through", () => {
    const v = validateServedLocation({ ...base, caseInsensitive: "true" as never }, NOW);
    expect(v.ok).toBe(false);
  });

  it("accepts exactly-at-bound values", () => {
    const location = accepted({
      vhost: "v".repeat(253),
      urlPrefix: "/" + "a".repeat(1023),
      indexFiles: ["i".repeat(255)],
      sensitive: ["s".repeat(1024)],
    });
    expect(servedLocationSchema.safeParse(location).success).toBe(true);
  });

  it("still enforces the pre-existing count caps", () => {
    const tooManySensitive = Array.from({ length: SENSITIVE_PER_LOCATION_MAX + 1 }, (_, i) => `p${i}`);
    expect(validateServedLocation({ ...base, sensitive: tooManySensitive }, NOW).ok).toBe(false);
    const tooManyIndex = Array.from({ length: INDEX_FILES_MAX + 1 }, (_, i) => `i${i}`);
    expect(validateServedLocation({ ...base, indexFiles: tooManyIndex }, NOW).ok).toBe(false);
  });
});
