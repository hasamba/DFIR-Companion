import { describe, it, expect, afterEach } from "vitest";
import { mispPushOptions } from "../../src/server.js";

// DFIR_MISP_TIMELINE_LIMIT caps forensic-timeline events per push. The push costs one sequential
// round-trip per event, so the cap is what keeps a large case from blocking the export route for
// hours — but the truncation warning tells the analyst to raise it, so it has to BE raisable.
// A bad value must fall back to the built-in default rather than take effect: a `0` or negative
// cap would silently push nothing while still reporting success, which is worse than a slow push.

const ORIGINAL = process.env.DFIR_MISP_TIMELINE_LIMIT;

afterEach(() => {
  if (ORIGINAL === undefined) delete process.env.DFIR_MISP_TIMELINE_LIMIT;
  else process.env.DFIR_MISP_TIMELINE_LIMIT = ORIGINAL;
});

describe("mispPushOptions timelineLimit", () => {
  it("passes a valid positive integer through", () => {
    process.env.DFIR_MISP_TIMELINE_LIMIT = "20000";
    expect(mispPushOptions().timelineLimit).toBe(20000);
  });

  it("leaves the limit unset when the env var is absent, so the built-in default applies", () => {
    delete process.env.DFIR_MISP_TIMELINE_LIMIT;
    expect(mispPushOptions().timelineLimit).toBeUndefined();
  });

  it.each(["0", "-1", "abc", "", "   ", "12.5"])(
    "ignores the unusable value %j and falls back to the default",
    (raw) => {
      process.env.DFIR_MISP_TIMELINE_LIMIT = raw;
      expect(mispPushOptions().timelineLimit).toBeUndefined();
    },
  );
});
