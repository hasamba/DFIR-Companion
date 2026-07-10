import { describe, it, expect } from "vitest";
import { resolveActiveAdapter, OVERRIDE_NONE } from "../src/adapters/override.js";

describe("resolveActiveAdapter", () => {
  it("uses the detected adapter when there is no override", () => {
    expect(resolveActiveAdapter("splunk", "")).toBe("splunk");
    expect(resolveActiveAdapter(null, "")).toBeNull();
  });

  it("forces no adapter when the override is the explicit none sentinel", () => {
    expect(resolveActiveAdapter("splunk", OVERRIDE_NONE)).toBeNull();
    expect(resolveActiveAdapter(null, OVERRIDE_NONE)).toBeNull();
  });

  it("forces a specific adapter when the override names a real registry id", () => {
    expect(resolveActiveAdapter(null, "velociraptor")).toBe("velociraptor");
    expect(resolveActiveAdapter("splunk", "elastic")).toBe("elastic");
  });

  it("falls back to the detected adapter when the override id is not a real adapter", () => {
    expect(resolveActiveAdapter("splunk", "not-a-real-adapter")).toBe("splunk");
    expect(resolveActiveAdapter(null, "not-a-real-adapter")).toBeNull();
  });
});
