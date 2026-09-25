// Readable served-model names on the jobs popover (#1601).
import { describe, it, expect } from "vitest";
import { jobModelLabel, modelDisplayName } from "../../src/analysis/modelDisplayName.js";

describe("modelDisplayName", () => {
  it.each([
    ["claude-sonnet-5", "Sonnet 5"],
    ["claude-opus-5-5", "Opus 5.5"],
    ["claude-haiku-4-5-20251001", "Haiku 4.5"],
    ["claude-sonnet-4-6", "Sonnet 4.6"],
    ["claude-sonnet-4-20250514", "Sonnet 4"],
    ["claude-3-5-sonnet-20241022", "Sonnet 3.5"],
    ["claude-3-opus-20240229", "Opus 3"],
  ])("names %s as %s", (id, name) => {
    expect(modelDisplayName(id)).toBe(name);
  });

  // Unknown ids come back byte for byte: an OpenRouter vendor/model path, other vendors' ids, and
  // near-misses that only look like a Claude id.
  it.each([
    "google/gemini-3.8-flash",
    "gpt-6-sol",
    "anthropic/claude-sonnet-4.5",
    "llama3.1:8b",
    "claude-sonnet",
    "claude-sonnet-5-beta",
    "claude-poet-5",
    "Claude-Sonnet-5",
    "claude-sonnet-5-5-5",
    "sonnet",
  ])("returns the unknown id %s unchanged", (id) => {
    expect(modelDisplayName(id)).toBe(id);
  });
});

describe("jobModelLabel", () => {
  it("shows the served version after the alias", () => {
    expect(jobModelLabel({ model: "sonnet", servedModel: "claude-sonnet-5", terminal: true })).toBe(
      "sonnet → Sonnet 5",
    );
  });

  it("prefers the job's own served model to the last known one", () => {
    expect(
      jobModelLabel(
        { model: "sonnet", servedModel: "claude-sonnet-5", terminal: false },
        "claude-sonnet-4-6",
      ),
    ).toBe("sonnet → Sonnet 5");
  });

  it("shows the last served version while the job has no answer yet", () => {
    expect(jobModelLabel({ model: "sonnet", terminal: false }, "claude-sonnet-5")).toBe(
      "sonnet (last run: Sonnet 5)",
    );
  });

  // A finished job that never reported a model ran on something — but not provably on the last
  // version another job saw. Saying so would be a guess.
  it("never borrows the last served version for a finished job", () => {
    expect(jobModelLabel({ model: "sonnet", terminal: true }, "claude-sonnet-5")).toBe("sonnet");
  });

  it("shows the alias alone when nothing is known", () => {
    expect(jobModelLabel({ model: "sonnet", terminal: false })).toBe("sonnet");
  });

  it("does not repeat a model that served exactly what was asked for", () => {
    expect(jobModelLabel({ model: "gpt-6-sol", servedModel: "gpt-6-sol", terminal: true })).toBe("gpt-6-sol");
  });

  it("shows an unknown served id as it is", () => {
    expect(jobModelLabel({ model: "gemini", servedModel: "google/gemini-3.8-flash", terminal: true })).toBe(
      "gemini → google/gemini-3.8-flash",
    );
  });

  it("is undefined for a job no model runs", () => {
    expect(jobModelLabel({ terminal: true }, "claude-sonnet-5")).toBeUndefined();
  });
});
