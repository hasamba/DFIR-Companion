import { describe, expect, it } from "vitest";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";

// AnalysisPipeline's collaborators must stay PRIVATE (#384).
//
// The ingest extraction first passed `this` to the importers and let the class satisfy
// ImportContext structurally. That works, but it forces `opts` and four methods to be public — so
// to give the importers a five-member interface, every OTHER consumer of the pipeline gained the
// whole options bag: AI providers, every store, every tuning knob. A boundary that widens the class
// in order to exist is not much of a boundary.
//
// The fix was a private adapter closing over the five permitted operations. This test is what stops
// the next person from "simplifying" it back — the @ts-expect-error lines below FAIL TO COMPILE if
// any of these members becomes public again, because an unused @ts-expect-error is itself an error.
// That makes this a compile-time assertion that happens to live in a test file; the runtime body
// exists only so vitest has something to report.

describe("AnalysisPipeline encapsulation", () => {
  it("keeps opts and the importer collaborators private", () => {
    const reachIn = (p: AnalysisPipeline): void => {
      // @ts-expect-error -- `opts` is private; the importers get it through the ImportContext adapter.
      void p.opts;
      // @ts-expect-error -- `withStateLock` is private.
      void p.withStateLock;
      // @ts-expect-error -- `mergeWithAliases` is private.
      void p.mergeWithAliases;
      // @ts-expect-error -- `noteEmptyImport` is private.
      void p.noteEmptyImport;
      // @ts-expect-error -- `persistPlasoParsed` is private.
      void p.persistPlasoParsed;
    };
    expect(typeof reachIn).toBe("function");
  });

  it("still exposes the public import surface callers depend on", async () => {
    // The point of the adapter is that it changed nothing for callers. Routes and scripts call
    // pipeline.importThor(...) and friends; if the delegations had been rewired wrongly, these
    // would have disappeared from the type.
    const { AnalysisPipeline: Ctor } = await import("../../src/analysis/pipeline.js");
    const named = Object.getOwnPropertyNames(Ctor.prototype).filter((n) => n.startsWith("import"));
    expect(named.length).toBeGreaterThanOrEqual(30);
    expect(named).toContain("importThor");
    expect(named).toContain("importVelociraptor");
  });
});
