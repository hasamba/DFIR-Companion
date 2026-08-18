import { describe, it, expect } from "vitest";
import { preflightBundleArtifacts } from "../../src/integrations/velociraptor/bundlePreflight.js";
import type { VeloArtifactInfo } from "../../src/integrations/velociraptor/velociraptorApi.js";

const def = (name: string, tools?: VeloArtifactInfo["tools"]): VeloArtifactInfo => ({
  name,
  description: "",
  parameters: [],
  ...(tools ? { tools } : {}),
});

const THOR = def("Generic.Scanner.ThorZIP", [{ name: "ThorZIP", url: "todo.thor-lite.zip.download.url" }]);

describe("preflightBundleArtifacts", () => {
  it("launches the artifacts that can run and names both kinds of casualty", async () => {
    const pre = await preflightBundleArtifacts(
      ["Windows.NTFS.MFT", "Generic.Scanner.ThorZIP", "Windows.Bogus.Typo"],
      async () => [def("Windows.NTFS.MFT"), THOR],
    );
    expect(pre.artifacts).toEqual(["Windows.NTFS.MFT"]);
    expect(pre.unknownArtifacts).toEqual(["Windows.Bogus.Typo"]);
    expect(pre.unavailableArtifacts).toEqual([
      { artifact: "Generic.Scanner.ThorZIP", reason: expect.stringContaining("ThorZIP") },
    ]);
    expect(pre.error).toBeUndefined();
    expect(pre.notes.join(" ")).toContain("Windows.Bogus.Typo");
    expect(pre.notes.join(" ")).toContain("Generic.Scanner.ThorZIP");
  });

  it("refuses the run when nothing is left, so no hunt is launched", async () => {
    const none = await preflightBundleArtifacts(["Windows.Bogus.Typo"], async () => [
      def("Windows.NTFS.MFT"),
    ]);
    expect(none.artifacts).toEqual([]);
    expect(none.error).toContain("Windows.Bogus.Typo");

    const noTool = await preflightBundleArtifacts(["Generic.Scanner.ThorZIP"], async () => [THOR]);
    expect(noTool.artifacts).toEqual([]);
    expect(noTool.error).toContain("ThorZIP");
  });

  // A diagnostics query must never be the thing that blocks a hunt: both of these launch the bundle
  // exactly as the analyst saved it. An empty catalog especially — an empty answer from the server is
  // not evidence that none of these artifacts exist.
  it("launches the bundle unchanged when the catalog read fails or comes back empty", async () => {
    const failed = await preflightBundleArtifacts(["A.B", "C.D"], async () => {
      throw new Error("gRPC unavailable");
    });
    expect(failed.artifacts).toEqual(["A.B", "C.D"]);
    expect(failed.error).toBeUndefined();
    expect(failed.notes.join(" ")).toContain("gRPC unavailable");
    expect(failed.definitions).toEqual([]);

    const empty = await preflightBundleArtifacts(["A.B"], async () => []);
    expect(empty.artifacts).toEqual(["A.B"]);
    expect(empty.notes).toEqual([]);
  });

  it("keeps the catalog it fetched, so the caller's time-scope plan needn't fetch it again", async () => {
    const pre = await preflightBundleArtifacts(["Windows.NTFS.MFT"], async () => [
      def("Windows.NTFS.MFT"),
      THOR,
    ]);
    expect(pre.definitions.map((d) => d.name)).toEqual(["Windows.NTFS.MFT", "Generic.Scanner.ThorZIP"]);
  });
});
