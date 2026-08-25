import { describe, it, expect } from "vitest";
import { preflightBundleArtifacts } from "../../src/integrations/velociraptor/bundlePreflight.js";
import { parseToolInventory } from "../../src/integrations/velociraptor/artifactTools.js";
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

  // The server's tool inventory is the authority: the catalog still shows THOR's placeholder URL long
  // after the analyst has uploaded the file, so the pre-flight must ask the inventory before dropping.
  it("keeps an artifact whose tool the inventory says the server now holds", async () => {
    const uploaded = parseToolInventory([
      { name: "ThorZIP", url: "todo.thor-lite.zip.download.url", hash: "9f809ea14b71" },
    ]);
    const pre = await preflightBundleArtifacts(
      ["Generic.Scanner.ThorZIP"],
      async () => [THOR],
      async () => uploaded,
    );
    expect(pre.artifacts).toEqual(["Generic.Scanner.ThorZIP"]);
    expect(pre.unavailableArtifacts).toEqual([]);
    expect(pre.error).toBeUndefined();
  });

  it("still checks the declared URLs, with a note, when the inventory read fails", async () => {
    const pre = await preflightBundleArtifacts(
      ["Windows.NTFS.MFT", "Generic.Scanner.ThorZIP"],
      async () => [def("Windows.NTFS.MFT"), THOR],
      async () => {
        throw new Error("inventory() unavailable");
      },
    );
    expect(pre.artifacts).toEqual(["Windows.NTFS.MFT"]);
    expect(pre.notes.join(" ")).toContain("inventory() unavailable");
    expect(pre.error).toBeUndefined();
  });

  // The air-gapped-server case: THOR and lolrmm were uploaded by hand, but the DetectRaptor YARA packs
  // are still only a GitHub URL. Every existing check passes them, Velociraptor then fails to fetch one
  // while compiling the hunt, and the analyst gets "no hunt id" for all 43 artifacts. Warn, do not drop:
  // on a server WITH egress these fetch fine, and dropping them would silently gut the sweep.
  it("warns about tools the server has not downloaded yet, without dropping their artifacts", async () => {
    const YARA = def("DetectRaptor.Generic.Detection.YaraFile", [
      { name: "FileYaraWindows", url: "https://github.com/x/full_windows.yar.gz" },
    ]);
    const pre = await preflightBundleArtifacts(
      ["DetectRaptor.Generic.Detection.YaraFile", "Generic.Scanner.ThorZIP"],
      async () => [YARA, THOR],
      async () =>
        parseToolInventory([
          { name: "FileYaraWindows", url: "https://github.com/x/full_windows.yar.gz" },
          { name: "ThorZIP", url: "todo.thor-lite.zip.download.url", hash: "ca5a50a52690" },
        ]),
    );
    expect(pre.artifacts).toEqual(["DetectRaptor.Generic.Detection.YaraFile", "Generic.Scanner.ThorZIP"]);
    expect(pre.unavailableArtifacts).toEqual([]);
    expect(pre.unheldTools).toEqual([
      {
        tool: "FileYaraWindows",
        url: "https://github.com/x/full_windows.yar.gz",
        artifacts: ["DetectRaptor.Generic.Detection.YaraFile"],
      },
    ]);
    expect(pre.notes.join(" ")).toContain("FileYaraWindows");
  });

  // The declared metadata NEVER carries a hash (it echoes the artifact YAML), so falling back to it
  // would report every tool in the bundle as missing — a false alarm on a perfectly healthy server.
  it("says nothing about unheld tools when the inventory read failed", async () => {
    const pre = await preflightBundleArtifacts(
      ["Windows.NTFS.MFT"],
      async () => [def("Windows.NTFS.MFT", [{ name: "Chainsaw", url: "https://github.com/x/chainsaw.zip" }])],
      async () => {
        throw new Error("inventory() unavailable");
      },
    );
    expect(pre.artifacts).toEqual(["Windows.NTFS.MFT"]);
    expect(pre.unheldTools).toEqual([]);
  });

  it("reports no unheld tools when the server holds every one of them", async () => {
    const pre = await preflightBundleArtifacts(
      ["Generic.Scanner.ThorZIP"],
      async () => [THOR],
      async () => parseToolInventory([{ name: "ThorZIP", url: "todo.x", hash: "ca5a50a52690" }]),
    );
    expect(pre.unheldTools).toEqual([]);
    expect(pre.notes).toEqual([]);
  });

  it("keeps the catalog it fetched, so the caller's time-scope plan needn't fetch it again", async () => {
    const pre = await preflightBundleArtifacts(["Windows.NTFS.MFT"], async () => [
      def("Windows.NTFS.MFT"),
      THOR,
    ]);
    expect(pre.definitions.map((d) => d.name)).toEqual(["Windows.NTFS.MFT", "Generic.Scanner.ThorZIP"]);
  });
});
