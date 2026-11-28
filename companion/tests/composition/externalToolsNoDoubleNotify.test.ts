import { describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createExternalTools } from "../../src/composition/externalTools.js";
import { dropDirOf } from "../../src/composition/dropFolder.js";
import { loadToolConfig, type ToolId, type ToolConfig } from "../../src/integrations/tools/toolConfig.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";
import type { Notifier } from "../../src/integrations/notify/notifyDispatch.js";

// #3036 — a dashboard tool run sends its own import message from the route. The drop-folder sweep
// runs the SAME tool path and reports the file in its own sweep message, so the shared tool path
// itself must send nothing: one message per file, never two. Synthetic data only.

const refuse = (): never => {
  throw new Error("not expected on this path");
};

const runner: ToolRunner = async (_binary, args) => {
  if (args.includes("--version")) return { stdout: "Hayabusa v3.2.0", stderr: "", code: 0 };
  await writeFile(args[args.indexOf("-o") + 1], "Timestamp,RuleTitle\n", "utf8");
  return { stdout: "", stderr: "", code: 0 };
};

describe("the shared tool path sends no import message of its own (#3036)", () => {
  it("a drop-folder tool run leaves the message to the sweep", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-tool-nodouble-"));
    const store = new CaseStore(join(root, "cases"));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const dispatch = vi.fn(async () => undefined);
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "/opt/hayabusa" })!;
    const tools = createExternalTools({
      store,
      options: {
        toolRunner: runner,
        loadToolConfigs: () => new Map<ToolId, ToolConfig>([["hayabusa", cfg]]),
        notifier: { dispatch } as unknown as Notifier,
      },
      resolveImportKind: refuse,
      ingestStreamed: async () => ({
        storedName: "x.out",
        addedEvents: 1,
        addedIocs: 0,
        analyzed: true,
        counts: { added: 1, highCritical: 0 },
      }),
      persistRawEvidence: refuse,
      pushImportCheckpoint: refuse,
    });
    const dropDir = dropDirOf(store, "c1");
    await mkdir(dropDir, { recursive: true });
    await writeFile(join(dropDir, "Security.evtx"), "synthetic");
    const r = await tools.runDropToolAndIngest("c1", "hayabusa", join(dropDir, "Security.evtx"), {
      name: "Security.evtx",
      dropRelpath: "Security.evtx",
    });
    expect(r).toEqual({ submitted: false, counts: { added: 1, highCritical: 0 } });
    expect(dispatch).not.toHaveBeenCalled();
  });
});
