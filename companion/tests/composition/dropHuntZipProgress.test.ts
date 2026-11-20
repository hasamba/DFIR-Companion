import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { JobManager } from "../../src/analysis/jobManager.js";
import type { Job } from "../../src/analysis/jobRegistry.js";
import { HUNT_ZIP_LEDGER_DIR } from "../../src/composition/dropHuntZipLedger.js";
import { buildZip, huntTree } from "../helpers/huntExportFixture.js";
import { makeHarness } from "../helpers/dropHuntHarness.js";

// #2742: while a hunt zip imports through the drop folder, the Jobs row counts the zip's result
// files (done of total), names the one importing, and shows a speed and ETA — not "1 file" at 0/1.
// perClientJson holds 9 result files to import (3 clients x 3 artifacts). Synthetic data only.

const THOR = JSON.stringify({
  level: "Warning",
  module: "Filescan",
  message: "Suspicious file",
  time: "2026-05-02T10:00:00Z",
  file: "C:\\Temp\\a.exe",
});
const pause = () => new Promise((r) => setTimeout(r, 5));

async function harness() {
  const jobManager = new JobManager();
  const h = await makeHarness({ jobManager });
  const newest = (): Job => jobManager.get(jobManager.list("c1")[0].id)!;
  return { h, newest };
}

describe("drop folder — hunt zip progress on the Jobs row (#2742)", () => {
  it("counts result files as they import, names the current one, and shows an ETA", async () => {
    const { h, newest } = await harness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
    let mid: Job | undefined;
    h.onIngest = async (n) => {
      await pause();
      if (n === 3) mid = structuredClone(newest());
    };
    await h.sweep();
    await h.sweep();
    expect(mid?.label).toBe("drop import (hunt export, 9 result files)");
    expect(mid?.progress).toMatchObject({ done: 2, total: 9 });
    expect(mid?.detail).toMatch(/^hunt\.zip — hunt file 3 of 9: .+\.json$/);
    expect(mid?.etaAt).toBeDefined();
    expect(mid?.throughputPerSecond).toBeGreaterThan(0);
    expect(newest()).toMatchObject({ status: "succeeded", progress: { done: 9, total: 9 } });
  });

  it("a hunt zip beside a plain file: the total covers both", async () => {
    const { h, newest } = await harness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
    await writeFile(join(h.dropDir, "thor.json"), THOR);
    await h.sweep();
    await h.sweep();
    expect(newest().label).toBe("drop import (hunt export, 9 result files + 1 other file)");
    expect(newest().progress).toMatchObject({ done: 10, total: 10 });
  });

  it("after a crash, the restarted import starts its count at the files already imported", async () => {
    const { h, newest } = await harness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
    await h.sweep();
    h.hangAfter = 4;
    await h.sweepUntilHang();
    h.restart();
    let first: Job | undefined;
    h.onIngest = () => {
      first ??= structuredClone(newest());
    };
    await h.sweep(); // a restarted folder lists first; the zip imports once its size is stable
    await h.sweep();
    // Ingest call 5 is the first of the restarted run: four files were recorded before the crash.
    expect(first?.progress).toMatchObject({ done: 4, total: 9, stepBaseline: 4 });
    expect(newest().progress).toMatchObject({ done: 9, total: 9 });
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "a zip left in drop/ because its progress could not be recorded is not shown as finished",
    async () => {
      const { h, newest } = await harness();
      await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
      const ledgerDir = join(h.store.stateDir("c1"), HUNT_ZIP_LEDGER_DIR);
      const ledgerFile = async () => join(ledgerDir, (await readdir(ledgerDir))[0]);
      h.onIngest = async (n) => {
        if (n === 2) await chmod(await ledgerFile(), 0o444);
      };
      await h.sweep();
      await h.sweep();
      expect(newest().progress).toMatchObject({ done: 2, total: 9 });
      await chmod(await ledgerFile(), 0o644);
      h.onIngest = null;
      await h.sweep();
      expect(newest().progress).toMatchObject({ done: 9, total: 9 });
    },
  );
});
