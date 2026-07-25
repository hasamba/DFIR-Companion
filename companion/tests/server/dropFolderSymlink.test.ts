import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, symlink, link, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { MockProvider } from "../../src/providers/provider.js";
import { createApp } from "../../src/server.js";

// #243: the drop-folder auto-importer used stat() (follows symlinks) and had no nlink check
// (a hardlink is indistinguishable from a normal file via stat), so a symlink or hardlink
// planted in a case's drop/ folder — realistic since it's documented as a Dropbox/OneDrive-synced
// inbox — could smuggle host files (/etc/shadow, .instance-secret, another case's case.json) into
// the case as "imported evidence". These tests exercise the REAL drop-folder poller end to end
// (not the private lstat helpers directly, since listDropFiles/processDropFile/moveDropFile are
// closures inside createApp with no exported surface) and assert the secret content never reaches
// the case, while a normal file dropped alongside it still imports correctly (no over-blocking).
//
// Verified against the pre-fix server.ts (before #259/this hardening): the hardlink test genuinely
// fails without the nlink guard (the hardlinked file gets processed and moved to _failed/, proving
// its content was read). The symlink "plant one and let the poller find it" case happened to be
// accidentally safe even before this fix too — Dirent.isFile() already returns false for a symlink
// dirent, so it was filtered before ever reaching stat() — but the REAL pre-fix symlink bug was a
// narrower TOCTOU race (a file that reads as a normal file when first listed, then gets swapped to
// a symlink before the read/move that follows once it's marked "ready"). That race isn't exercised
// here — it would need to land squarely inside the drop poller's sub-second settle window — so the
// symlink test below documents the now-deliberate (not incidental) guarantee at the listing stage,
// while the processDropFile/moveDropFile lstat re-checks that close the TOCTOU window itself remain
// unverified by an automated test.

function findingPipeline(stateStore: StateStore): AnalysisPipeline {
  return new AnalysisPipeline({
    provider: new MockProvider("mock", JSON.stringify({
      findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
      timelineNote: "n", summary: "s",
    })),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

const VELO_EVIDENCE = JSON.stringify([{
  _Source: "Windows.Detection.X", Detection: { Name: "Bad" },
  EventTime: "2026-01-01T00:00:00Z", EntryPath: "c:\\x.exe",
}]);

async function runDropSweep(caseId: string, dropDir: string, seedSecretLinks: (dropDir: string, secretFile: string) => Promise<void>) {
  const prevPoll = process.env.DFIR_DROP_POLL_S;
  process.env.DFIR_DROP_POLL_S = "2"; // minimum settle: seen at poll 1, imported at poll 2
  try {
    const root = await mkdtemp(join(tmpdir(), "dfir-dropsymlink-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const jobManager = new JobManager();
    const app = createApp(store, {
      pipeline: findingPipeline(stateStore), stateStore, jobManager,
      dropStatusStore: new DropStatusStore(store), // presence ARMS the drop-folder poller
    });
    await request(app).post("/cases").send({ caseId, name: "n", investigator: "i", aiProvider: "mock" });

    const caseDropDir = join(store.caseDir(caseId), "drop");
    await mkdir(caseDropDir, { recursive: true });
    // A secret file OUTSIDE the drop folder, plus a symlink/hardlink to it planted INSIDE.
    const secretDir = await mkdtemp(join(tmpdir(), "dfir-dropsymlink-secret-"));
    const secretFile = join(secretDir, "shadow.txt");
    await writeFile(secretFile, "TOPSECRET-HOST-FILE-CONTENTS-4f8a2b", "utf8");
    await seedSecretLinks(caseDropDir, secretFile);
    // A normal, legitimately-dropped file alongside it — proves the guard doesn't over-block.
    await writeFile(join(caseDropDir, "evidence.json"), VELO_EVIDENCE, "utf8");

    let jobs: { kind: string; label?: string }[] = [];
    for (let i = 0; i < 200 && !jobs.some((j) => j.kind === "import"); i++) {
      await new Promise((r) => setTimeout(r, 50));
      jobs = jobManager.list(caseId);
    }
    expect(jobs.some((j) => j.kind === "import")).toBe(true);
    // Give the sweep a moment past job completion to finish writing state/moving files.
    await new Promise((r) => setTimeout(r, 200));

    const state = await stateStore.load(caseId);
    const haystack = JSON.stringify(state);
    return { caseDropDir, haystack };
  } finally {
    if (prevPoll === undefined) delete process.env.DFIR_DROP_POLL_S;
    else process.env.DFIR_DROP_POLL_S = prevPoll;
  }
}

describe("drop-folder auto-importer — symlink/hardlink rejection (#243)", () => {
  it("never reads a symlink's target content into the case, but still imports a normal file", async () => {
    const { caseDropDir, haystack } = await runDropSweep("c1", "drop", async (dropDir, secretFile) => {
      await symlink(secretFile, join(dropDir, "innocuous.json"));
    });
    expect(haystack).not.toContain("TOPSECRET-HOST-FILE-CONTENTS");
    expect(haystack).toContain("Bad"); // the legit Velociraptor detection DID import
    // The symlink itself is never even recognized by listDropFiles, so it's left exactly where
    // it was dropped — never moved to _processed/ or _failed/.
    const remaining = await readdir(caseDropDir);
    expect(remaining).toContain("innocuous.json");
  }, 15000);

  it("never reads a hardlink's target content into the case, but still imports a normal file", async () => {
    const { caseDropDir, haystack } = await runDropSweep("c2", "drop", async (dropDir, secretFile) => {
      await link(secretFile, join(dropDir, "innocuous2.json"));
    });
    expect(haystack).not.toContain("TOPSECRET-HOST-FILE-CONTENTS");
    expect(haystack).toContain("Bad");
    const remaining = await readdir(caseDropDir);
    expect(remaining).toContain("innocuous2.json");
  }, 15000);
});
