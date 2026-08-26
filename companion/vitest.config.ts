import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "vitest/config";

// ONE temp root per run, so the ~147 test files that call mkdtemp() stop stranding directories in
// the OS temp dir (issue #173 — 388,954 had piled up). Node reads TEMP/TMP/TMPDIR on every
// os.tmpdir() call, so pointing them here redirects every existing mkdtemp(join(tmpdir(), ...))
// into this root with no test change, and covers tests not written yet. tests/setup/tempRoot.ts
// deletes it when the run ends. Kept short ("dfir-vt-") because it prefixes every temp path in the
// suite and Windows still has a 260-char limit in play.
//
// The BASE this root is created in matters as much as the root itself. GitHub's Windows runners
// are Azure VMs with two disks: C: is the OS disk (a network-attached managed disk, IOPS-throttled
// and burst-credited) and D: is the physically-attached ephemeral SSD. The checkout and
// node_modules land on D:, but os.tmpdir() resolves to C:\Users\RUNNER~1\AppData\Local\Temp — so
// every mkdtemp() in the suite wrote its case trees, zips and SQLite files to the SLOW disk while
// module loading read from the fast one. RUNNER_TEMP is the runner's own scratch dir and is on the
// same disk as the checkout on every hosted platform, so preferring it puts test I/O and module
// I/O on one disk. Falsy-checked, not `??`: the bench workflow sets RUNNER_TEMP="" to reproduce the
// pre-fix path, and an empty string must fall through to tmpdir().
const runTempBase = process.env.RUNNER_TEMP || tmpdir();
const runTempRoot = mkdtempSync(join(runTempBase, "dfir-vt-"));
// Handed to the globalSetup teardown, which runs in this same (main) process.
process.env.DFIR_TEST_TMP_ROOT = runTempRoot;

export default defineConfig({
  test: {
    globalSetup: ["tests/setup/tempRoot.ts"],
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Vitest's 5s default is not a statement about how long these tests take — it's a statement
    // about how long they take ON AN IDLE MACHINE. The suite is ~384 files whose cost is dominated
    // by module collection/transform, so a full parallel run saturates every core and a test doing
    // <1s of real work can sit descheduled for >4s and "time out" (issue #173). That produced a
    // different set of failures on every run, which trains everyone to dismiss real regressions as
    // flake. 15s keeps genuinely-hung tests failing fast while removing the starvation false
    // positives — and removes the incentive to keep bumping timeouts one test at a time.
    //
    // 15s is that reasoning measured on LINUX. The Windows runner has fewer cores, slower
    // filesystem calls and a virus scanner in the path, and it reproduced the exact symptom this
    // comment describes: consecutive runs failed a DIFFERENT set of files each time — stateStore,
    // encryptedCaseRoutes, playbookHunts, veloImportExternal, backupManager, importWriterExclusion
    // — nearly every one reporting "Test timed out in 15000ms" rather than an assertion. Applying
    // the idle-Linux number to a slower platform re-creates the starvation false positives the
    // number exists to remove, so it scales with the platform rather than per test.
    testTimeout: process.platform === "win32" ? 45_000 : 15_000,
    // Same reasoning for setup/teardown: a beforeEach doing mkdtemp + createApp() starves too, and
    // a hook timeout fails the whole file rather than one test.
    hookTimeout: process.platform === "win32" ? 45_000 : 15_000,
    // Real OCR (TesseractOcrRunner) hits the network for language data and isn't mocked by
    // every test that triggers a capture — off by default so the suite never depends on
    // network access; tests/server/ocrSearchRoute.test.ts opts back in per test.
    env: {
      DFIR_OCR_SEARCH: "off",
      // Redirect the worker pool's temp dir into the per-run root above. All three names are set
      // because Node checks TEMP then TMP on Windows and TMPDIR elsewhere.
      TEMP: runTempRoot,
      TMP: runTempRoot,
      TMPDIR: runTempRoot,
    },
  },
});
