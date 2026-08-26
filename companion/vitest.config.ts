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
// WHICH DISK that root lands on matters more than anything else in this file. GitHub's Windows
// runners are Azure VMs with two disks: C: is the OS disk (network-attached, IOPS-throttled) and
// D: is the physically-attached ephemeral SSD. The checkout and node_modules are on D:, but
// os.tmpdir() resolves to C:\Users\RUNNER~1\AppData\Local\Temp — so the suite read its modules
// from the fast disk and wrote every case tree, zip and SQLite file to the slow one. Measured on
// the runner (create + write + fsync + unlink, 300 files): C: 5.0-14.0ms/file against D:
// 0.25-0.64ms/file, a 10-34x gap. RUNNER_TEMP is the runner's own scratch dir and sits on the same
// disk as the checkout on every hosted platform, so preferring it puts test I/O and module I/O on
// one disk; off CI it is unset and this is exactly the old behaviour. Falsy-checked rather than
// `??` so the bench workflow can set RUNNER_TEMP="" to reproduce the pre-fix path.
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
    // about how long they take ON AN IDLE MACHINE. A full parallel run of 670 files saturates the
    // box, and a test doing <1s of real work can sit waiting for >4s and "time out" (issue #173).
    // That produced a different set of failures on every run, which trains everyone to dismiss real
    // regressions as flake. 15s keeps genuinely-hung tests failing fast while removing those false
    // positives — and removes the incentive to keep bumping timeouts one test at a time.
    //
    // The Windows number was 45s for the same reason, and by #642 it had stopped being enough: runs
    // of an IDENTICAL commit failed a different, disjoint set of files each time, every one of them
    // a timeout rather than an assertion. Two claims this comment used to make were the reason the
    // remedy kept being a bigger constant, and both were wrong when measured:
    //
    //   - "cost is dominated by module collection/transform". Not at 670 files. Same commit, Linux
    //     vs Windows: collect 290s vs 340s and transform 15s vs 14s — near-identical. The entire
    //     platform gap was test execution, 453s vs 1788s.
    //   - "the Windows runner has fewer cores". It does not. Both report availableParallelism 4, so
    //     both run vitest's default pool of 3 forks — and 3 workers on 4 cores cannot deschedule
    //     anyone for 45 seconds. The stalls were never CPU.
    //
    // The distribution said the same thing: the median file went 38ms -> 44ms (1.16x) while p90
    // went 708ms -> 6233ms (8.8x). Uniform slowness and a heavy tail need opposite fixes, and only
    // an aggregate makes them look alike. The tail was the C: temp root above; moving it to D: is
    // what this file now does, measured over 6 configurations x 3 runs (see
    // .github/workflows/windows-test-bench.yml): wall 748.8s -> 383.9s, test phase 1667.9s ->
    // 567.4s, and per-file p90 6381ms -> 914ms, against 708ms on Linux. The same matrix rejected
    // the two other candidates on their numbers: capping the fork pool at 2 made it WORSE (875.4s,
    // +17%), and a Defender exclusion bought 12% on its own but nothing once the I/O was already on
    // the fast disk.
    //
    // 45s stays. It is the ceiling that keeps a hung test from burning the job's 40 minutes, not an
    // allowance any test needs: the slowest test actually governed by it went 26.9s -> 16.1s, so
    // headroom went 18.1s -> 28.9s. (Slower tests exist — the full-pipeline run reached 46.5s — but
    // they pass their own timeout to it() and this number never applied to them.) Tightening 45s is
    // a separate change that needs its own run of the bench matrix, not a guess.
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
