import { describe, it, expect, afterEach } from "vitest";
import { join } from "node:path";
import { appendFile, chmod, readdir, readFile, writeFile } from "node:fs/promises";
import { buildZip, expectedRowKeys, huntTree } from "../helpers/huntExportFixture.js";
import { dropLog, exists, listFiles, makeHarness } from "../helpers/dropHuntHarness.js";
import { HUNT_ZIP_LEDGER_DIR } from "../../src/composition/dropHuntZipLedger.js";

// #2714: a Velociraptor hunt export dropped as a .zip imports every row exactly once, reading only
// the members it needs; one bad member never stops the rest; a crash resumes without duplicates.

afterEach(() => {
  delete process.env.DFIR_DROP_MAX_BYTES;
});

async function dropZip(zip: Buffer, name = "hunt.zip", opts: { dropMaxBytes?: number } = {}) {
  const h = await makeHarness(opts);
  await writeFile(join(h.dropDir, name), zip);
  await h.sweep();
  await h.sweep();
  return h;
}

describe("drop folder — Velociraptor hunt export zip (#2714)", () => {
  for (const layout of ["full", "perClientJson", "huntWide", "csvOnlyUsers"] as const) {
    it(`${layout}: every row imported exactly once, with the right host`, async () => {
      const h = await dropZip(await buildZip(huntTree(layout)));
      expect(h.rowKeys()).toEqual(expectedRowKeys(layout));
      expect(await listFiles(h.dropDir)).toEqual(["README.txt", "_processed/hunt.zip", "drop-log.txt"]);
    });
  }

  it("reads a ZIP64 archive", async () => {
    const h = await dropZip(await buildZip(huntTree("full"), { zip64: true }));
    expect(h.rowKeys()).toEqual(expectedRowKeys("full"));
  });

  it("names per-client hosts from the client folder and logs the members not read", async () => {
    const h = await dropZip(await buildZip(huntTree("perClientJson", "H.TEST0001")));
    const hosts = h.calls.filter((c) => c.name === "Windows.Network.Netstat.json").map((c) => c.host);
    expect(hosts.sort()).toEqual(["SRV-CHARLIE", "WS-ALPHA", "WS-BRAVO"]);
    const log = await dropLog(h.dropDir);
    expect(log).toMatch(/IMPORTED\s+hunt\.zip/);
  });

  it("#2810: imports one hunt-wide copy per artifact and logs the per-client copies not read", async () => {
    const h = await dropZip(await buildZip(huntTree("full", "H.TEST0001")));
    expect(h.calls.map((c) => c.name).sort()).toEqual([
      "All Windows.Network.Netstat.json",
      "All Windows.Sys.Users%2FUsers.json",
      "All Windows.System.Pslist.json",
    ]);
    expect(h.rowKeys()).toEqual(expectedRowKeys("full"));
    const log = await dropLog(h.dropDir);
    expect(log).toMatch(/SKIPPED\s+hunt\.zip\s+— Velociraptor hunt export: 34 member\(s\) not read/);
    expect(log).toMatch(/IMPORTED\s+hunt\.zip/);
  });

  it("one broken member lands in _failed/<zip>/… while the rest import and the zip is processed", async () => {
    const tree = huntTree("perClientJson");
    const h = await makeHarness();
    h.failOn.add("Windows.Network.Netstat.json"); // every client's netstat fails to parse
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(tree));
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(6);
    const files = await listFiles(h.dropDir);
    expect(files).toContain("_processed/hunt.zip");
    const failed = files.filter((f) => f.startsWith("_failed/hunt/"));
    expect(failed).toEqual([
      "_failed/hunt/SRV-CHARLIE-C.0000000000000003/results/Windows.Network.Netstat.json",
      "_failed/hunt/WS-ALPHA-C.0000000000000001/results/Windows.Network.Netstat.json",
      "_failed/hunt/WS-BRAVO-C.0000000000000002/results/Windows.Network.Netstat.json",
    ]);
    const got = await readFile(join(h.dropDir, failed[1]), "utf8");
    expect(got).toBe(tree["WS-ALPHA-C.0000000000000001/results/Windows.Network.Netstat.json"]);
    const log = await dropLog(h.dropDir);
    expect(log).toMatch(
      /FAILED\s+hunt\.zip!WS-ALPHA-C\.0000000000000001\/results\/Windows\.Network\.Netstat\.json\s+— synthetic parse failure/,
    );
    expect(log).toMatch(/IMPORTED\s+hunt\.zip\s+— 6 of 9 hunt result file\(s\) imported, 3 failed/);
  });

  it("a corrupt member is reported and the rest still import", async () => {
    const tree = huntTree("perClientJson");
    const bad = "WS-BRAVO-C.0000000000000002/results/Windows.System.Pslist.json";
    const h = await dropZip(await buildZip(tree, { corrupt: [bad] }));
    expect(h.calls).toHaveLength(8);
    expect(await dropLog(h.dropDir)).toMatch(/FAILED\s+hunt\.zip!WS-BRAVO.*could not be read from the zip/);
  });

  it("a zip where no member imports goes to _failed/", async () => {
    const h = await makeHarness();
    for (const a of [
      "Windows.System.Pslist.json",
      "Windows.Network.Netstat.json",
      "Windows.Sys.Users%2FUsers.json",
    ])
      h.failOn.add(a);
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
    await h.sweep();
    await h.sweep();
    expect(await listFiles(h.dropDir)).toContain("_failed/hunt.zip");
  });

  it("a crash mid-zip, then a restart, adds no duplicates and finishes the rest", async () => {
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("full")));
    await h.sweep();
    h.hangAfter = 1; // one member imported, the second never returns: the process dies there
    await h.sweepUntilHang();
    expect(h.calls).toHaveLength(1);
    h.restart(); // fresh in-memory state over the same case dir
    await h.sweep();
    await h.sweep();
    expect(h.rowKeys()).toEqual(expectedRowKeys("full"));
    expect(await listFiles(h.dropDir)).toContain("_processed/hunt.zip");
  });

  it("resumes from the ledger: members already recorded are not imported again", async () => {
    const h = await makeHarness();
    const zip = await buildZip(huntTree("perClientJson"));
    await writeFile(join(h.dropDir, "hunt.zip"), zip);
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(9);
    // Simulate "imported but not yet moved": put the same archive back while its ledger is still there.
    const ledgerDir = join(h.store.stateDir("c1"), HUNT_ZIP_LEDGER_DIR);
    const ledgers = await readdir(ledgerDir).catch(() => [] as string[]);
    expect(ledgers.length).toBe(1); // kept until a later sweep sees the zip gone
    await writeFile(join(h.dropDir, "hunt.zip"), zip);
    h.restart();
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(9); // nothing imported twice
  });

  it("#2810: a run begun per-client before the change finishes that artifact per-client, without duplicates", async () => {
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("full")));
    await h.sweep();
    h.hangAfter = 1;
    await h.sweepUntilHang(); // the ledger exists; one hunt-wide member is recorded
    const ledgerDir = join(h.store.stateDir("c1"), HUNT_ZIP_LEDGER_DIR);
    const [file] = await readdir(ledgerDir);
    // As an older build would have left it: one per-client Pslist file already imported.
    const pc = "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json";
    await appendFile(join(ledgerDir, file), JSON.stringify({ member: pc, ok: true }) + "\n");
    h.restart();
    await h.sweep();
    await h.sweep();
    const names = h.calls.map((c) => c.name);
    expect(names).not.toContain("All Windows.System.Pslist.json");
    expect(names.filter((n) => n === "Windows.System.Pslist.json")).toHaveLength(2); // the other two clients
    expect(await listFiles(h.dropDir)).toContain("_processed/hunt.zip");
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "a progress-record failure leaves the zip in drop/ and the next sweep resumes without duplicates",
    async () => {
      const h = await makeHarness();
      await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
      const ledgerDir = join(h.store.stateDir("c1"), HUNT_ZIP_LEDGER_DIR);
      const ledgerFile = async () => join(ledgerDir, (await readdir(ledgerDir))[0]);
      h.onIngest = async (n) => {
        if (n === 2) await chmod(await ledgerFile(), 0o444); // the next append fails
      };
      await h.sweep();
      await h.sweep();
      expect(h.calls).toHaveLength(2); // the second member imported, then its record failed
      expect(await exists(join(h.dropDir, "hunt.zip"))).toBe(true);
      await chmod(await ledgerFile(), 0o644);
      h.onIngest = null;
      await h.sweep();
      expect(h.rowKeys()).toEqual(expectedRowKeys("perClientJson"));
      expect(await listFiles(h.dropDir)).toContain("_processed/hunt.zip");
    },
  );

  it("carries a member's import caveat onto the zip's drop-log line", async () => {
    const tree = {
      ...huntTree("perClientJson"),
      "WS-ALPHA-C.0000000000000001/results/notes.json": JSON.stringify([{ foo: "bar", n: 1 }]),
    };
    const h = await dropZip(await buildZip(tree));
    const line = (await dropLog(h.dropDir)).split("\n").find((l) => /IMPORTED\s+hunt\.zip/.test(l)) ?? "";
    expect(line).toContain("results/notes.json:");
  });

  it("prunes a ledger once its zip has left the drop folder", async () => {
    const h = await dropZip(await buildZip(huntTree("perClientJson")));
    await h.sweep();
    const ledgerDir = join(h.store.stateDir("c1"), HUNT_ZIP_LEDGER_DIR);
    expect(await readdir(ledgerDir)).toEqual([]);
  });

  it("refuses traversal, symlink and zip-bomb members; the rest import", async () => {
    const tree = {
      ...huntTree("perClientJson"),
      "xx/evil.json": '{"Pid":1}\n',
      "WS-ALPHA-C.0000000000000001/results/Linked.json": "/etc/passwd",
      "WS-ALPHA-C.0000000000000001/results/Bomb.json": " ".repeat(4 * 1024 * 1024),
    };
    const zip = await buildZip(tree, {
      symlinks: ["WS-ALPHA-C.0000000000000001/results/Linked.json"],
      patch: [["xx/evil.json", "../evil.json"]],
    });
    const h = await dropZip(zip);
    expect(h.calls).toHaveLength(9);
    const log = await dropLog(h.dropDir);
    expect(log).toMatch(/FAILED\s+hunt\.zip!\.\.\/evil\.json\s+— unsafe member name/);
    expect(log).toMatch(/FAILED\s+hunt\.zip!WS-ALPHA.*Linked\.json\s+— symbolic link member — refused/);
    expect(log).toMatch(/FAILED\s+hunt\.zip!WS-ALPHA.*Bomb\.json\s+— compression ratio of a zip bomb/);
    const files = await listFiles(join(h.dropDir, ".."));
    expect(files.some((f) => f.endsWith("evil.json"))).toBe(false);
    expect(files.some((f) => f.includes("Linked.json"))).toBe(false);
  });

  it("a member over the in-memory cap that does not stream fails and is extracted", async () => {
    const tree = huntTree("perClientJson");
    const big = "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json";
    const h = await dropZip(await buildZip(tree), "hunt.zip", { dropMaxBytes: tree[big].length - 1 });
    // Every member here is about that size; the ones over the cap stage, are not a streaming kind, fail.
    const failed = (await listFiles(h.dropDir)).filter((f) => f.startsWith("_failed/hunt/"));
    expect(failed).toContain(`_failed/hunt/${big}`);
    expect(await dropLog(h.dropDir)).toMatch(/in-memory cap/);
    expect(await exists(join(h.dropDir, ".hunt-zip-staging"))).toBe(true); // cleared on the next sweep
    await h.sweep();
    expect(await exists(join(h.dropDir, ".hunt-zip-staging"))).toBe(false);
  });

  it("a zip that is not a hunt export still routes to the tool path", async () => {
    const zip = await buildZip({ "sample.exe": "MZ...", "readme.txt": "x" });
    const h = await dropZip(zip, "sample.zip");
    expect(h.calls).toEqual([]);
    expect(await exists(join(h.dropDir, "sample.zip"))).toBe(true); // pending for a tool, left in place
  });
});
