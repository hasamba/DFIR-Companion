import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDropLinkReporter } from "../../src/composition/dropLinkReport.js";
import { DROP_LOG_FILE } from "../../src/analysis/dropLog.js";

// #2788: a symlink or hardlink in drop/ is refused (security) but used to be refused silently.
// It is now reported once per file — a server log line and a drop-log.txt SKIPPED line — and not
// again on every poll while it stays in place.
async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dfir-droplink-"));
  const dropDir = join(root, "c1", "drop");
  await mkdir(dropDir, { recursive: true });
  const lines: string[] = [];
  const reporter = createDropLinkReporter({ casesRoot: () => root, log: (l) => lines.push(l) });
  const dropLog = async () => readFile(join(dropDir, DROP_LOG_FILE), "utf8").catch(() => "");
  return { dropDir, lines, reporter, dropLog };
}

describe("drop-folder link reporting (#2788)", () => {
  it("logs each link once, to the server log and drop-log.txt, not on every poll", async () => {
    const { dropDir, lines, reporter, dropLog } = await setup();
    const links = [
      { relpath: "a.json", kind: "symlink" as const },
      { relpath: join("sub", "b.json"), kind: "hardlink" as const },
    ];
    await reporter.report("c1", dropDir, links);
    await reporter.report("c1", dropDir, links);
    await reporter.report("c1", dropDir, links);

    const log = (await dropLog()).trim().split("\n");
    expect(log).toHaveLength(2);
    expect(log[0]).toMatch(/SKIPPED\s+a\.json\s+— symbolic link — not imported \(security\)/);
    expect(log[1]).toMatch(/SKIPPED\s+sub.b\.json\s+— hardlink — not imported \(security\)/);
    expect(lines.filter((l) => l.includes("a.json"))).toHaveLength(1);
    expect(lines.filter((l) => l.includes("b.json"))).toHaveLength(1);
    expect(lines[0]).toContain("[drop] c1:");
  });

  it("reports a link again after it was removed and planted anew", async () => {
    const { dropDir, reporter, dropLog } = await setup();
    const link = { relpath: "a.json", kind: "symlink" as const };
    await reporter.report("c1", dropDir, [link]);
    await reporter.report("c1", dropDir, []);
    await reporter.report("c1", dropDir, [link]);
    expect((await dropLog()).trim().split("\n")).toHaveLength(2);
  });

  it("still logs each link once to the server log when drop-log.txt cannot be written", async () => {
    const { dropDir, lines, reporter } = await setup();
    const missing = join(dropDir, "gone"); // appendFile fails: the directory does not exist
    const links = [{ relpath: "a.json", kind: "symlink" as const }];
    await reporter.report("c1", missing, links);
    await reporter.report("c1", missing, links);
    await reporter.report("c1", missing, links);
    expect(lines.filter((l) => l.includes("skipped a.json"))).toHaveLength(1);
    expect(lines.filter((l) => l.includes("log append failed"))).toHaveLength(1);
  });

  it("writes nothing when there are no links", async () => {
    const { dropDir, lines, reporter, dropLog } = await setup();
    await reporter.report("c1", dropDir, []);
    expect(await dropLog()).toBe("");
    expect(lines).toEqual([]);
  });
});
