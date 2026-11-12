import { describe, it, expect, beforeEach } from "vitest";
import {
  mkdtemp,
  writeFile,
  appendFile,
  readFile,
  rename,
  truncate,
  utimes,
  stat,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AppendOnlyLogTail,
  FULL_REREAD_MAX_AGE_MS,
  type LogFold,
} from "../../src/storage/appendOnlyLogTail.js";

// #2584: a cached audit-log answer is used only while the file is exactly as the last full read, or
// this process's own append(), left it. Every other change takes the full re-read, and every answer
// equals what a reader with no cache gets (#1119 highest number on disk, fail closed; #2150 the last
// stored line; #2253 the file is the authority).

interface Acc {
  count: number;
  max: number;
}
const MAX_SEQ: LogFold<Acc> = {
  id: "max-seq",
  initial: { count: 0, max: 0 },
  step: (acc, line, index) => {
    let row: { seq?: unknown };
    try {
      row = JSON.parse(line) as { seq?: unknown };
    } catch {
      throw new Error(`bad line ${index + 1}`);
    }
    const seq = typeof row.seq === "number" ? row.seq : 0;
    return { count: acc.count + 1, max: Math.max(acc.max, seq) };
  },
};
const LINES: LogFold<null> = { id: "lines", initial: null, step: () => null };

const scope = { caseId: "c1", generation: "g1" };
const line = (seq: number, pad = "") => JSON.stringify({ seq, pad }) + "\n";
/** A log well past the 4 KiB tail window, so edits can land outside it. */
const bigLog = (n: number) => Array.from({ length: n }, (_, i) => line(i + 1, "p".repeat(200))).join("");

let dir: string;
let path: string;
let clock: number;
let tail: AppendOnlyLogTail;

/** What a reader with no cache answers — the reference every read must equal. */
async function fresh() {
  const r = await new AppendOnlyLogTail().read(scope, path, MAX_SEQ);
  return { state: r.state, lineCount: r.lineCount, lastLine: r.lastLine };
}
async function readBoth() {
  const r = await tail.read(scope, path, MAX_SEQ);
  expect({ state: r.state, lineCount: r.lineCount, lastLine: r.lastLine }).toEqual(await fresh());
  return r;
}
const ownAppend = (text: string) => tail.append(path, text, () => appendFile(path, text));
/** Same length, same mtime as before: only ctime (and the content) moved. */
async function rewriteKeepingMtime(text: string) {
  const before = await stat(path);
  await writeFile(path, text);
  await utimes(path, before.atime, before.mtime);
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-logtail-"));
  path = join(dir, "log.jsonl");
  clock = 1_000_000;
  tail = new AppendOnlyLogTail(() => clock);
});

describe("AppendOnlyLogTail (#2584)", () => {
  it("reports a missing log as empty", async () => {
    const r = await tail.read(scope, path, MAX_SEQ);
    expect(r).toMatchObject({ read: "absent", lineCount: 0, lastLine: null, state: { count: 0, max: 0 } });
  });

  it("reads in full first, then serves an untouched log from the snapshot", async () => {
    await writeFile(path, line(1) + line(2));
    expect((await readBoth()).read).toBe("full");
    expect((await readBoth()).read).toBe("cached");
  });

  it("follows this process's own appends without re-reading the log", async () => {
    await writeFile(path, line(1) + "\n" + line(2));
    await readBoth();
    await ownAppend(line(3));
    await ownAppend(line(4) + "\n" + line(5));
    const r = await readBoth();
    expect(r.read).toBe("cached");
    expect(r).toMatchObject({ lineCount: 5, state: { count: 5, max: 5 } });
    expect(r.lastLine).toBe(line(5).trimEnd());
  });

  it("re-reads in full after another writer's append (another process, a crash-written line)", async () => {
    await writeFile(path, line(1));
    await readBoth();
    await appendFile(path, line(90) + line(4));
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(90);
  });

  it("finds a higher number hidden by an in-place edit outside the tail window, then an own append", async () => {
    await writeFile(path, bigLog(40));
    await readBoth();
    const text = await readFile(path, "utf8");
    await rewriteKeepingMtime(text.replace('{"seq":2,', '{"seq":9,')); // same length, early line
    await ownAppend(line(41));
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(41);
    await rewriteKeepingMtime((await readFile(path, "utf8")).replace('{"seq":3,', '{"seq":8,'));
    expect((await readBoth()).read).toBe("full");
  });

  it("keeps failing closed on a line corrupted outside the tail window, even after an own append", async () => {
    await writeFile(path, bigLog(40));
    await readBoth();
    await rewriteKeepingMtime((await readFile(path, "utf8")).replace('{"seq":2,', '{"seq"!2,'));
    await ownAppend(line(41));
    await expect(tail.read(scope, path, MAX_SEQ)).rejects.toThrow(/bad line 2/);
    await expect(tail.read(scope, path, MAX_SEQ)).rejects.toThrow(/bad line 2/);
  });

  it("re-reads in full when an oversized last line was edited and blank lines appended", async () => {
    const huge = JSON.stringify({ seq: 2, pad: "h".repeat(9000) });
    await writeFile(path, line(1) + huge + "\n");
    await readBoth();
    await rewriteKeepingMtime(line(1) + huge.replace('"seq":2', '"seq":7') + "\n");
    await appendFile(path, "\n".repeat(5000));
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(7);
  });

  it("re-reads in full after a truncation, and after a truncation regrown past the old size", async () => {
    await writeFile(path, line(1) + line(2) + line(3));
    await readBoth();
    const text = await readFile(path, "utf8");
    await truncate(path, text.indexOf(line(3)));
    expect((await readBoth()).read).toBe("full");
    await writeFile(path, line(1));
    await appendFile(path, line(7, "y".repeat(80)));
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(7);
  });

  it("re-reads in full when the last bytes were rewritten with the mtime put back", async () => {
    await writeFile(path, line(1) + line(2));
    await readBoth();
    await rewriteKeepingMtime(line(1) + line(5));
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(5);
  });

  it("re-reads in full when the log was replaced by a new file (a restore, an atomic rewrite)", async () => {
    await writeFile(path, line(1));
    await readBoth();
    const other = join(dir, "other.jsonl");
    await writeFile(other, line(1) + line(40));
    await rename(other, path);
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(40);
  });

  it("re-reads in full after a delete and recreate", async () => {
    await writeFile(path, line(1) + line(2));
    await readBoth();
    await rm(path);
    expect((await tail.read(scope, path, MAX_SEQ)).read).toBe("absent");
    await writeFile(path, line(1) + line(2) + line(3));
    expect((await readBoth()).read).toBe("full");
  });

  it("drops the snapshot when another writer appends during an own append", async () => {
    await writeFile(path, line(1));
    await readBoth();
    await tail.append(path, line(2), async () => {
      await appendFile(path, line(70)); // lands between the pre-check and the write
      await appendFile(path, line(2));
    });
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(70);
  });

  it("drops the snapshot when an early line is rewritten to the same length during an own append", async () => {
    await writeFile(path, bigLog(40));
    await readBoth();
    await tail.append(path, line(41), async () => {
      const text = await readFile(path, "utf8");
      await writeFile(path, text.replace('{"seq":2,', '{"seq":900,').replace(',"pad":"pp', ',"pad":"'));
      await appendFile(path, line(41));
    });
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(900);
  });

  it("keeps failing closed when an early line is corrupted during an own append", async () => {
    await writeFile(path, bigLog(40));
    await readBoth();
    await tail.append(path, line(41), async () => {
      const text = await readFile(path, "utf8");
      await writeFile(path, text.replace('{"seq":2,', '{"seq"!2,'));
      await appendFile(path, line(41));
    });
    await expect(tail.read(scope, path, MAX_SEQ)).rejects.toThrow(/bad line 2/);
  });

  it("drops the snapshot when the file changed before an own append", async () => {
    await writeFile(path, line(1));
    await readBoth();
    await appendFile(path, line(60));
    await ownAppend(line(2));
    const r = await readBoth();
    expect(r.read).toBe("full");
    expect(r.state.max).toBe(60);
  });

  it("does not build on a partial last line; the full read decides, and nothing is cached", async () => {
    await writeFile(path, line(1));
    await readBoth();
    await appendFile(path, '{"seq":2');
    await expect(tail.read(scope, path, MAX_SEQ)).rejects.toThrow(/bad line 2/);
    await expect(tail.read(scope, path, MAX_SEQ)).rejects.toThrow(/bad line 2/);
    await appendFile(path, "}\n");
    expect((await readBoth()).read).toBe("full");
  });

  it("propagates a failed own append and keeps no snapshot", async () => {
    await writeFile(path, line(1));
    await readBoth();
    await expect(
      tail.append(path, line(2), async () => {
        throw new Error("disk full");
      }),
    ).rejects.toThrow("disk full");
    expect((await readBoth()).read).toBe("full");
  });

  it("re-reads in full for another incarnation of the case, and once the case was forgotten", async () => {
    await writeFile(path, line(1));
    await tail.read(scope, path, MAX_SEQ);
    expect((await tail.read({ caseId: "c1", generation: "g2" }, path, MAX_SEQ)).read).toBe("full");
    tail.forget("c1");
    expect((await tail.read({ caseId: "c1", generation: "g2" }, path, MAX_SEQ)).read).toBe("full");
  });

  it("re-reads in full once a snapshot is older than the trust window", async () => {
    await writeFile(path, line(1));
    await readBoth();
    await ownAppend(line(2));
    clock += FULL_REREAD_MAX_AGE_MS - 1;
    expect((await readBoth()).read).toBe("cached");
    clock += 1;
    expect((await readBoth()).read).toBe("full");
  });

  it("moves every fold's snapshot over an own append", async () => {
    await writeFile(path, line(1));
    await tail.read(scope, path, MAX_SEQ);
    await tail.read(scope, path, LINES);
    await ownAppend(line(2));
    const lines = await tail.read(scope, path, LINES);
    expect(lines).toMatchObject({ read: "cached", lineCount: 2, lastLine: line(2).trimEnd() });
    expect((await readBoth()).read).toBe("cached");
  });

  it("matches a full re-read across many own appends of varied size", async () => {
    await writeFile(path, "");
    expect((await readBoth()).read).toBe("full");
    for (let n = 1; n <= 60; n++) {
      await ownAppend(line(n, "z".repeat((n * 997) % 5000)) + (n % 7 === 0 ? "\n" : ""));
      expect((await readBoth()).read).toBe("cached");
    }
  });
});
