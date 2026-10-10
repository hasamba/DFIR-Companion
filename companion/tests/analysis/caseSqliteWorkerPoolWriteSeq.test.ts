import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseSqliteWorkerPool } from "../../src/analysis/caseSqliteWorkerPool.js";

// #2057: the report-lite cache keys on a per-database write sequence. It must move, at submission,
// on every op that can change the file (plain writes and the exclusive restore) and never on a read.

// A stand-in worker that answers every request; the pool's bookkeeping is what is under test.
const ECHO = `
const { parentPort } = require("node:worker_threads");
parentPort.on("message", (m) => parentPort.postMessage({ requestId: m.requestId, value: true }));
`;

describe("CaseSqliteWorkerPool write sequence (#2057)", () => {
  it("bumps on writes and exclusive ops at submission, never on reads", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-writeseq-"));
    const db = join(dir, "investigation.sqlite");
    const other = join(dir, "other.sqlite");
    const pool = new CaseSqliteWorkerPool(ECHO);
    expect(pool.writeSequence(db)).toBe(0);

    await pool.request({ op: "loadState", dbPath: db });
    await pool.request({ op: "stateExists", dbPath: db });
    expect(pool.writeSequence(db)).toBe(0);

    const pending = pool.request({ op: "saveState", dbPath: db });
    expect(pool.writeSequence(db)).toBe(1); // already moved while the write is in flight
    await pending;

    await pool.request({ op: "restoreDatabase", sourcePath: other, targetPath: db });
    expect(pool.writeSequence(db)).toBe(2);
    expect(pool.writeSequence(other)).toBe(0);
  });
});
