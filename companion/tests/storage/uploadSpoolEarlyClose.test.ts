import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { mkdtemp, open } from "node:fs/promises";
import type { IncomingMessage } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { spoolUpload, UploadAbortedError } from "../../src/storage/uploadSpool.js";

// A client that hangs up while the spool file is still being opened (#2336 review): the request's
// "close" event has already fired before the pump attaches its listeners, so the pump must notice
// the destroyed request itself, close the descriptor and remove the partial file.
function fakeRequest(): IncomingMessage {
  const req = new PassThrough() as unknown as IncomingMessage & { complete: boolean };
  req.complete = false;
  req.pause();
  return req;
}

describe("spoolUpload — client disconnects before the pump starts (#2336)", () => {
  it("rejects with UploadAbortedError and removes the spool file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "spool-early-"));
    const path = join(dir, "u.part");
    const req = fakeRequest();
    const opener = async (p: string) => {
      const handle = await open(p, "wx");
      req.destroy(); // the client hangs up during the asynchronous open
      await new Promise((r) => setImmediate(r)); // let "close" fire before the pump listens
      return handle;
    };
    const settled = await Promise.race([
      spoolUpload(req, path, 1024, opener).then(
        () => "resolved",
        (e: unknown) => e,
      ),
      new Promise((r) => setTimeout(() => r("pending"), 2000)),
    ]);
    expect(settled).toBeInstanceOf(UploadAbortedError);
    expect(existsSync(path)).toBe(false);
  });
});
