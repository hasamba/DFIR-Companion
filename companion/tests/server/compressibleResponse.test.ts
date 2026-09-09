import { describe, it, expect } from "vitest";
import type { Request, Response } from "express";
import { sendMaybeGzipped } from "../../src/http/compressibleResponse.js";

// A fake response that records what a real one would have done. Express's own `vary()` appends to
// an existing header; `set()` replaces it — the distinction this exercises.
interface FakeRes {
  body: unknown;
  headers: Record<string, string>;
  type(): FakeRes;
  set(name: string, value: string): FakeRes;
  get(name: string): string | undefined;
  vary(field: string): FakeRes;
  send(payload: unknown): FakeRes;
}

function fakeRes(): FakeRes {
  const headers: Record<string, string> = {};
  const res: FakeRes = {
    body: undefined,
    headers,
    type: () => res,
    set(name, value) {
      headers[name] = value;
      return res;
    },
    get: (name) => headers[name],
    vary(field) {
      headers.Vary = headers.Vary ? `${headers.Vary}, ${field}` : field;
      return res;
    },
    send(payload) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

const req = (accept: string) => ({ headers: { "accept-encoding": accept } }) as unknown as Request;
const big = "x".repeat(4096);

describe("sendMaybeGzipped", () => {
  it("gzips when the client accepts it", async () => {
    const res = fakeRes();
    await sendMaybeGzipped(req("gzip"), res as unknown as Response, "html", big);
    expect(res.headers["Content-Encoding"]).toBe("gzip");
  });

  it("honours an explicit gzip;q=0, which forbids gzip", async () => {
    const res = fakeRes();
    await sendMaybeGzipped(req("gzip;q=0"), res as unknown as Response, "html", big);
    // A substring test for "gzip" reads this as permission. It is the opposite.
    expect(res.headers["Content-Encoding"]).toBeUndefined();
    expect(res.body).toBeInstanceOf(Buffer);
  });

  it("honours q=0 inside a longer preference list", async () => {
    const res = fakeRes();
    await sendMaybeGzipped(req("br, gzip;q=0, *;q=0"), res as unknown as Response, "html", big);
    expect(res.headers["Content-Encoding"]).toBeUndefined();
  });

  it("appends to an existing Vary rather than replacing it", async () => {
    const res = fakeRes();
    // originGuard sets Vary: Origin on an allowed cross-origin request, because
    // Access-Control-Allow-Origin echoes the caller. Overwriting it lets a shared cache serve one
    // origin's response to another, with a CORS header that makes it unreadable.
    res.vary("Origin");
    await sendMaybeGzipped(req("gzip"), res as unknown as Response, "html", big);
    expect(res.headers.Vary).toMatch(/Origin/);
    expect(res.headers.Vary).toMatch(/Accept-Encoding/);
  });

  it("leaves a small body uncompressed", async () => {
    const res = fakeRes();
    await sendMaybeGzipped(req("gzip"), res as unknown as Response, "html", "tiny");
    expect(res.headers["Content-Encoding"]).toBeUndefined();
  });
});
