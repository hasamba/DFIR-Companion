import { describe, it, expect, vi } from "vitest";
import {
  readBoundedBuffer,
  readBoundedText,
  readBoundedJson,
  readBoundedArrayBuffer,
  ResponseTooLargeError,
  RESPONSE_SIZE_LIMITS,
  rethrowIfTooLarge,
} from "../../src/providers/boundedResponse.js";

// A Response whose body streams `chunks` one at a time, regardless of what Content-Length (if any)
// claims — this is what lets the tests exercise "declared size lies" independently of "actual size
// exceeds the cap".
function streamedResponse(chunks: string[], headers: Record<string, string> = {}): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk));
      controller.close();
    },
  });
  return new Response(stream, { headers });
}

// Same shape, but also exposes a spy on the underlying stream's `cancel` — for asserting a
// rejected body is actually torn down, not just refused.
function streamedResponseWithCancelSpy(
  chunks: string[],
  headers: Record<string, string> = {},
): { res: Response; cancel: ReturnType<typeof vi.fn> } {
  const cancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk));
      controller.close();
    },
    cancel,
  });
  return { res: new Response(stream, { headers }), cancel };
}

describe("readBoundedBuffer", () => {
  it("reads a normal body under the cap", async () => {
    const res = streamedResponse(["hello ", "world"]);
    const buf = await readBoundedBuffer(res, { maxBytes: 1024 });
    expect(buf.toString("utf8")).toBe("hello world");
  });

  it("rejects up front on an honest but oversized Content-Length, without reading the body", async () => {
    const res = streamedResponse(["x".repeat(100)], { "content-length": "100" });
    await expect(readBoundedBuffer(res, { maxBytes: 10 })).rejects.toThrow(ResponseTooLargeError);
  });

  it("rejects a body that exceeds the cap with NO Content-Length header (chunked transfer)", async () => {
    const res = streamedResponse(["a".repeat(50), "b".repeat(50)]); // no content-length at all
    await expect(readBoundedBuffer(res, { maxBytes: 60 })).rejects.toThrow(ResponseTooLargeError);
  });

  it("rejects a body whose actual bytes exceed a FALSE (too-low) Content-Length", async () => {
    // Content-Length under-declares — the streamed check must still catch the real size.
    const res = streamedResponse(["x".repeat(200)], { "content-length": "5" });
    await expect(readBoundedBuffer(res, { maxBytes: 5 })).rejects.toThrow(ResponseTooLargeError);
  });

  it("accepts a body exactly at the cap", async () => {
    const res = streamedResponse(["x".repeat(10)]);
    const buf = await readBoundedBuffer(res, { maxBytes: 10 });
    expect(buf.byteLength).toBe(10);
  });

  it("stops reading as soon as the running total crosses the cap, not just at the final chunk", async () => {
    const res = streamedResponse(["a".repeat(5), "b".repeat(5), "c".repeat(5)]);
    await expect(readBoundedBuffer(res, { maxBytes: 8 })).rejects.toThrow(ResponseTooLargeError);
  });

  it("names the limit and context in the error, never response content", async () => {
    const res = streamedResponse(["SECRET-PAYLOAD-DATA".repeat(10)]);
    try {
      await readBoundedBuffer(res, { maxBytes: 5, context: "TestProvider" });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(ResponseTooLargeError);
      const e = err as ResponseTooLargeError;
      expect(e.limitBytes).toBe(5);
      expect(e.context).toBe("TestProvider");
      expect(e.message).not.toContain("SECRET-PAYLOAD-DATA");
      expect(e.message).toContain("TestProvider");
    }
  });

  it("returns an empty buffer for a body-less response (e.g. 204)", async () => {
    const res = new Response(null, { status: 204 });
    const buf = await readBoundedBuffer(res, { maxBytes: 10 });
    expect(buf.byteLength).toBe(0);
  });

  it("cancels the body stream when rejecting on a declared Content-Length, instead of leaving it dangling", async () => {
    const { res, cancel } = streamedResponseWithCancelSpy(["x".repeat(100)], { "content-length": "100" });
    await expect(readBoundedBuffer(res, { maxBytes: 10 })).rejects.toThrow(ResponseTooLargeError);
    expect(cancel).toHaveBeenCalled();
  });
});

describe("readBoundedText / readBoundedJson / readBoundedArrayBuffer", () => {
  it("readBoundedText decodes utf8", async () => {
    const res = streamedResponse(["héllo"]);
    expect(await readBoundedText(res, { maxBytes: 1024 })).toBe("héllo");
  });

  it("readBoundedJson parses a normal payload", async () => {
    const res = streamedResponse([JSON.stringify({ a: 1, b: [2, 3] })]);
    expect(await readBoundedJson<{ a: number; b: number[] }>(res, { maxBytes: 1024 })).toEqual({
      a: 1,
      b: [2, 3],
    });
  });

  it("readBoundedJson throws on malformed JSON near the cap without leaking the body", async () => {
    const res = streamedResponse(['{"a": 1, "b": '.padEnd(30, "x")]); // truncated/invalid, ~cap-sized
    await expect(readBoundedJson(res, { maxBytes: 100, context: "TestProvider" })).rejects.toThrow(
      /invalid JSON.*TestProvider/,
    );
  });

  it("readBoundedJson still enforces the size cap before attempting to parse", async () => {
    const res = streamedResponse([JSON.stringify({ a: "x".repeat(100) })]);
    await expect(readBoundedJson(res, { maxBytes: 10 })).rejects.toThrow(ResponseTooLargeError);
  });

  it("readBoundedJson never leaks a snippet of the malformed body via the parser's own error message", async () => {
    // Modern V8 quotes a slice of the offending text in SyntaxError.message (e.g. `Unexpected
    // token 'S', "SECRET-TO"... is not valid JSON`) — the helper must not pass that through.
    const res = streamedResponse(["SECRET-TOKEN-VALUE-not-json"]);
    try {
      await readBoundedJson(res, { maxBytes: 1024, context: "TestProvider" });
      expect.unreachable();
    } catch (err) {
      expect((err as Error).message).not.toContain("SECRET-TOKEN-VALUE");
      expect((err as Error).message).toContain("TestProvider");
    }
  });

  it("readBoundedText strips a leading UTF-8 BOM, matching native Response.text()", async () => {
    const res = streamedResponse(["﻿hello"]);
    expect(await readBoundedText(res, { maxBytes: 1024 })).toBe("hello");
  });

  it("readBoundedJson parses a BOM-prefixed JSON body (some self-hosted servers emit one)", async () => {
    const res = streamedResponse(["﻿" + JSON.stringify({ ok: true })]);
    expect(await readBoundedJson(res, { maxBytes: 1024 })).toEqual({ ok: true });
  });

  it("readBoundedArrayBuffer returns the right byte length", async () => {
    const res = streamedResponse(["abcdef"]);
    const ab = await readBoundedArrayBuffer(res, { maxBytes: 1024 });
    expect(ab.byteLength).toBe(6);
    expect(Buffer.from(ab).toString("utf8")).toBe("abcdef");
  });

  it("readBoundedArrayBuffer rejects over the cap", async () => {
    const res = streamedResponse(["x".repeat(20)]);
    await expect(readBoundedArrayBuffer(res, { maxBytes: 10 })).rejects.toThrow(ResponseTooLargeError);
  });
});

describe("RESPONSE_SIZE_LIMITS", () => {
  it("orders json <= text is NOT assumed; binary is the largest of the three presets", () => {
    expect(RESPONSE_SIZE_LIMITS.binary).toBeGreaterThan(RESPONSE_SIZE_LIMITS.json);
    expect(RESPONSE_SIZE_LIMITS.binary).toBeGreaterThan(RESPONSE_SIZE_LIMITS.text);
  });
});

describe("rethrowIfTooLarge", () => {
  it("rethrows a ResponseTooLargeError instead of swallowing it into the fallback", () => {
    const err = new ResponseTooLargeError(10, "TestProvider");
    expect(() => rethrowIfTooLarge(err, { fallback: true })).toThrow(ResponseTooLargeError);
  });

  it("returns the fallback for any other error (the original .catch(() => fallback) behavior)", () => {
    expect(rethrowIfTooLarge(new SyntaxError("bad json"), { fallback: true })).toEqual({ fallback: true });
    expect(rethrowIfTooLarge("not even an Error", [])).toEqual([]);
  });

  it("end-to-end: a success-path .catch(() => ({})) pattern must not turn an oversized body into an empty result", async () => {
    const res = streamedResponse(["x".repeat(50)]);
    const readAsFallback = () =>
      readBoundedJson<Record<string, unknown>>(res, { maxBytes: 5, context: "TestProvider" }).catch((err) =>
        rethrowIfTooLarge(err, {}),
      );
    await expect(readAsFallback()).rejects.toThrow(ResponseTooLargeError);
  });
});
