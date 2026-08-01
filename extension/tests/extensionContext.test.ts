import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { runBestEffortExtensionCall } from "../src/extensionContext.js";

const testDir = dirname(fileURLToPath(import.meta.url));

describe("runBestEffortExtensionCall", () => {
  it("contains synchronous context-invalidation errors", () => {
    const onInvalidated = vi.fn();

    expect(() => runBestEffortExtensionCall(
      () => { throw new Error("Extension context invalidated."); },
      onInvalidated,
    )).not.toThrow();
    expect(onInvalidated).toHaveBeenCalledTimes(1);
  });

  it("contains asynchronous context-invalidation errors", async () => {
    const onInvalidated = vi.fn();

    runBestEffortExtensionCall(
      () => Promise.reject(new Error("Extension context invalidated.")),
      onInvalidated,
    );
    await vi.waitFor(() => expect(onInvalidated).toHaveBeenCalledTimes(1));
  });

  it("ignores unrelated best-effort delivery failures", async () => {
    const onInvalidated = vi.fn();

    runBestEffortExtensionCall(
      () => Promise.reject(new Error("Receiving end does not exist.")),
      onInvalidated,
    );
    await Promise.resolve();
    expect(onInvalidated).not.toHaveBeenCalled();
  });

  it("leaves no uncontained fire-and-forget extension calls in the content bundle", () => {
    const sources = ["content.ts", "artifactCapture.ts", "contextMenuCapture.ts"]
      .map((name) => readFileSync(resolve(testDir, `../src/${name}`), "utf8"))
      .join("\n");

    expect(sources).not.toMatch(
      /void browserApi\.(?:runtime\.sendMessage|storage\.local\.(?:get|set|remove))\(/,
    );
  });
});
