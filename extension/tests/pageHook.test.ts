import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it, vi } from "vitest";

const testDir = dirname(fileURLToPath(import.meta.url));

function compiledPageHook(): string {
  const source = readFileSync(resolve(testDir, "../src/pageHook.ts"), "utf8");
  return ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.None,
    },
  }).outputText;
}

// #430: the hook's forward() cap and the content script's accept cap are the same bound, written
// twice — pageHook.ts is bundled standalone and cannot import bridge.ts, the same reason the
// message-name strings are duplicated. A drift test is what keeps "keep the two in sync" true.
describe("capture body cap", () => {
  it("pageHook's MAX_BODY matches MAX_CAPTURE_BODY in adapters/bridge.ts", async () => {
    const source = readFileSync(resolve(testDir, "../src/pageHook.ts"), "utf8");
    const declared = /const MAX_BODY = ([0-9_]+);/.exec(source);
    expect(declared).not.toBeNull();
    const { MAX_CAPTURE_BODY } = await import("../src/adapters/bridge.js");
    expect(Number(declared![1].replace(/_/g, ""))).toBe(MAX_CAPTURE_BODY);
  });

  it("rejects a body over the cap at the content script's boundary", async () => {
    const { isAcceptableCaptureBody, MAX_CAPTURE_BODY } = await import("../src/adapters/bridge.js");
    expect(isAcceptableCaptureBody("a".repeat(MAX_CAPTURE_BODY))).toBe(true);
    expect(isAcceptableCaptureBody("a".repeat(MAX_CAPTURE_BODY + 1))).toBe(false);
    // Still the type guard the call site relied on before the length check joined it.
    expect(isAcceptableCaptureBody(undefined)).toBe(false);
    expect(isAcceptableCaptureBody({ length: 1 })).toBe(false);
  });
});

describe("pageHook", () => {
  it("can be injected repeatedly into the same page", () => {
    const addEventListener = vi.fn();
    const pageWindow = {
      addEventListener,
      postMessage: vi.fn(),
      fetch: undefined,
      XMLHttpRequest: undefined,
    };
    const context = createContext({ window: pageWindow });
    const hook = compiledPageHook();

    runInContext(hook, context);
    expect(() => runInContext(hook, context)).not.toThrow();
    expect(addEventListener).toHaveBeenCalledTimes(1);
  });
});
