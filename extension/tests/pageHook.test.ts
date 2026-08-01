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
