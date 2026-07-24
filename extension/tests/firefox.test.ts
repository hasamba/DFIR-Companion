import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const firefoxManifest = JSON.parse(readFileSync(resolve(__dirname, "../manifest-firefox.json"), "utf-8"));

describe("manifest-firefox.json", () => {
  it("has browser_specific_settings with a gecko id", () => {
    expect(firefoxManifest.browser_specific_settings).toBeDefined();
    expect(firefoxManifest.browser_specific_settings.gecko.id).toMatch(/.+@.+/);
    expect(firefoxManifest.browser_specific_settings.gecko.strict_min_version).toMatch(/^\d/);
  });

  it("uses background.scripts instead of service_worker", () => {
    expect(firefoxManifest.background.service_worker).toBeUndefined();
    expect(firefoxManifest.background.scripts).toContain("serviceWorker.js");
  });

  it("includes host access under permissions (Firefox MV3 style)", () => {
    expect(firefoxManifest.permissions).toContain("<all_urls>");
  });

  it("keeps the same capture shortcut", () => {
    expect(firefoxManifest.commands["toggle-capture"].suggested_key.default).toBe("Ctrl+Shift+S");
  });
});

describe("browser shim", () => {
  it("executeScriptTarget passes world:MAIN for chrome and omits it for firefox", async () => {
    const calls: unknown[] = [];
    const fakeChrome = { scripting: { executeScript: (args: unknown) => { calls.push(args); return Promise.resolve([]); } } } as unknown as typeof chrome;
    (globalThis as unknown as Record<string, unknown>).chrome = fakeChrome;
    delete (globalThis as unknown as Record<string, unknown>).browser;

    const { executeScriptTarget } = await import("../src/browser.js");
    await executeScriptTarget(42, ["pageHook.js"]);
    expect((calls[0] as { world?: string }).world).toBe("MAIN");

    const fakeBrowser = { scripting: { executeScript: (args: unknown) => { calls.push(args); return Promise.resolve([]); } } } as unknown as typeof chrome;
    delete (globalThis as unknown as Record<string, unknown>).chrome;
    (globalThis as unknown as Record<string, unknown>).browser = fakeBrowser;

    await executeScriptTarget(43, ["pageHook.js"]);
    expect((calls[1] as { world?: string }).world).toBeUndefined();
  });
});
