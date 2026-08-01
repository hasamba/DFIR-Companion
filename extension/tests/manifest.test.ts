import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(__dirname, "../manifest.json"), "utf-8"));

describe("manifest.json commands", () => {
  it("defines toggle-capture with Ctrl+Shift+S", () => {
    expect(manifest.commands["toggle-capture"]).toBeDefined();
    expect(manifest.commands["toggle-capture"].suggested_key.default).toBe("Ctrl+Shift+S");
  });

  it("defines _execute_action so Chrome can open the popup via keyboard shortcut", () => {
    expect(manifest.commands["_execute_action"]).toBeDefined();
    expect(manifest.commands["_execute_action"].description).toBeTruthy();
  });
});

describe("manifest.json permissions", () => {
  it("requests contextMenus for the right-click send feature", () => {
    expect(manifest.permissions).toContain("contextMenus");
  });

  it("installs without persistent access to websites", () => {
    expect(manifest.host_permissions ?? []).toEqual([]);
    expect(manifest.content_scripts ?? []).toEqual([]);
    expect(manifest.permissions).not.toContain("tabs");
  });

  it("declares web origins as runtime-only permissions", () => {
    expect(manifest.optional_host_permissions).toEqual(["http://*/*", "https://*/*"]);
  });

  it("does not request private browsing access at install", () => {
    expect(manifest.incognito).toBeUndefined();
  });
});
