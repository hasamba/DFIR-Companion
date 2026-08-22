import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(__dirname, "../manifest.json"), "utf-8"));

describe("manifest.json store listing", () => {
  // Chrome Web Store caps the manifest description at 132 characters and rejects the package on
  // 133 — at upload, after the build passed, which is the slowest place to learn it. This branch
  // hit exactly that: rewording the description to stop calling the companion "local" pushed it to
  // 133 and nothing in the repo would have said so.
  const CHROME_DESCRIPTION_LIMIT = 132;

  it("keeps the description within the Chrome Web Store limit", () => {
    expect(manifest.description.length).toBeLessThanOrEqual(CHROME_DESCRIPTION_LIMIT);
  });

  it("does not promise the companion is local, because the address is a setting", () => {
    // PRIVACY.md stopped claiming evidence never leaves the machine: the companion URL is a plain
    // setting and team mode exists for a companion on another host. The store listing sits beside
    // that policy on the add-on's page, so it must not re-make the claim the policy retracted.
    expect(manifest.description).not.toMatch(/your local (DFIR )?Companion/i);
    expect(manifest.description).toMatch(/you configure/i);
  });
});

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
