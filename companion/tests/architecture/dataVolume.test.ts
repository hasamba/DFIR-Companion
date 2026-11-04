import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

// Everything the server keeps beside the cases root — the dashboard-written companion.env, and the
// global stores (dashboard views, report templates, tagger rules, notifications, logs, Sigma rules,
// audit export, ...) — sits directly under /data in the image. Compose mounted only ./cases,
// ./server-sets and ./auth, so every container recreate deleted the rest. One ./data mount keeps
// all of it, including stores added later.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

interface Compose {
  services: { companion: { volumes?: string[]; environment?: Record<string, string> } };
}

const volumes = (): string[] =>
  ((parse(read("docker-compose.yml")) as Compose).services.companion.volumes ?? []).map((v) =>
    v.split("#")[0].trim(),
  );

describe("container /data state persists", () => {
  it("docker-compose mounts ./data at /data", () => {
    expect(volumes()).toContain("./data:/data");
  });

  it("keeps the existing nested mounts, so current ./cases, ./server-sets and ./auth folders still load", () => {
    expect(volumes()).toEqual(
      expect.arrayContaining(["./cases:/data/cases", "./server-sets:/data/server-sets", "./auth:/data/auth"]),
    );
  });

  it("the entrypoint hands the /data entry itself to the run user, whatever DFIR_ENV_FILE says", () => {
    // Before: /data became writable only because the default env file sits in it. With
    // DFIR_ENV_FILE elsewhere and a root-owned ./data mount, stores outside KNOWN_STORES
    // (audit-export, Sigma rules) could not be created.
    const script = read("docker-entrypoint.sh");
    expect(script).toMatch(/\n\s*\/data\)\s*\n\s*handoff_entry "\$data_root"/);
  });

  it("git ignores the host-side ./data folder (settings file with API keys)", () => {
    expect(read(".gitignore").split(/\r?\n/)).toContain("/data/");
  });
});
