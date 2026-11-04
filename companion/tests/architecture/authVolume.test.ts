import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

// Team mode keeps its accounts, sessions, roles and audit under DFIR_AUTH_DATA_DIR. Unset, that is
// a hashed .dfir-auth-* folder beside the cases root — /data in the image, which compose does NOT
// mount. Every `docker compose up -d` that recreated the container then deleted every account, and
// the next start refused to run without a bootstrap token. Compose must pin the store to a mount.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

interface Compose {
  services: { companion: { volumes?: string[]; environment?: Record<string, string> } };
}

const companion = (): Compose["services"]["companion"] =>
  (parse(read("docker-compose.yml")) as Compose).services.companion;

describe("team-mode account store persists in the container", () => {
  it("docker-compose pins DFIR_AUTH_DATA_DIR to /data/auth", () => {
    expect(companion().environment?.DFIR_AUTH_DATA_DIR).toBe("/data/auth");
  });

  it("docker-compose mounts ./auth at /data/auth", () => {
    const volumes = (companion().volumes ?? []).map((v) => v.split("#")[0].trim());
    expect(volumes).toContain("./auth:/data/auth");
  });

  it("the entrypoint hands DFIR_AUTH_DATA_DIR to the run user", () => {
    expect(read("docker-entrypoint.sh")).toMatch(/\$\{DFIR_AUTH_DATA_DIR:-\}/);
  });

  it("git ignores the host-side ./auth folder (password hashes, session digests)", () => {
    expect(read(".gitignore").split(/\r?\n/)).toContain("/auth/");
  });
});
