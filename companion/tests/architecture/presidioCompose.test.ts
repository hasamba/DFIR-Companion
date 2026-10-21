import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

// #2197: the optional Presidio analyzer in docker-compose.yml.
//
// Presidio reads case text — masked, but still the timeline — so the service must stay opt-in,
// pinned, loopback-only and hardened. A plain `docker compose up -d` must not pull a ~1 GB image
// for a layer most users never turn on.
const root = new URL("../../../", import.meta.url);

interface ComposeService {
  image?: string;
  profiles?: string[];
  ports?: string[];
  environment?: Record<string, string>;
  security_opt?: string[];
  cap_drop?: string[];
  cap_add?: string[];
  healthcheck?: { test?: string[] };
  depends_on?: unknown;
}

const services = (
  parse(readFileSync(new URL("docker-compose.yml", root), "utf8")) as {
    services: Record<string, ComposeService>;
  }
).services;
const presidio = services["presidio-analyzer"];

describe("Presidio compose service (#2197)", () => {
  it("exists under the name the Settings warning accepts", () => {
    expect(presidio).toBeDefined();
  });

  it("is opt-in behind the presidio profile", () => {
    expect(presidio.profiles).toEqual(["presidio"]);
  });

  it("pins the image to a version", () => {
    expect(presidio.image).toMatch(/^mcr\.microsoft\.com\/presidio-analyzer:\d+\.\d+\.\d+$/);
  });

  it("publishes to host loopback only", () => {
    const ports = presidio.ports ?? [];
    expect(ports.length).toBeGreaterThan(0);
    for (const p of ports) expect(p.startsWith("127.0.0.1:"), p).toBe(true);
  });

  it("raises gunicorn's worker timeout above the Companion's 60 s request budget", () => {
    const args = presidio.environment?.GUNICORN_CMD_ARGS ?? "";
    const timeout = Number(/--timeout[= ](\d+)/.exec(args)?.[1]);
    expect(timeout).toBeGreaterThan(60);
  });

  it("is hardened: no privilege regain and no capabilities", () => {
    expect(presidio.security_opt).toContain("no-new-privileges:true");
    expect(presidio.cap_drop).toContain("ALL");
    expect(presidio.cap_add ?? []).toEqual([]);
  });

  it("has a healthcheck on /health", () => {
    expect((presidio.healthcheck?.test ?? []).join(" ")).toContain("/health");
  });

  it("is not a dependency of the companion, so a plain `up` stays valid without the profile", () => {
    expect(services.companion.depends_on).toBeUndefined();
  });
});
