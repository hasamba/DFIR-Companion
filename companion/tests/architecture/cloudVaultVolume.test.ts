import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

// The cloud account vault (#2307) is two mounts on purpose: the sealed accounts beside the other
// stores, and the KEY on its own mount outside /data. A data-folder backup must never hold both.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

const volumes = (): string[] => {
  const doc = parse(read("docker-compose.yml")) as { services: { companion: { volumes?: string[] } } };
  return (doc.services.companion.volumes ?? []).map((v) => v.split("#")[0].trim());
};

describe("cloud vault in the container", () => {
  it("docker-compose mounts the accounts store and the key on separate mounts", () => {
    expect(volumes()).toContain("./cloud-accounts:/data/cloud-accounts");
    expect(volumes()).toContain("./cloud-vault-key:/run/dfir-vault");
  });

  it("the image points the key at its own mount, outside /data", () => {
    const dockerfile = read("Dockerfile");
    expect(dockerfile).toMatch(/ENV DFIR_CLOUD_VAULT_KEY_FILE=\/run\/dfir-vault\/cloud-vault\.key/);
    expect(dockerfile).toMatch(/mkdir -p [^\n]*\/data\/cloud-accounts/);
    expect(dockerfile).toMatch(/mkdir -p [^\n]*\/run\/dfir-vault/);
  });

  it("the entrypoint hands both to the run user, the key mount by its literal path only", () => {
    const script = read("docker-entrypoint.sh");
    const known = /KNOWN_STORES="([^"]*)"/.exec(script)?.[1] ?? "";
    expect(known.split(/\s+/)).toContain("cloud-accounts");
    expect(script).toMatch(/vault_dir=\/run\/dfir-vault\n/);
    // The server refuses a key readable by others, so the handoff leaves it 0600 after the chown.
    expect(script).toMatch(
      /chown -h [^\n]*cloud-vault\.key[^\n]*\n\s*chmod 600 "\$vault_dir\/cloud-vault\.key"/,
    );
    // Never read from the dashboard-writable dotenv file: only an image-set path is handed over.
    expect(script).not.toMatch(/load_env_file_var[^\n]*DFIR_CLOUD_VAULT_KEY_FILE/);
  });

  it("git and the Docker build context ignore the host-side key and accounts folders", () => {
    for (const file of [".gitignore", ".dockerignore"]) {
      const lines = read(file).split(/\r?\n/);
      expect(
        lines.some((l) => /^\/?cloud-vault-key\/$/.test(l)),
        `${file} key`,
      ).toBe(true);
      expect(
        lines.some((l) => /^\/?cloud-accounts\/$/.test(l)),
        `${file} accounts`,
      ).toBe(true);
    }
  });

  it(".env.example documents the key-file override", () => {
    expect(read("companion/.env.example")).toMatch(/^#?\s*DFIR_CLOUD_VAULT_KEY_FILE=/m);
  });
});
