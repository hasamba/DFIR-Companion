import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

// THE CONTAINER MUST NOT BE ABLE TO REGAIN ROOT AFTER THE ENTRYPOINT DROPS IT (#2155).
//
// The entrypoint starts as root, hands the mounts to the run user, then drops privileges with
// setpriv. Without PR_SET_NO_NEW_PRIVS, a compromised server (a parser RCE on hostile evidence)
// could still exec a SUID-root binary from the base image and climb back to root — with ./cases
// bind-mounted. Three layers close that, and this gate keeps each one in place:
//   1. every setpriv in the entrypoint passes --no-new-privs (holds on plain `docker run` and
//      Railway, where compose flags never apply);
//   2. the runtime image strips the SUID/SGID bits from its binaries;
//   3. compose adds no-new-privileges and drops every capability except the five the root
//      entrypoint needs to chown the mounts and switch user. `cap_drop: [ALL]` alone was
//      verified to stop the container from starting (setpriv: setresuid failed).
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

const ALLOWED_CAPS = new Set(["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]);

interface ComposeService {
  security_opt?: string[];
  cap_drop?: string[];
  cap_add?: string[];
}

const companionService = (): ComposeService => {
  const doc = parse(read("docker-compose.yml")) as { services: { companion: ComposeService } };
  return doc.services.companion;
};

const codeLines = (text: string): string[] =>
  text.split(/\r?\n/).filter((line) => !line.trimStart().startsWith("#"));

describe("container hardening (#2155)", () => {
  it("compose sets no-new-privileges", () => {
    expect(companionService().security_opt ?? []).toContain("no-new-privileges:true");
  });

  it("compose drops ALL capabilities and adds back only what the entrypoint needs", () => {
    const svc = companionService();
    expect(svc.cap_drop ?? []).toContain("ALL");
    const added = svc.cap_add ?? [];
    expect(added).toContain("SETUID");
    expect(added).toContain("SETGID");
    for (const cap of added) expect(ALLOWED_CAPS.has(cap), `unexpected cap_add ${cap}`).toBe(true);
  });

  it("every setpriv in the entrypoint sets --no-new-privs", () => {
    const setprivLines = codeLines(read("docker-entrypoint.sh")).filter((l) => /\bsetpriv\b/.test(l));
    expect(setprivLines.length).toBeGreaterThanOrEqual(3);
    for (const line of setprivLines) expect(line, line.trim()).toContain("--no-new-privs");
  });

  it("the entrypoint never execs node without the no-new-privs wrapper", () => {
    const bare = codeLines(read("docker-entrypoint.sh")).filter((l) => /^\s*exec\s+node\b/.test(l));
    expect(bare).toEqual([]);
  });

  it("the runtime image strips SUID/SGID bits", () => {
    const dockerfile = read("Dockerfile");
    const runtime = dockerfile.slice(dockerfile.indexOf("AS runtime"));
    const stripped = codeLines(runtime).join("\n");
    expect(stripped).toMatch(/find\s+\/\s+-xdev\s+-perm\s+\/6000[^\n]*chmod\s+a-s/);
  });
});
