import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// SECURITY.md MUST RECORD THAT BACKUPS ARE NOT CONTENT-AUTHENTICATED, AND WHY (#2154).
//
// BackupManager.restoreBackup validates filenames, allowlists the state files and runs
// integrity_check on the DB sidecar, but it does not authenticate the manifest or sidecar content.
// That is a deliberate trust boundary: anyone who can write state/backups/ can also write the live
// state/ and read <casesRoot>/.instance-secret, so an instance-secret signature would be forgeable
// by exactly that writer, and it would strand older and imported backups. Automated reviews keep
// filing it as a gap; the bullet below is the answer.
const root = new URL("../../../", import.meta.url);
const security = readFileSync(new URL("SECURITY.md", root), "utf8");

/** The "Trust boundaries that are deliberate" section only. */
function trustBoundarySection(md: string): string {
  const start = md.indexOf("## Trust boundaries that are deliberate");
  if (start === -1) return "";
  const next = md.indexOf("\n## ", start + 1);
  return md.slice(start, next === -1 ? undefined : next).replace(/\s+/g, " ");
}

describe("SECURITY.md records the backup trust boundary (#2154)", () => {
  const section = trustBoundarySection(security);

  it("has the deliberate trust-boundaries section", () => {
    expect(section.length).toBeGreaterThan(0);
  });

  it("names the cases folder on disk, including state/backups/, as trusted", () => {
    expect(section).toMatch(/cases folder/i);
    expect(section).toContain("state/backups/");
  });

  it("says backups are not content-authenticated", () => {
    expect(section).toMatch(/not content-authenticated/i);
  });

  it("gives the reasons: forgeable by the same writer, and strands older and imported backups", () => {
    expect(section).toMatch(/instance secret/i);
    expect(section).toMatch(/forge/i);
    expect(section).toMatch(/imported/i);
  });
});
