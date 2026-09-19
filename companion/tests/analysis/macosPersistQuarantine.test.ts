import { describe, it, expect } from "vitest";
import { parseMacPersist } from "../../src/analysis/macosPersistImport.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";

// #1037 link 2, import half: a launchd job whose program carries a decodable quarantine mark is a
// structured attribute observation — the persistence target — so the merge-time join can read the
// event identifier as data, never from the finding's prose.

const UUID = "550e8400-e29b-41d4-a716-446655440000";
const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.vendor.helper</string>
<key>ProgramArguments</key><array><string>/Users/Shared/.a/agent</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`;

const collection = (quarantine?: string) =>
  `==> /Library/LaunchAgents/com.vendor.helper.plist <==
# mtime: 2026-01-02T09:00:00Z
# codesign: unsigned
${quarantine ? `# quarantine: ${quarantine}\n` : ""}${plist}
`;

describe("the persistence target as a quarantine attribute observation (#1037 link 2)", () => {
  it("carries the program path, the decoded mark and the event identifier in the envelope", () => {
    const { events } = parseMacPersist("mac.txt", collection(`0083;5f3a1b2c;Safari;${UUID}`));
    expect(events).toHaveLength(1);
    const env = events[0].canonical;
    expect(env).toBeDefined();
    expect(canonicalEventEnvelopeSchema.safeParse(env).success).toBe(true);
    expect(env?.event.type).toBe("persistence-quarantine-target");
    const block = env?.quarantineAttribute;
    expect(block?.role).toBe("persistence-target");
    expect(block?.path).toBe("/Users/Shared/.a/agent");
    expect(block?.persistence?.artifact).toBe("/Library/LaunchAgents/com.vendor.helper.plist");
    expect(block?.persistence?.label).toBe("com.vendor.helper");
    expect(block?.mark).toMatchObject({
      eventId: UUID,
      agent: "Safari",
      encoding: "unix-hex-seconds",
      time: "2020-08-17T05:52:44.000Z",
    });
    // A persistence collection names no host, and its upload holds no database record.
    expect(block?.host).toEqual({ state: "not named" });
    expect(block?.join.state).toBe("no database record in this upload");
    // The row's own words are unchanged: the join wording is the merge pass's, not the importer's.
    expect(events[0].description).toContain("[quarantine mark: download, sandbox (+0x0080); agent Safari;");
    expect(events[0].description).not.toContain("download event:");
  });

  it("a job with no mark, a legacy URL, or an undecodable value carries no envelope", () => {
    for (const q of [
      undefined,
      "https://evil.test/update.zip",
      "garbage",
      "0083;5f3a1b2c;Safari;not-a-uuid",
    ]) {
      const { events } = parseMacPersist("mac.txt", collection(q));
      expect(events).toHaveLength(1);
      expect(events[0].canonical).toBeUndefined();
    }
  });
});
