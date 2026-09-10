import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  parseLinuxPersist,
  readCollection,
  incidentWindowFromTimeline,
} from "../../src/analysis/linuxPersistImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

const COLLECTION = [
  "==> /root/.ssh/authorized_keys <==",
  "# mtime: 2026-01-02T09:00:00Z",
  'command="/bin/bash" ssh-rsa AAAAB3NzaC1 attacker@vps',
  "",
  "==> /etc/cron.d/update <==",
  "*/5 * * * * root /tmp/.cache/update.sh",
  "",
  "==> /etc/systemd/system/telemetry.service <==",
  "[Unit]",
  "Description=Telemetry",
  "[Service]",
  "ExecStart=/dev/shm/.t/agent --quiet",
  "Restart=always",
  "[Install]",
  "WantedBy=multi-user.target",
  "",
  "==> /var/log/syslog <==",
  "Jan  2 09:00:00 host something happened",
].join("\n");

describe("readCollection", () => {
  it("reads a headered collection", () => {
    expect(readCollection("triage.txt", COLLECTION).map((f) => f.kind)).toEqual([
      "authorized_keys",
      "cron",
      "systemd",
      "unknown",
    ]);
  });

  it("reads one named artifact when the upload has no headers", () => {
    const files = readCollection("authorized_keys.txt", "ssh-rsa AAAA a@b");
    expect(files).toHaveLength(1);
    expect(files[0].kind).toBe("authorized_keys");
  });

  it("reads nothing from a file it cannot place", () => {
    expect(readCollection("notes.txt", "just some text")).toEqual([]);
  });
});

describe("incidentWindowFromTimeline", () => {
  it("spans the case's High and Critical events", () => {
    const w = incidentWindowFromTimeline([
      { timestamp: "2026-01-01T00:00:00Z", severity: "High" },
      { timestamp: "2026-01-05T00:00:00Z", severity: "Critical" },
      { timestamp: "2020-01-01T00:00:00Z", severity: "Info" },
    ]);
    expect(w).toEqual({ start: "2026-01-01T00:00:00.000Z", end: "2026-01-05T00:00:00.000Z" });
  });

  // A guessed window would silently raise findings. No window is the correct answer.
  it("returns nothing when the case has not established one", () => {
    expect(
      incidentWindowFromTimeline([{ timestamp: "2026-01-01T00:00:00Z", severity: "High" }]),
    ).toBeUndefined();
    expect(incidentWindowFromTimeline([])).toBeUndefined();
  });

  it("ignores an event whose time cannot be read", () => {
    expect(
      incidentWindowFromTimeline([
        { timestamp: "not a date", severity: "High" },
        { timestamp: "2026-01-01T00:00:00Z", severity: "High" },
      ]),
    ).toBeUndefined();
  });
});

describe("parseLinuxPersist", () => {
  const parsed = () => parseLinuxPersist("triage.txt", COLLECTION, {}, "2026-06-01T00:00:00Z");

  it("makes one event per finding, not one per collected line", () => {
    const p = parsed();
    expect(p.events).toHaveLength(p.signals.length);
    expect(p.events.length).toBeGreaterThan(0);
    expect(p.events.length).toBeLessThan(COLLECTION.split("\n").length);
  });

  it("keeps the collected line on the event so the analyst reads the original text", () => {
    const e = parsed().events.find((x) => x.path === "/etc/cron.d/update");
    expect(e?.description).toContain("/tmp/.cache/update.sh");
    expect(e?.severity).toBe("High");
  });

  it("uses a collected modification time as the event time", () => {
    const e = parsed().events.find((x) => x.path === "/root/.ssh/authorized_keys");
    expect(e?.timestamp).toBe("2026-01-02T09:00:00.000Z");
    expect(e?.description).not.toContain("no collected timestamp");
  });

  // An invented timestamp puts a persistence mechanism at a moment it may have nothing to do with.
  it("says so when the event time is the import time, not a collected one", () => {
    const e = parsed().events.find((x) => x.path === "/etc/systemd/system/telemetry.service");
    expect(e?.timestamp).toBe("2026-06-01T00:00:00Z");
    expect(e?.description).toContain("no collected timestamp");
  });

  it("makes the payload an IOC, not the artifact every host has", () => {
    const values = parsed().iocs.map((i) => i.value);
    expect(values).toContain("/tmp/.cache/update.sh");
    expect(values).toContain("/dev/shm/.t/agent");
    expect(values).not.toContain("/etc/cron.d/update");
  });

  it("keys each event so a re-import produces one row, not two", () => {
    const keys = parsed().events.map((e) => e.aggKey);
    expect(new Set(keys).size).toBe(keys.length);
    expect(parsed().events.map((e) => e.aggKey)).toEqual(keys);
  });

  it("tells the analyst what it skipped and what it could not date", () => {
    const p = parsed();
    expect(p.note).toContain("3 artifact file(s) read");
    expect(p.note).toContain("1 member(s) skipped");
    expect(p.note).toContain("carried no modification time");
  });

  it("returns nothing for a collection with no artifact this reads", () => {
    const p = parseLinuxPersist("x.txt", "==> /var/log/syslog <==\nnothing");
    expect(p.signals).toEqual([]);
    expect(p.events).toEqual([]);
  });
});

describe("detection and dispatch", () => {
  it("routes a headered collection to the Linux persistence importer", () => {
    expect(detectImportKind("triage.txt", COLLECTION)).toBe("linuxpersist");
  });

  it("routes a single named artifact", () => {
    expect(detectImportKind("authorized_keys", "ssh-rsa AAAA a@b")).toBe("linuxpersist");
    expect(detectImportKind("evil.service", "[Service]\nExecStart=/tmp/x")).toBe("linuxpersist");
    expect(detectImportKind(".bashrc", "alias ll='ls -al'")).toBe("linuxpersist");
  });

  // A .env file is an application's secrets. Routing one here would be a mis-route with a privacy cost.
  it("does not claim a .env file", () => {
    expect(detectImportKind(".env", "PATH=/usr/bin\nAPI_KEY=secret")).not.toBe("linuxpersist");
  });

  it("does not claim an ordinary log", () => {
    expect(detectImportKind("syslog", "Jan  2 09:00:00 host sshd[1]: Accepted password for root")).not.toBe(
      "linuxpersist",
    );
  });

  it("does not claim auditd, which is still routed to its own importer", () => {
    expect(detectImportKind("audit.log", "type=SYSCALL msg=audit(1490451217.272:270): arch=c000003e")).toBe(
      "auditd",
    );
  });

  it("reaches a dispatch case and a pipeline method", () => {
    const dispatch = readFileSync(join(process.cwd(), "src/composition/importIngest.ts"), "utf8");
    expect(dispatch).toContain('case "linuxpersist":');
    const pipeline = readFileSync(join(process.cwd(), "src/analysis/pipeline.ts"), "utf8");
    expect(pipeline).toContain("importLinuxPersist");
  });
});
