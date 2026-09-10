import { describe, it, expect } from "vitest";
import {
  classifyLinuxArtifact,
  splitCollection,
  singleArtifact,
  parseAuthorizedKeys,
  keyOption,
  parseCrontab,
  cronHasUserColumn,
  parseUnit,
  stripExecPrefix,
  shellInitLines,
  parseSuidListing,
  parsePathEntries,
} from "../../src/analysis/linuxPersistence.js";

describe("classifyLinuxArtifact — the path decides, not the content", () => {
  it("names each artifact class", () => {
    expect(classifyLinuxArtifact("/root/.ssh/authorized_keys")).toBe("authorized_keys");
    expect(classifyLinuxArtifact("/etc/systemd/system/evil.service")).toBe("systemd");
    expect(classifyLinuxArtifact("/etc/crontab")).toBe("cron");
    expect(classifyLinuxArtifact("/var/spool/cron/crontabs/alice")).toBe("cron");
    expect(classifyLinuxArtifact("/home/alice/.bashrc")).toBe("shellrc");
    expect(classifyLinuxArtifact("/etc/profile.d/init.sh")).toBe("shellrc");
    expect(classifyLinuxArtifact("suid-listing.txt")).toBe("suid");
    expect(classifyLinuxArtifact("/etc/environment")).toBe("env");
  });

  it("says unknown rather than guessing", () => {
    expect(classifyLinuxArtifact("/var/log/syslog")).toBe("unknown");
  });
});

describe("splitCollection — one upload, many files", () => {
  it("reads the head/tail header form", () => {
    const files = splitCollection(
      [
        "==> /root/.ssh/authorized_keys <==",
        "ssh-rsa AAAA root@host",
        "",
        "==> /etc/crontab <==",
        "* * * * * root /bin/true",
      ].join("\n"),
    );
    expect(files.map((f) => f.path)).toEqual(["/root/.ssh/authorized_keys", "/etc/crontab"]);
    expect(files[0].kind).toBe("authorized_keys");
    expect(files[1].content).toContain("/bin/true");
  });

  it("reads the other three header spellings", () => {
    const files = splitCollection(
      [
        "=== /etc/crontab ===",
        "a",
        "##### /home/u/.bashrc #####",
        "b",
        "# FILE: /etc/systemd/system/x.service",
        "c",
      ].join("\n"),
    );
    expect(files.map((f) => f.path)).toEqual([
      "/etc/crontab",
      "/home/u/.bashrc",
      "/etc/systemd/system/x.service",
    ]);
  });

  it("requires an absolute path, so a decoration line does not split the collection", () => {
    const files = splitCollection(
      ["=== summary ===", "==> not a path <==", "==> /etc/crontab <==", "x"].join("\n"),
    );
    expect(files.map((f) => f.path)).toEqual(["/etc/crontab"]);
  });

  it("drops a banner that precedes the first header", () => {
    const files = splitCollection(["collection started", "==> /etc/crontab <==", "x"].join("\n"));
    expect(files).toHaveLength(1);
    expect(files[0].content).toBe("x");
  });

  it("reads a mtime and owner annotation directly under the header", () => {
    const [f] = splitCollection(
      ["==> /etc/crontab <==", "# mtime: 2026-01-02T03:04:05Z", "# owner: root", "* * * * * root x"].join(
        "\n",
      ),
    );
    expect(f.mtime).toBe("2026-01-02T03:04:05.000Z");
    expect(f.owner).toBe("root");
    expect(f.content).toBe("* * * * * root x");
  });

  it("leaves a comment further down the file as content", () => {
    const [f] = splitCollection(
      ["==> /etc/crontab <==", "* * * * * root x", "# mtime: 2026-01-02T03:04:05Z"].join("\n"),
    );
    expect(f.mtime).toBeUndefined();
    expect(f.content).toContain("# mtime");
  });

  it("carries a platform annotation through without interpreting it", () => {
    const [f] = splitCollection(
      [
        "==> /Library/LaunchDaemons/x.plist <==",
        "# codesign: unsigned",
        "# quarantine: https://evil.test/a",
        "<plist/>",
      ].join("\n"),
    );
    expect(f.extra).toEqual({ codesign: "unsigned", quarantine: "https://evil.test/a" });
  });

  // An open key set swallowed the first line of any file that began with a `# word:` comment.
  it("leaves an ordinary leading comment in the content", () => {
    const [f] = splitCollection(
      ["==> /etc/crontab <==", "# Edited by: alice", "* * * * * root x"].join("\n"),
    );
    expect(f.extra).toBeUndefined();
    expect(f.content).toContain("# Edited by: alice");
  });

  it("ignores an unparseable mtime rather than inventing one", () => {
    const [f] = splitCollection(["==> /etc/crontab <==", "# mtime: never", "x"].join("\n"));
    expect(f.mtime).toBeUndefined();
  });
});

describe("singleArtifact — one collected file", () => {
  it("routes by filename", () => {
    expect(singleArtifact("authorized_keys", "ssh-rsa AAAA u@h")[0].kind).toBe("authorized_keys");
  });
  it("returns nothing for a name it cannot place", () => {
    expect(singleArtifact("notes.txt", "x")).toEqual([]);
  });
});

describe("parseAuthorizedKeys", () => {
  it("reads a plain key", () => {
    const [k] = parseAuthorizedKeys("ssh-ed25519 AAAAC3Nz alice@laptop");
    expect(k.type).toBe("ssh-ed25519");
    expect(k.blob).toBe("AAAAC3Nz");
    expect(k.comment).toBe("alice@laptop");
    expect(k.options).toBe("");
  });

  it("skips comments and blank lines", () => {
    expect(parseAuthorizedKeys("# a comment\n\n   \n")).toEqual([]);
  });

  // The options field is comma-separated, its values may be quoted, and a quoted value may hold
  // both spaces and commas. Splitting on whitespace first lost the command.
  it("keeps a quoted forced command that contains spaces and commas", () => {
    const [k] = parseAuthorizedKeys("command=\"/bin/bash -c 'a,b c'\",no-pty ssh-rsa AAAAB3 backup@host");
    expect(k.type).toBe("ssh-rsa");
    expect(k.blob).toBe("AAAAB3");
    expect(keyOption(k.options, "command")).toBe("/bin/bash -c 'a,b c'");
  });

  it("reads the options that follow a quoted value", () => {
    const [k] = parseAuthorizedKeys(
      'command="/usr/bin/rrsync /srv",no-agent-forwarding,from="10.0.0.1" ssh-rsa AAAA u@h',
    );
    expect(keyOption(k.options, "from")).toBe("10.0.0.1");
  });

  it("records the line number for the evidence link", () => {
    const keys = parseAuthorizedKeys("# c\nssh-rsa AAAA a@b\nssh-rsa BBBB c@d");
    expect(keys.map((k) => k.line)).toEqual([2, 3]);
  });

  it("ignores a line with no key material", () => {
    expect(parseAuthorizedKeys("ssh-rsa")).toEqual([]);
  });
});

describe("parseCrontab", () => {
  it("reads a five-field user crontab and takes the account from the path", () => {
    const { entries } = parseCrontab(
      "*/5 * * * * /usr/local/bin/backup.sh",
      "/var/spool/cron/crontabs/alice",
    );
    expect(entries[0].schedule).toBe("*/5 * * * *");
    expect(entries[0].user).toBe("alice");
    expect(entries[0].command).toBe("/usr/local/bin/backup.sh");
  });

  it("reads the user column of /etc/crontab", () => {
    const { entries } = parseCrontab("17 * * * * root cd / && run-parts /etc/cron.hourly", "/etc/crontab");
    expect(entries[0].user).toBe("root");
    expect(entries[0].command).toBe("cd / && run-parts /etc/cron.hourly");
  });

  it("reads @reboot and the other specials", () => {
    const { entries } = parseCrontab("@reboot /tmp/x.sh\n@daily /usr/bin/y", "/var/spool/cron/crontabs/bob");
    expect(entries.map((e) => e.schedule)).toEqual(["@reboot", "@daily"]);
  });

  it("separates environment assignments from jobs", () => {
    const { entries, env } = parseCrontab(
      "PATH=/tmp:/usr/bin\nSHELL=/bin/sh\n* * * * * bob /bin/true",
      "/var/spool/cron/crontabs/bob",
    );
    expect(env.map((e) => e.name)).toEqual(["PATH", "SHELL"]);
    expect(env[0].value).toBe("/tmp:/usr/bin");
    expect(entries).toHaveLength(1);
  });

  it("knows which files carry a user column", () => {
    expect(cronHasUserColumn("/etc/crontab")).toBe(true);
    expect(cronHasUserColumn("/etc/cron.d/backup")).toBe(true);
    expect(cronHasUserColumn("/var/spool/cron/crontabs/alice")).toBe(false);
  });

  it("ignores a short line rather than reading a schedule field as a command", () => {
    expect(parseCrontab("* * * *", "/etc/crontab").entries).toEqual([]);
  });
});

describe("parseUnit", () => {
  const unit = [
    "[Unit]",
    "Description=Update service",
    "[Service]",
    "Type=simple",
    "User=www-data",
    "ExecStartPre=/bin/mkdir -p /run/x",
    "ExecStart=/usr/local/bin/agent \\",
    "  --daemon",
    "Restart=always",
    "[Install]",
    "WantedBy=multi-user.target",
  ].join("\n");

  it("reads the directives from their own sections", () => {
    const u = parseUnit(unit);
    expect(u.description).toBe("Update service");
    expect(u.user).toBe("www-data");
    expect(u.restart).toBe("always");
    expect(u.wantedBy).toBe("multi-user.target");
    expect(u.execStartPre).toEqual(["/bin/mkdir -p /run/x"]);
  });

  it("joins a wrapped ExecStart", () => {
    expect(parseUnit(unit).execStart[0]).toBe("/usr/local/bin/agent --daemon");
  });

  it("honours systemd's empty-assignment reset", () => {
    const u = parseUnit("[Service]\nExecStart=/bin/a\nExecStart=\nExecStart=/bin/b");
    expect(u.execStart).toEqual(["/bin/b"]);
  });

  it("ignores a directive outside its own section, because systemd does", () => {
    const u = parseUnit("[Unit]\nExecStart=/tmp/evil\n[Service]\nExecStart=/bin/true");
    expect(u.execStart).toEqual(["/bin/true"]);
  });

  it("strips the execution-modifier prefixes", () => {
    expect(stripExecPrefix("-/bin/false")).toBe("/bin/false");
    expect(stripExecPrefix("+@/bin/x")).toBe("/bin/x");
  });
});

describe("shellInitLines", () => {
  it("drops comments and blanks and keeps line numbers", () => {
    const out = shellInitLines("# top\n\nexport A=1\n  \nrun me");
    expect(out).toEqual([
      { text: "export A=1", line: 3 },
      { text: "run me", line: 5 },
    ]);
  });

  it("does not treat a # inside quotes as a comment", () => {
    expect(shellInitLines(`echo "a # b"`)[0].text).toBe(`echo "a # b"`);
    expect(shellInitLines(`grep '#tag' f`)[0].text).toBe(`grep '#tag' f`);
  });

  it("strips a trailing comment that follows whitespace", () => {
    expect(shellInitLines("run me # why")[0].text).toBe("run me");
  });

  it("joins a backslash continuation and reports the first line", () => {
    expect(shellInitLines("curl x \\\n  | sh")).toEqual([{ text: "curl x | sh", line: 1 }]);
  });
});

describe("parseSuidListing", () => {
  it("reads find -ls output", () => {
    const [e] = parseSuidListing(
      "  1234   56 -rwsr-xr-x   1 root root    68208 Jan  1 10:00 /usr/bin/passwd",
    );
    expect(e.path).toBe("/usr/bin/passwd");
    expect(e.owner).toBe("root");
    expect(e.setuid).toBe(true);
  });

  it("reads ls -l output", () => {
    const [e] = parseSuidListing("-rwsr-xr-x 1 root root 68208 Jan  1 10:00 /usr/bin/sudo");
    expect(e.path).toBe("/usr/bin/sudo");
    expect(e.setuid).toBe(true);
  });

  it("reads a bare path list and says the setuid bit was not stated", () => {
    const [e] = parseSuidListing("/usr/bin/passwd");
    expect(e.path).toBe("/usr/bin/passwd");
    expect(e.setuid).toBeNull();
  });

  // Taking the last whitespace-separated field truncated a real path to its final word.
  it("keeps a path that contains spaces", () => {
    const [e] = parseSuidListing("-rwsr-xr-x 1 root root 100 Jan  1 10:00 /opt/My App/bin/helper");
    expect(e.path).toBe("/opt/My App/bin/helper");
  });

  it("records a mode that is not setuid as such", () => {
    const [e] = parseSuidListing("-rwxr-xr-x 1 root root 100 Jan  1 10:00 /usr/bin/ls");
    expect(e.setuid).toBe(false);
  });

  it("keeps the entry, not the symlink destination", () => {
    const [e] = parseSuidListing("-rwsr-xr-x 1 root root 100 Jan  1 10:00 /usr/bin/x -> /tmp/y");
    expect(e.path).toBe("/usr/bin/x");
  });
});

describe("parsePathEntries", () => {
  it("reads an env dump", () => {
    expect(parsePathEntries("HOME=/root\nPATH=/usr/bin:/bin\nSHELL=/bin/bash")).toEqual(["/usr/bin", "/bin"]);
  });

  it("reads an export line and strips the quotes", () => {
    expect(parsePathEntries('export PATH="/a:/b"')).toEqual(["/a", "/b"]);
  });

  // An empty entry IS the current directory. Dropping it erases the finding.
  it("keeps an empty entry", () => {
    expect(parsePathEntries("PATH=:/usr/bin")).toEqual(["", "/usr/bin"]);
    expect(parsePathEntries("PATH=/usr/bin::/bin")).toEqual(["/usr/bin", "", "/bin"]);
  });

  it("returns null when there is no PATH", () => {
    expect(parsePathEntries("HOME=/root")).toBeNull();
  });
});
