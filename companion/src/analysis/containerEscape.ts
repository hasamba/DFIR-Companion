// Container escape (#908 item 11).
//
// Kubernetes privileged-pod creation is already graded by k8sAuditImport.ts. Docker is not covered
// at all, and Docker is where most of this happens: the socket, the capabilities, the host mounts
// and the shared namespaces are all one flag away on a command line an operator types.
//
// ─────────────────────────── CONFIGURATION IS NOT BEHAVIOUR ───────────────────────────
//
// The issue asks for that separation by name, and it is the whole design here. They are different
// claims about different facts, and confusing them is how a report ends up asserting a breach that
// did not happen:
//
//   • A CONFIGURATION makes escape POSSIBLE. `--privileged`, a mounted docker socket, `--pid=host`.
//     Every CI runner, every monitoring agent, every backup container and most of the Docker
//     ecosystem runs with at least one of these. It is a risk, not an event, and it is graded
//     Medium with those words on it.
//   • A BEHAVIOUR is escape being ATTEMPTED or ACHIEVED. `nsenter -t 1`, `chroot /host`, a write to
//     the cgroup release_agent, a write to a host persistence path through a mount. Those have no
//     ordinary explanation, and they are High.
//
// The one exception in each direction is stated on the finding rather than being handled silently:
// a configuration whose container ALSO shows escape behaviour is reported as the pair, and a
// behaviour with no configuration behind it is still a behaviour.
//
// ─────────────────────────── LINKING HOST AND CONTAINER ───────────────────────────
//
// A container-originated change to host persistence is the one finding that needs both halves. The
// container writes to `/host/etc/cron.d/x`; the host's own collection shows a cron job at
// `/etc/cron.d/x` (#908 item 5). Neither alone says how the job got there. Together they do, and
// the pass names the host path the mount maps to so an analyst can look for it.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { judgePayload } from "./linuxPayload.js";

/** The marker this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const ESCAPE_MARKER = "[container escape:";

/** How far apart a configuration and a behaviour may sit and still be reported as one story. */
export const DEFAULT_WINDOW_MS = 24 * 60 * 60 * 1000;

/** How much of one command line is read. */
export const MAX_COMMAND = 8_192;

export type EscapeKind = "config" | "behavior";

export interface EscapeHit {
  id: string;
  kind: EscapeKind;
  /** Short label for the primitive, used to group and to dedup. */
  primitive: string;
  /** What it means, in words an analyst can check. */
  detail: string;
  mitre: string[];
  /** The container this came from, when the evidence named one. */
  container: string;
  /** The host path a mount exposes, when this hit is about one. */
  hostPath: string;
}

const CONTAINER_CMD_RE = /\b(?:docker|podman|nerdctl|ctr)\b/i;

// ─────────────────────────── configuration ───────────────────────────

/** Capabilities that hand a container the host, one way or another. */
const DANGEROUS_CAPS: Record<string, string> = {
  sys_admin: "SYS_ADMIN is most of root: it allows mount, and mount is a filesystem escape",
  sys_ptrace: "SYS_PTRACE allows attaching to processes outside the container when PID namespaces are shared",
  sys_module: "SYS_MODULE allows loading a kernel module, which ends any container boundary",
  dac_read_search: "DAC_READ_SEARCH allows reading any file on the host through open_by_handle_at",
  dac_override: "DAC_OVERRIDE bypasses file permission checks",
  sys_rawio: "SYS_RAWIO allows raw access to devices, including the host's disks",
  sys_boot: "SYS_BOOT allows rebooting the host",
  bpf: "BPF allows loading eBPF programs, which run in the kernel",
  all: "ALL grants every capability, which is the same as --privileged for this purpose",
};

/** Host paths whose exposure to a container is an escape primitive. */
const SENSITIVE_HOST_MOUNTS: { re: RegExp; why: string }[] = [
  {
    re: /^\/(?:var\/)?run\/docker\.sock$/i,
    why: "the Docker socket. Anything that can write to it can start a new privileged container, which is root on the host",
  },
  { re: /^\/$/, why: "the entire host filesystem" },
  { re: /^\/etc\/?$/i, why: "the host's /etc, which includes its users, cron and systemd units" },
  { re: /^\/root\/?$/i, why: "root's home directory, including its SSH keys" },
  { re: /^\/home\/?$/i, why: "every user's home directory on the host" },
  { re: /^\/proc\/?$/i, why: "the host's /proc, which exposes every process and several kernel controls" },
  {
    re: /^\/sys\/?$/i,
    why: "the host's /sys, which exposes kernel controls including the cgroup release_agent",
  },
  {
    re: /^\/var\/run\/?$/i,
    why: "the host's runtime directory, which usually contains the container socket",
  },
  { re: /^\/dev\/?$/i, why: "the host's device nodes, including its raw disks" },
  {
    re: /^\/var\/lib\/(?:docker|kubelet|containerd)\/?/i,
    why: "the container runtime's own state, which includes every other container's filesystem",
  },
];

export interface ConfigRisk {
  primitive: string;
  detail: string;
  mitre: string[];
  hostPath: string;
}

/** Split a command line into tokens, honouring quotes. */
function tokens(command: string): string[] {
  const out: string[] = [];
  let current = "";
  let quote = "";
  for (const ch of (command ?? "").slice(0, MAX_COMMAND)) {
    if (quote) {
      if (ch === quote) quote = "";
      else current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (/\s/.test(ch)) {
      if (current) out.push(current);
      current = "";
    } else current += ch;
  }
  if (current) out.push(current);
  return out;
}

/** The value of `--flag=value` or `--flag value`. */
function flagValue(list: string[], i: number, flag: string): string {
  const t = list[i];
  if (t.startsWith(`${flag}=`)) return t.slice(flag.length + 1);
  if (t === flag) return list[i + 1] ?? "";
  return "";
}

/**
 * Read the escape primitives a container-run command line configures.
 *
 * Returns every one it finds, because they combine: a docker socket AND `--pid=host` is a different
 * conversation from either alone, and the finding lists them.
 */
export function configRisks(command: string): ConfigRisk[] {
  const cmd = (command ?? "").slice(0, MAX_COMMAND);
  if (!CONTAINER_CMD_RE.test(cmd)) return [];
  const list = tokens(cmd);
  const out: ConfigRisk[] = [];
  const seen = new Set<string>();
  const add = (r: ConfigRisk) => {
    if (seen.has(r.primitive)) return;
    seen.add(r.primitive);
    out.push(r);
  };

  for (let i = 0; i < list.length; i++) {
    const t = list[i];

    if (t === "--privileged" || t.startsWith("--privileged=")) {
      if (!/=false$/i.test(t)) {
        add({
          primitive: "privileged",
          detail:
            "The container runs --privileged, which gives it every capability, all devices and no seccomp or AppArmor profile. Escaping from it is a documented one-liner, not an exploit.",
          mitre: ["T1611"],
          hostPath: "",
        });
      }
      continue;
    }

    for (const flag of ["-v", "--volume", "--mount"]) {
      const value = flagValue(list, i, flag);
      if (!value) continue;
      // -v HOST:CONTAINER[:opts], or --mount type=bind,source=HOST,target=CONTAINER
      const source =
        /source=([^,]+)|src=([^,]+)/i.exec(value)?.[1] ??
        /source=([^,]+)|src=([^,]+)/i.exec(value)?.[2] ??
        value.split(":")[0];
      const target =
        /target=([^,]+)|destination=([^,]+)|dst=([^,]+)/i.exec(value)?.slice(1).find(Boolean) ??
        value.split(":")[1] ??
        "";
      const host = (source ?? "").trim();
      if (!host.startsWith("/")) continue;
      const match = SENSITIVE_HOST_MOUNTS.find((m) => m.re.test(host.replace(/\/+$/, "") || "/"));
      if (!match) continue;
      add({
        primitive: `mount:${host}`,
        detail: `The container mounts ${host}${target ? ` at ${target}` : ""} — ${match.why}.`,
        mitre: ["T1611"],
        hostPath: host,
      });
    }

    for (const flag of ["--cap-add", "--capabilities"]) {
      const value = flagValue(list, i, flag).toLowerCase().replace(/^cap_/, "");
      if (!value) continue;
      const why = DANGEROUS_CAPS[value];
      if (!why) continue;
      add({
        primitive: `cap:${value}`,
        detail: `The container is granted ${value.toUpperCase()}: ${why}.`,
        mitre: ["T1611"],
        hostPath: "",
      });
    }

    for (const [flag, what] of [
      ["--pid", "process"],
      ["--net", "network"],
      ["--network", "network"],
      ["--ipc", "IPC"],
      ["--uts", "UTS"],
      ["--userns", "user"],
      ["--cgroupns", "cgroup"],
    ] as const) {
      const value = flagValue(list, i, flag).toLowerCase();
      if (value !== "host") continue;
      add({
        primitive: `ns:${what}`,
        detail:
          what === "process"
            ? "The container shares the host's PID namespace, so it can see and — with the right capability — attach to every process on the host, including PID 1."
            : `The container shares the host's ${what} namespace, so that boundary does not exist for it.`,
        mitre: ["T1611"],
        hostPath: "",
      });
    }

    const secOpt = flagValue(list, i, "--security-opt").toLowerCase();
    if (/(?:seccomp|apparmor)\s*[=:]\s*unconfined/.test(secOpt)) {
      add({
        primitive: `secopt:${secOpt.split(/[=:]/)[0]}`,
        detail: `The container runs with ${secOpt.split(/[=:]/)[0]} unconfined, so the syscall filtering that blocks most escape techniques is off.`,
        mitre: ["T1611"],
        hostPath: "",
      });
    }

    const device = flagValue(list, i, "--device");
    if (device && /^\/dev\/(?:sd|nvme|vd|hd|mem|kmem|kmsg|port)/i.test(device)) {
      add({
        primitive: `device:${device}`,
        detail: `The container is given ${device}, a raw device. A raw disk can be read and written past every filesystem permission on the host.`,
        mitre: ["T1611"],
        hostPath: device,
      });
    }
  }
  return out;
}

// ─────────────────────────── behaviour ───────────────────────────

/** Paths on a mounted host filesystem whose modification IS host persistence. */
const HOST_PERSISTENCE_RE =
  /\/(?:etc\/(?:cron\.[a-z]+\/|cron\.d\/|crontab|systemd\/system\/|rc\.local|profile\.d\/|sudoers(?:\.d\/)?|ld\.so\.preload|passwd|shadow)|root\/\.ssh\/|home\/[^/]+\/\.ssh\/|var\/spool\/cron\/)/i;

/** A mount point a container commonly gives the host filesystem. */
const HOST_MOUNT_PREFIX_RE = /^(\/(?:host|hostfs|mnt\/host|rootfs|host-root|mnt\/root|media\/root))(\/.*)$/i;

export interface BehaviorHit {
  primitive: string;
  detail: string;
  mitre: string[];
  hostPath: string;
}

/**
 * Escape being attempted or achieved.
 *
 * None of these has an ordinary explanation from inside a container. That is what separates them
 * from the configuration list, where nearly everything has one.
 */
export function escapeBehavior(command: string): BehaviorHit[] {
  const cmd = (command ?? "").slice(0, MAX_COMMAND);
  const out: BehaviorHit[] = [];

  // nsenter into PID 1's namespaces is THE escape one-liner for a --pid=host container.
  if (/\bnsenter\b[^\n]{0,200}(?:-t\s*1\b|--target[= ]\s*1\b)/i.test(cmd)) {
    out.push({
      primitive: "nsenter-pid1",
      detail:
        "nsenter was run against PID 1, which enters the host's own namespaces. After this the process is running on the host, not in the container.",
      mitre: ["T1611"],
      hostPath: "",
    });
  }

  if (/\bchroot\s+(\/(?:host|hostfs|mnt\/host|rootfs|host-root|mnt|media\/root)[^\s]*)/i.test(cmd)) {
    const target = /\bchroot\s+(\/[^\s]+)/i.exec(cmd)?.[1] ?? "";
    out.push({
      primitive: "chroot-host",
      detail: `chroot into ${target}, a mounted host filesystem. Everything after this runs against the host's files, not the container's.`,
      mitre: ["T1611"],
      hostPath: target,
    });
  }

  // The cgroup v1 release_agent escape: the kernel runs the named program on the HOST.
  if (/release_agent|notify_on_release/i.test(cmd) && /(?:echo|printf|tee|>)/.test(cmd)) {
    out.push({
      primitive: "release-agent",
      detail:
        "A cgroup release_agent was written. The kernel runs that program on the HOST when the cgroup empties, so this is a container-to-host code-execution primitive, not a configuration.",
      mitre: ["T1611"],
      hostPath: "",
    });
  }

  if (/\/proc\/sys\/kernel\/core_pattern/i.test(cmd) && /(?:echo|printf|tee|>)/.test(cmd)) {
    out.push({
      primitive: "core-pattern",
      detail:
        "The kernel's core_pattern was written. A crashing process then runs the named program on the host with full privileges.",
      mitre: ["T1611"],
      hostPath: "/proc/sys/kernel/core_pattern",
    });
  }

  // Talking to the Docker API through the socket from inside a container.
  if (
    /--unix-socket\s+\/(?:var\/)?run\/docker\.sock/i.test(cmd) ||
    /\bdocker\b[^\n]{0,80}-H\s+unix:\/\//i.test(cmd)
  ) {
    out.push({
      primitive: "docker-api",
      detail:
        "The Docker API was called over the daemon's unix socket. Whatever holds that socket can create a container with the host's filesystem mounted, which is root on the host.",
      mitre: ["T1610", "T1611"],
      hostPath: "/var/run/docker.sock",
    });
  }

  // Writing host persistence through a mount. This is the one that needs both halves.
  const write =
    /(?:^|[\s>|;&])(?:tee|cp|mv|install|cat\s*>|echo[^\n>]{0,200}>{1,2})\s*("?)(\/[^\s"']+)/i.exec(cmd);
  const target = write?.[2] ?? "";
  const mounted = HOST_MOUNT_PREFIX_RE.exec(target);
  if (mounted && HOST_PERSISTENCE_RE.test(mounted[2])) {
    out.push({
      primitive: "host-persistence-write",
      detail: `A write to ${target} — that path is inside a mounted host filesystem, and on the host it is ${mounted[2]}, which decides what the HOST runs. This is a container-originated change to host persistence.`,
      mitre: ["T1611", "T1543"],
      hostPath: mounted[2],
    });
  }

  // A payload judgement adds nothing new here, but a fetch-and-execute inside an escape command
  // says the operator brought their own tooling with them.
  const j = judgePayload(cmd);
  if (out.length > 0 && (j.fetchExec || j.reverseShell)) {
    out.push({
      primitive: "escape-payload",
      detail: j.reverseShell
        ? "The same command opens a connection back to a remote host."
        : "The same command downloads code and runs it.",
      mitre: ["T1059.004"],
      hostPath: "",
    });
  }
  return out;
}

// ─────────────────────────── the timeline pass ───────────────────────────

const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const DESCRIPTION_MAX = 600;

function commandOf(e: ForensicEvent): string {
  return `${e.commandLine ?? ""} ${e.description ?? ""}`;
}

/**
 * Grade container-escape evidence on the timeline.
 *
 * Only ever raises, and appends its marker once.
 */
export function markContainerEscape(events: readonly ForensicEvent[]): ForensicEvent[] {
  let changed = false;
  const out = events.map((e) => {
    if ((e.description ?? "").includes(ESCAPE_MARKER)) return e;
    const cmd = commandOf(e);

    const behaviors = escapeBehavior(cmd);
    if (behaviors.length > 0) {
      changed = true;
      const persistence = behaviors.find((b) => b.primitive === "host-persistence-write");
      const reason =
        `Container escape BEHAVIOUR, not configuration: ${behaviors.map((b) => b.detail).join(" ")} ` +
        (persistence
          ? `Look for ${persistence.hostPath} in the host's own collection — the host artifact and this write are two halves of one event, and neither alone shows how the entry got there.`
          : "This is evidence of an attempt or a success, and it has no ordinary explanation from inside a container.");
      return {
        ...e,
        severity: RANK.High > RANK[e.severity] ? "High" : e.severity,
        mitreTechniques: [...new Set([...(e.mitreTechniques ?? []), ...behaviors.flatMap((b) => b.mitre)])],
        description: `${(e.description ?? "").slice(0, DESCRIPTION_MAX)} ${ESCAPE_MARKER} ${reason}]`.trim(),
      };
    }

    const risks = configRisks(cmd);
    if (risks.length === 0) return e;
    changed = true;
    const reason =
      `Container escape CONFIGURATION, not behaviour: ${risks.map((r) => r.detail).join(" ")} ` +
      "This makes escape possible and does NOT show that anyone escaped — CI runners, monitoring agents and backup containers routinely run this way. " +
      (risks.length > 1
        ? `${risks.length} separate primitives are combined here, which is worth more than any one of them alone. `
        : "") +
      "Confirm the container is meant to run this way, and look for what it actually did.";
    return {
      ...e,
      // Medium, deliberately. A configuration is a risk, and a High on every CI runner in the
      // estate would bury the behaviours that are the real finding.
      severity: RANK.Medium > RANK[e.severity] ? "Medium" : e.severity,
      mitreTechniques: [...new Set([...(e.mitreTechniques ?? []), ...risks.flatMap((r) => r.mitre)])],
      description: `${(e.description ?? "").slice(0, DESCRIPTION_MAX)} ${ESCAPE_MARKER} ${reason}]`.trim(),
    };
  });

  return changed ? out : (events as ForensicEvent[]);
}

/** Host paths the containers in this case expose, for an analyst asking what is reachable. */
export function exposedHostPaths(events: readonly ForensicEvent[]): string[] {
  const out = new Set<string>();
  for (const e of events) {
    for (const r of configRisks(commandOf(e))) if (r.hostPath) out.add(r.hostPath);
  }
  return [...out].sort();
}
