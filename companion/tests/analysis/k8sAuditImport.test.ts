import { describe, it, expect } from "vitest";
import { parseK8sAudit } from "../../src/analysis/k8sAuditImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

// A minimal audit.k8s.io Event; `over` overrides the interesting fields per test.
function event(over: object): object {
  return {
    kind: "Event",
    apiVersion: "audit.k8s.io/v1",
    level: "RequestResponse",
    stage: "ResponseComplete",
    requestReceivedTimestamp: "2024-08-01T12:00:00.000000Z",
    stageTimestamp: "2024-08-01T12:00:00.100000Z",
    user: { username: "dev@corp.local", groups: ["system:authenticated"] },
    sourceIPs: ["10.0.5.9"],
    verb: "get",
    objectRef: { resource: "pods", namespace: "default", name: "web-1" },
    responseStatus: { code: 200 },
    ...over,
  };
}
function ndjson(...evs: object[]): string {
  return evs.map((e) => JSON.stringify(e)).join("\n");
}

describe("parseK8sAudit — verdict-derived severity", () => {
  it("grades pod exec/attach as High (T1609 container administration command)", () => {
    const r = parseK8sAudit(ndjson(event({ verb: "create", objectRef: { resource: "pods", subresource: "exec", namespace: "prod", name: "api-7" } })));
    expect(r.format).toBe("k8s-audit");
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1609");
    expect(r.events[0].description).toContain("pods/exec");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("10.0.5.9");
  });

  it("grades secret list as High and a single secret get as Medium (T1552.007)", () => {
    const r = parseK8sAudit(ndjson(
      event({ verb: "list", objectRef: { resource: "secrets", namespace: "kube-system" } }),
      event({ verb: "get", objectRef: { resource: "secrets", namespace: "default", name: "db-cred" } }),
    ));
    const byVerb = Object.fromEntries(r.events.map((e) => [e.description.match(/K8s (\w+)/)![1], e]));
    expect(byVerb["list"].severity).toBe("High");
    expect(byVerb["get"].severity).toBe("Medium");
    for (const e of r.events) expect(e.mitreTechniques).toContain("T1552.007");
  });

  it("grades a cluster RBAC binding write as Critical and a namespaced one as High (T1098)", () => {
    const r = parseK8sAudit(ndjson(
      event({ verb: "create", objectRef: { resource: "clusterrolebindings", name: "pwn" } }),
      event({ verb: "patch", objectRef: { resource: "rolebindings", namespace: "team-a", name: "edit" } }),
    ));
    const byRes = Object.fromEntries(r.events.map((e) => [e.description.match(/K8s \w+ (\S+)/)![1], e]));
    expect(byRes["clusterrolebindings"].severity).toBe("Critical");
    expect(byRes["rolebindings"].severity).toBe("High");
    for (const e of r.events) expect(e.mitreTechniques).toContain("T1098.003");
  });

  it("grades a privileged-pod create as High (T1610/T1611) but a normal pod create as Info", () => {
    const priv = event({
      verb: "create",
      objectRef: { resource: "pods", namespace: "default", name: "escape" },
      requestObject: { spec: { containers: [{ name: "c", securityContext: { privileged: true } }] } },
    });
    const normal = event({ verb: "create", objectRef: { resource: "pods", namespace: "default", name: "plain" }, requestObject: { spec: { containers: [{ name: "c" }] } } });
    const r = parseK8sAudit(ndjson(priv, normal));
    const byName = Object.fromEntries(r.events.map((e) => [e.description.match(/"([^"]+)"/)![1], e]));
    expect(byName["escape"].severity).toBe("High");
    expect(byName["escape"].mitreTechniques).toEqual(expect.arrayContaining(["T1610", "T1611"]));
    expect(byName["plain"].severity).toBe("Info");
  });

  it("flags successful anonymous API access as High (T1078), denied anonymous as Low", () => {
    const r = parseK8sAudit(ndjson(
      event({ user: { username: "system:anonymous" }, verb: "get", objectRef: { resource: "pods", namespace: "kube-system" }, responseStatus: { code: 200 } }),
      event({ user: { username: "system:anonymous" }, verb: "list", objectRef: { resource: "nodes" }, responseStatus: { code: 403, reason: "Forbidden" } }),
    ));
    const byCode = Object.fromEntries(r.events.map((e) => [/\[40/.test(e.description) ? "denied" : "ok", e]));
    expect(byCode["ok"].severity).toBe("High");
    expect(byCode["ok"].mitreTechniques).toContain("T1078");
    expect(byCode["denied"].severity).toBe("Low");
  });

  it("keeps a routine authenticated get as Info evidence and reads the artifact's own time", () => {
    const r = parseK8sAudit(ndjson(event({})));
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].timestamp).toBe("2024-08-01T12:00:00.000Z");
    expect(r.events[0].sources).toEqual(["Kubernetes Audit"]);
  });

  it("reads an EventList batch and an empty input", () => {
    const batch = JSON.stringify({ kind: "EventList", apiVersion: "audit.k8s.io/v1", items: [event({}), event({ verb: "delete", objectRef: { resource: "secrets", namespace: "x" } })] });
    expect(parseK8sAudit(batch).events.length).toBe(2);
    expect(parseK8sAudit("").format).toBe("empty");
  });
});

describe("detectImportKind — routes k8s audit logs", () => {
  it("detects an audit.k8s.io event (NDJSON) as k8s", () => {
    expect(detectImportKind("audit.log", ndjson(event({})))).toBe("k8s");
  });
  it("detects an EventList batch as k8s", () => {
    const batch = JSON.stringify({ kind: "EventList", apiVersion: "audit.k8s.io/v1", items: [event({})] });
    expect(detectImportKind("audit.json", batch)).toBe("k8s");
  });
});
