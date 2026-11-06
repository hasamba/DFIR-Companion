import { createRequire } from "node:module";
import { format } from "node:util";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cloudTransportSettingsFromEnv } from "../../../src/composition/cloudTransportEnv.js";
import {
  createCloudTransport,
  type CloudTransport,
} from "../../../src/integrations/cloudTransport/cloudAgent.js";
import { cloudFetch } from "../../../src/integrations/cloudTransport/cloudFetch.js";
import { CloudTransportError } from "../../../src/integrations/cloudTransport/destinationTls.js";
import {
  makeTlsMaterial,
  startConnectProxy,
  startTlsServer,
  type ConnectProxy,
  type TlsMaterial,
  type TlsServer,
} from "../../helpers/cloudTlsHarness.js";

// The shared cloud transport (#2310): the CA, insecure and proxy policy, decided per destination.

let material: TlsMaterial;
let server: TlsServer;
let proxy: ConnectProxy;
const open: CloudTransport[] = [];

function transport(settings: Parameters<typeof createCloudTransport>[0]): CloudTransport {
  const t = createCloudTransport(settings);
  open.push(t);
  return t;
}

beforeAll(async () => {
  material = makeTlsMaterial();
  server = await startTlsServer(material, (req) => ({ body: JSON.stringify({ path: req.path }) }));
  proxy = await startConnectProxy(server.port);
});
afterEach(() => {
  for (const t of open.splice(0)) t.close();
  vi.unstubAllEnvs();
  server.seen.length = 0;
  proxy.tunnels.length = 0;
  proxy.proxyAuth.length = 0;
});
afterAll(async () => {
  await proxy.close();
  await server.close();
  material.cleanup();
});

describe("CA bundle", () => {
  it("verifies a server signed by the configured CA", async () => {
    const res = await cloudFetch(transport({ caCertPath: material.caPath }))(`${server.origin}/ok`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ path: "/ok" });
  });

  it("rejects the same server without the CA — the default trust is unchanged", async () => {
    await expect(cloudFetch(transport({}))(`${server.origin}/ok`)).rejects.toThrow(/certificate/i);
    expect(server.seen).toEqual([]);
  });

  it("fails the run up front when the CA bundle cannot be read, naming the path only", () => {
    expect(() => createCloudTransport({ caCertPath: "/nonexistent/cloud-ca.pem" })).toThrow(
      CloudTransportError,
    );
    expect(() => createCloudTransport({ caCertPath: "/nonexistent/cloud-ca.pem" })).toThrow(/cloud-ca\.pem/);
  });
});

describe("insecure override — same rule as the other features", () => {
  it("is allowed toward a loopback host", async () => {
    const res = await cloudFetch(transport({ insecure: true }))(`${server.origin}/ok`);
    expect(res.status).toBe(200);
  });

  it("is refused toward a non-loopback host, before any connection is made", async () => {
    vi.stubEnv("DFIR_TLS_ALLOW_INSECURE_EXTERNAL", "");
    const t = transport({ insecure: true, proxyUrl: proxy.url });
    await expect(cloudFetch(t)("https://login.cloud.test/token")).rejects.toThrow(
      /DFIR_TLS_ALLOW_INSECURE_EXTERNAL/,
    );
    expect(proxy.tunnels).toEqual([]);
    expect(server.seen).toEqual([]);
  });

  it("applies to a non-loopback host once DFIR_TLS_ALLOW_INSECURE_EXTERNAL=true", async () => {
    vi.stubEnv("DFIR_TLS_ALLOW_INSECURE_EXTERNAL", "true");
    const res = await cloudFetch(transport({ insecure: true, proxyUrl: proxy.url }))(
      "https://login.cloud.test/t",
    );
    expect(res.status).toBe(200);
  });
});

describe("proxy", () => {
  it("tunnels every destination through the proxy and verifies the REAL host past it", async () => {
    const fetchCloud = cloudFetch(transport({ caCertPath: material.caPath, proxyUrl: proxy.url }));
    expect((await fetchCloud("https://login.cloud.test/a")).status).toBe(200);
    expect((await fetchCloud("https://graph.cloud.test/b")).status).toBe(200);
    expect(proxy.tunnels).toEqual(["login.cloud.test:443", "graph.cloud.test:443"]);
    expect(server.seen.map((r) => r.sni)).toEqual(["login.cloud.test", "graph.cloud.test"]);
  });

  it("still enforces the CA past the proxy", async () => {
    const fetchCloud = cloudFetch(transport({ proxyUrl: proxy.url }));
    await expect(fetchCloud("https://login.cloud.test/a")).rejects.toThrow(/certificate/i);
    expect(proxy.tunnels).toEqual(["login.cloud.test:443"]);
  });

  it("sends proxy credentials as Proxy-Authorization and never writes them to debug output", async () => {
    // The debug instance https-proxy-agent itself imports, switched on the way DEBUG= would.
    const proxyRequire = createRequire(createRequire(import.meta.url).resolve("https-proxy-agent"));
    const debug = proxyRequire("debug") as {
      enable(ns: string): void;
      disable(): string;
      log: (...args: unknown[]) => void;
    };
    const captured: string[] = [];
    const originalLog = debug.log;
    debug.log = (...args: unknown[]) => captured.push(format(...args));
    debug.enable("https-proxy-agent*");
    try {
      const withLogin = proxy.url.replace("http://", "http://pxuser:pxs%40cret@");
      const res = await cloudFetch(transport({ caCertPath: material.caPath, proxyUrl: withLogin }))(
        "https://login.cloud.test/a",
      );
      expect(res.status).toBe(200);
    } finally {
      debug.disable();
      debug.log = originalLog;
    }
    expect(proxy.proxyAuth).toEqual([`Basic ${Buffer.from("pxuser:pxs@cret").toString("base64")}`]);
    expect(captured.length).toBeGreaterThan(0); // the debug channel really was on
    const log = captured.join("\n");
    for (const secret of [
      "pxuser",
      "pxs@cret",
      "pxs%40cret",
      Buffer.from("pxuser:pxs@cret").toString("base64"),
    ]) {
      expect(log).not.toContain(secret);
    }
  });

  it("refuses a proxy URL that is not http(s)", () => {
    expect(() => createCloudTransport({ proxyUrl: "socks5://127.0.0.1:1080" })).toThrow(
      /http:\/\/ or https:\/\//,
    );
    expect(() => createCloudTransport({ proxyUrl: "not a url" })).toThrow(CloudTransportError);
  });
});

describe("cloudFetch", () => {
  it("returns an HTTP error status as a Response instead of throwing", async () => {
    const res = await cloudFetch(transport({ caCertPath: material.caPath }))(`${server.origin}/x`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(res.ok).toBe(true);
    expect(server.seen[0]).toMatchObject({ method: "POST", body: "{}" });
  });

  it("refuses a non-http scheme", async () => {
    await expect(cloudFetch(transport({}))("file:///etc/passwd")).rejects.toThrow(/unsupported scheme/);
  });
});

describe("settings from env", () => {
  it("reads the DFIR_CLOUD_* family and ignores HTTPS_PROXY", () => {
    expect(cloudTransportSettingsFromEnv({ HTTPS_PROXY: "http://corp:3128" })).toEqual({});
    expect(
      cloudTransportSettingsFromEnv({
        DFIR_CLOUD_CA: " /etc/ca.pem ",
        DFIR_CLOUD_INSECURE: "1",
        DFIR_CLOUD_PROXY_URL: "http://proxy:3128",
      }),
    ).toEqual({ caCertPath: "/etc/ca.pem", insecure: true, proxyUrl: "http://proxy:3128" });
    expect(cloudTransportSettingsFromEnv({ DFIR_CLOUD_INSECURE: "0" })).toEqual({});
  });
});
