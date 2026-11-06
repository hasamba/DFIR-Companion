import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect as netConnect, type AddressInfo, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { certNamesFor, ensureServerCert, loadOrCreateCa } from "../../src/http/tlsMaterial.js";

// Local TLS test bed for the cloud transport (#2310): a test CA and server certificate made at
// runtime (no key material in the repo), an HTTPS server that plays every cloud endpoint, and a
// CONNECT proxy that sends every tunnel to that server whatever host was asked for. Fake host names
// use the reserved .test TLD, so a routing bug can never reach a real cloud endpoint. The one
// exception is Google's token endpoint, which google-auth-library hardcodes: those tests always go
// through the proxy, which answers for it locally.

export const GOOGLE_TOKEN_HOST = "oauth2.googleapis.com";

export const FAKE_HOSTS = [
  "sts.cloud.test",
  "s3.cloud.test",
  "login.cloud.test",
  "arm.cloud.test",
  "logging.cloud.test",
  "graph.cloud.test",
  GOOGLE_TOKEN_HOST,
];

export interface TlsMaterial {
  dir: string;
  /** A CA bundle file holding only the test CA's certificate. */
  caPath: string;
  keyPem: string;
  certPem: string;
  cleanup(): void;
}

export function makeTlsMaterial(): TlsMaterial {
  const dir = mkdtempSync(join(tmpdir(), "dfir-cloud-tls-"));
  const now = new Date();
  const { ca } = loadOrCreateCa(dir, now, "cloud-test");
  const server = ensureServerCert(dir, ca, certNamesFor(FAKE_HOSTS, "cloud-test", {}), now);
  const caPath = join(dir, "test-ca-cert.pem");
  writeFileSync(caPath, ca.certPem);
  return {
    dir,
    caPath,
    keyPem: server.keyPem,
    certPem: server.certPem,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

export interface SeenRequest {
  method: string;
  path: string;
  /** The TLS SNI the client sent: the destination host it believed it was talking to. */
  sni: string | undefined;
  body: string;
}

export type Route = (
  req: SeenRequest,
  origin: string,
) => { status?: number; type?: string; body: string } | undefined;

export interface TlsServer {
  port: number;
  origin: string;
  seen: SeenRequest[];
  close(): Promise<void>;
}

function reply(res: ServerResponse, out: ReturnType<Route>): void {
  if (!out) {
    res.writeHead(404, { "content-type": "text/plain" }).end("no route");
    return;
  }
  res.writeHead(out.status ?? 200, { "content-type": out.type ?? "application/json" }).end(out.body);
}

export async function startTlsServer(material: TlsMaterial, route: Route): Promise<TlsServer> {
  const seen: SeenRequest[] = [];
  const server = createHttpsServer({ key: material.keyPem, cert: material.certPem });
  server.on("request", (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const entry: SeenRequest = {
        method: req.method ?? "",
        path: req.url ?? "",
        sni: (req.socket as TLSSocket).servername || undefined,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      seen.push(entry);
      const host = req.headers.host ?? `127.0.0.1:${(server.address() as AddressInfo).port}`;
      reply(res, route(entry, `https://${host}`));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    origin: `https://127.0.0.1:${port}`,
    seen,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export interface ConnectProxy {
  url: string;
  /** Every CONNECT target asked for, as host:port. */
  tunnels: string[];
  close(): Promise<void>;
}

/** A CONNECT proxy that tunnels every request to 127.0.0.1:<targetPort>, recording the asked host. */
export async function startConnectProxy(targetPort: number): Promise<ConnectProxy> {
  const tunnels: string[] = [];
  const sockets = new Set<Socket>();
  const proxy = createHttpServer((_req, res) => res.writeHead(405).end());
  proxy.on("connect", (req: IncomingMessage, client: Socket, head: Buffer) => {
    tunnels.push(req.url ?? "");
    const upstream = netConnect(targetPort, "127.0.0.1", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    for (const s of [client, upstream]) {
      sockets.add(s);
      s.on("error", () => s.destroy());
      s.on("close", () => sockets.delete(s));
    }
  });
  await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  const port = (proxy.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    tunnels,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        proxy.close(() => resolve());
      }),
  };
}
