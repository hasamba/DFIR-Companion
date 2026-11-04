import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { request as httpsRequest } from "node:https";
import { request as httpRequest, type RequestListener } from "node:http";
import { connect as tlsConnect } from "node:tls";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import express from "express";
import {
  httpsRedirectTarget,
  listenHttps,
  listenPlainHttp,
  redirectToHttps,
} from "../../src/http/httpsListener.js";
import { prepareHttps } from "../../src/http/httpsStartup.js";

const DAY = 86_400_000;
let root: string;
const servers: { close: () => unknown }[] = [];
const quiet = { log: () => {}, warn: () => {} };

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "dfir-https-"));
});
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
  rmSync(root, { recursive: true, force: true });
});

function listening<T extends { address(): unknown }>(start: (cb: () => void) => T) {
  return new Promise<{ server: T; port: number }>((resolve) => {
    const server: T = start(() => resolve({ server, port: (server.address() as AddressInfo).port }));
  });
}

function get(port: number, ca: string, path = "/") {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = httpsRequest(
      { host: "127.0.0.1", port, path, ca, servername: "localhost", agent: false },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode!, body }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function peerFingerprint(port: number) {
  return new Promise<string>((resolve, reject) => {
    const socket = tlsConnect({ host: "127.0.0.1", port, rejectUnauthorized: false }, () => {
      resolve(socket.getPeerX509Certificate()!.fingerprint256);
      socket.end();
    });
    socket.on("error", reject);
  });
}

describe("built-in HTTPS listener (#2285)", () => {
  it("serves the app over TLS, verifiable against the downloadable CA, with req.secure", async () => {
    const prepared = prepareHttps({
      env: { DFIR_HTTPS: "on" },
      casesRoot: join(root, "cases"),
      teamMode: false,
      port: 0,
      ...quiet,
    });
    const app = express();
    app.get("/", (req, res) => res.json({ secure: req.secure }));
    let upgraded = false;
    const { server, port } = await listening((cb) =>
      listenHttps(app, 0, "127.0.0.1", prepared.material!, cb),
    );
    servers.push(server);
    server.on("upgrade", (_req, socket) => {
      upgraded = true;
      socket.destroy();
    });
    expect(await get(port, prepared.caCertPem()!)).toEqual({
      status: 200,
      body: JSON.stringify({ secure: true }),
    });

    await new Promise<void>((resolve) => {
      const req = httpsRequest({
        host: "127.0.0.1",
        port,
        ca: prepared.caCertPem()!,
        servername: "localhost",
        agent: false,
        headers: { Connection: "Upgrade", Upgrade: "websocket" },
      });
      req.on("error", () => resolve());
      req.on("close", () => resolve());
      req.end();
    });
    expect(upgraded).toBe(true);
  });

  it("swaps in a renewed certificate without a restart", async () => {
    let clock = new Date("2026-11-04T10:00:00Z");
    const prepared = prepareHttps({
      env: { DFIR_HTTPS: "on" },
      casesRoot: join(root, "cases"),
      teamMode: false,
      port: 0,
      now: () => clock,
      ...quiet,
    });
    const { server, port } = await listening((cb) =>
      listenHttps(express(), 0, "127.0.0.1", prepared.material!, cb),
    );
    servers.push(server);
    const before = await peerFingerprint(port);
    const renewal = prepared.startRenewal(server);
    clock = new Date(clock.getTime() + 800 * DAY);
    renewal.check();
    renewal.stop();
    const after = await peerFingerprint(port);
    expect(after).not.toBe(before);
    expect(prepared.status().server?.fingerprint256).toBe(after);
  });

  it("retries a renewal whose certificate swap failed", () => {
    let clock = new Date("2026-11-04T10:00:00Z");
    const prepared = prepareHttps({
      env: { DFIR_HTTPS: "on" },
      casesRoot: join(root, "cases"),
      teamMode: false,
      port: 0,
      now: () => clock,
      ...quiet,
    });
    const original = prepared.status().server!.fingerprint256;
    let calls = 0;
    const server = {
      setSecureContext: () => {
        calls++;
        if (calls === 1) throw new Error("swap failed");
      },
    };
    const renewal = prepared.startRenewal(server);
    clock = new Date(clock.getTime() + 800 * DAY);
    renewal.check(); // re-issues to disk, swap throws: still serving the original
    expect(prepared.status().server!.fingerprint256).toBe(original);
    renewal.check(); // nothing new to issue, but the unserved certificate on disk is swapped in now
    renewal.stop();
    expect(calls).toBe(2);
    expect(prepared.status().server!.fingerprint256).not.toBe(original);
  });

  it("creates the CA even with HTTPS off, and offers it for download", () => {
    const prepared = prepareHttps({
      env: {},
      casesRoot: join(root, "cases"),
      teamMode: false,
      port: 4773,
      ...quiet,
    });
    expect(prepared.config.enabled).toBe(false);
    expect(prepared.material).toBeUndefined();
    expect(prepared.caCertPem()).toMatch(/BEGIN CERTIFICATE/);
    expect(prepared.status()).toMatchObject({ enabled: false, caDownload: true });
  });

  it("turns on in team mode under auto and says why", () => {
    const lines: string[] = [];
    const prepared = prepareHttps({
      env: {},
      casesRoot: join(root, "cases"),
      teamMode: true,
      port: 4773,
      log: (m) => lines.push(m),
      warn: () => {},
    });
    expect(prepared.status()).toMatchObject({ enabled: true, enabledBy: "team-mode", source: "generated" });
    expect(lines.join("\n")).toMatch(/because team mode is on/);
    expect(lines.join("\n")).toMatch(/SHA-256 [0-9A-F:]{95}/);
  });
});

describe("plain-HTTP side door", () => {
  const opts = { httpsPort: 4773, isHostAllowed: (h: string) => !h.startsWith("evil") };

  it("redirects a page load to the same host on the HTTPS port", () => {
    expect(httpsRedirectTarget("GET", "/dashboard?x=1", "dfir.lab:4774", opts)).toBe(
      "https://dfir.lab:4773/dashboard?x=1",
    );
    expect(httpsRedirectTarget("HEAD", "/", "[FD00::5]:4774", opts)).toBe("https://[fd00::5]:4773/");
    expect(httpsRedirectTarget("GET", "/", "x", { ...opts, publicOrigin: "https://dfir.example" })).toBe(
      "https://dfir.example/",
    );
  });

  it("never redirects a request that may carry secrets, or to an untrusted target", () => {
    expect(httpsRedirectTarget("POST", "/auth/local/login", "dfir.lab", opts)).toBeUndefined();
    expect(httpsRedirectTarget("GET", "//evil.example/", "dfir.lab", opts)).toBeUndefined();
    expect(httpsRedirectTarget("GET", "/\\evil", "dfir.lab", opts)).toBeUndefined();
    expect(httpsRedirectTarget("GET", "http://evil/", "dfir.lab", opts)).toBeUndefined();
    expect(httpsRedirectTarget("GET", "/", "evil.example", opts)).toBeUndefined();
    expect(httpsRedirectTarget("GET", "/", "user@dfir.lab", opts)).toBeUndefined();
    expect(httpsRedirectTarget("GET", "/", undefined, opts)).toBeUndefined();
  });

  it("answers 308 or 400 over a real socket", async () => {
    const handler: RequestListener = redirectToHttps(opts);
    const { server, port } = await listening((cb) => listenPlainHttp(handler, 0, "127.0.0.1", cb));
    servers.push(server);
    const send = (method: string) =>
      new Promise<{ status: number; location?: string }>((resolve, reject) => {
        const req = httpRequest(
          { host: "127.0.0.1", port, method, path: "/x", headers: { Host: "dfir.lab" }, agent: false },
          (res) => {
            res.resume();
            resolve({
              status: res.statusCode!,
              ...(res.headers.location ? { location: res.headers.location } : {}),
            });
          },
        );
        req.on("error", reject);
        req.end();
      });
    expect(await send("GET")).toEqual({ status: 308, location: "https://dfir.lab:4773/x" });
    expect((await send("POST")).status).toBe(400);
  });
});
