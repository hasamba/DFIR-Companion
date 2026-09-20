import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import WebSocket from "ws";
import { CaseStore } from "../../src/storage/caseStore.js";
import { LiveHub } from "../../src/live/hub.js";
import { attachLiveSocket } from "../../src/live/wsGate.js";
import { hashCasePassword, signUnlockToken, unlockCookieName } from "../../src/analysis/casePassword.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

let store: CaseStore;
let hub: LiveHub;
let server: Server;
let port: number;
let secret: Buffer;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-wsattach-")));
  await store.createCase({ caseId: "locked", name: "n", investigator: "i", aiProvider: null });
  await store.updateCaseMeta("locked", { password: await hashCasePassword("secret123") });
  secret = randomBytes(32);
  hub = new LiveHub();
  server = createServer();
  attachLiveSocket(server, hub, { store, secret, allowedOrigins: [] });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as { port: number }).port;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

// Connect, then broadcast, then report whether the socket received the state.
async function sawStateBroadcast(query: string, headers: Record<string, string> = {}): Promise<boolean> {
  const socket = new WebSocket(`ws://127.0.0.1:${port}/ws?${query}`, { headers });
  const received: string[] = [];
  socket.on("message", (data) => received.push(String(data)));

  const settled = await new Promise<"open" | "closed">((resolve) => {
    socket.on("open", () => resolve("open"));
    socket.on("close", () => resolve("closed"));
    socket.on("error", () => resolve("closed"));
  });
  if (settled === "open") {
    hub.broadcast({
      caseId: "locked",
      findings: [{ secret: "exfiltrated" }],
    } as unknown as InvestigationState);
    await new Promise((r) => setTimeout(r, 50)); // let any message land
  }
  socket.close();
  return received.some((m) => m.includes("exfiltrated"));
}

describe("attachLiveSocket (#212)", () => {
  it("does not send a locked case's state to a socket with no unlock cookie", async () => {
    expect(await sawStateBroadcast("caseId=locked")).toBe(false);
  });

  it("does not send a locked case's state to an untrusted origin", async () => {
    expect(await sawStateBroadcast("caseId=locked", { origin: "https://evil.example" })).toBe(false);
  });

  it("does send the state to a properly unlocked dashboard socket", async () => {
    const meta = await store.getCaseMeta("locked");
    const token = signUnlockToken("locked", meta!.password!.salt, secret, 60_000, false);
    const saw = await sawStateBroadcast("caseId=locked", {
      cookie: `${unlockCookieName("locked")}=${token}`,
      origin: `http://127.0.0.1:${port}`,
    });
    expect(saw).toBe(true);
  });
});

// #1453: a dashboard that connects (or reconnects) during an import must draw the jobs chip at
// once, without an HTTP read it may not get a lane for. The gate sends the case's current job
// list on subscribe when the server hands it a `jobsFor` reader.
describe("attachLiveSocket sends the job list on subscribe (#1453)", () => {
  async function openAndCollect(port: number, caseId: string): Promise<string[]> {
    const socket = new WebSocket(`ws://127.0.0.1:${port}/ws?caseId=${caseId}`, {
      headers: { origin: `http://127.0.0.1:${port}` },
    });
    const received: string[] = [];
    socket.on("message", (data) => received.push(String(data)));
    await new Promise<void>((resolve) => {
      socket.on("open", () => resolve());
      socket.on("close", () => resolve());
      socket.on("error", () => resolve());
    });
    await new Promise((r) => setTimeout(r, 50));
    socket.close();
    return received;
  }

  it("pushes job_changed with the case's jobs right after the handshake", async () => {
    const localStore = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-wsjobs-")));
    await localStore.createCase({ caseId: "open", name: "n", investigator: "i", aiProvider: null });
    const localHub = new LiveHub();
    const localServer = createServer();
    const asked: string[] = [];
    attachLiveSocket(localServer, localHub, {
      store: localStore,
      secret: randomBytes(32),
      allowedOrigins: [],
      jobsFor: async (caseId) => {
        asked.push(caseId);
        return [{ id: "job_9", caseId, kind: "import", status: "running" }];
      },
    });
    await new Promise<void>((resolve) => localServer.listen(0, "127.0.0.1", resolve));
    const localPort = (localServer.address() as { port: number }).port;
    try {
      const received = await openAndCollect(localPort, "open");
      expect(asked).toEqual(["open"]);
      const pushes = received.map((m) => JSON.parse(m) as { type: string; jobs?: unknown[] });
      expect(pushes).toEqual([
        { type: "job_changed", jobs: [{ id: "job_9", caseId: "open", kind: "import", status: "running" }] },
      ]);
    } finally {
      await new Promise<void>((resolve) => localServer.close(() => resolve()));
    }
  });

  it("sends nothing extra when no jobs reader is wired, and survives a reader that throws", async () => {
    const localStore = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-wsjobs-")));
    await localStore.createCase({ caseId: "open", name: "n", investigator: "i", aiProvider: null });
    const localHub = new LiveHub();
    const localServer = createServer();
    attachLiveSocket(localServer, localHub, {
      store: localStore,
      secret: randomBytes(32),
      allowedOrigins: [],
      jobsFor: () => Promise.reject(new Error("ledger down")),
    });
    await new Promise<void>((resolve) => localServer.listen(0, "127.0.0.1", resolve));
    const localPort = (localServer.address() as { port: number }).port;
    try {
      expect(await openAndCollect(localPort, "open")).toEqual([]);
      expect(await openAndCollect(port, "locked")).toEqual([]); // the shared gate has no reader
    } finally {
      await new Promise<void>((resolve) => localServer.close(() => resolve()));
    }
  });
});
