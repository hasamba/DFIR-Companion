import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import WebSocket, { type WebSocketServer } from "ws";
import { CaseStore } from "../../src/storage/caseStore.js";
import { LiveHub } from "../../src/live/hub.js";
import { attachLiveSocket } from "../../src/live/wsGate.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import type { AuthIdentity } from "../../src/auth/types.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

// #2449: in team mode a live dashboard socket was authorized only when it opened. Disabling the
// user, signing them out, removing their case role or demoting them left the socket streaming the
// full case state for as long as the tab stayed open. Each of those now closes it.

const PASSWORD = "a different sufficiently long password";

interface Client {
  socket: WebSocket;
  received: string[];
  closed: Promise<void>;
  isClosed: () => boolean;
}

let cases: CaseStore;
let authStore: AuthStore;
let teamAuth: TeamAuth;
let hub: LiveHub;
let server: Server;
let wss: WebSocketServer;
let port: number;
let admin: AuthIdentity;
let member: AuthIdentity;
const clients: Client[] = [];

async function startServer(withTeamAuth: boolean): Promise<void> {
  hub = new LiveHub();
  server = createServer();
  wss = attachLiveSocket(server, hub, {
    store: cases,
    secret: randomBytes(32),
    allowedOrigins: [],
    ...(withTeamAuth ? { teamAuth } : {}),
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as { port: number }).port;
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-ws-revoke-"));
  cases = new CaseStore(join(root, "cases"));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  authStore = new AuthStore(join(root, "auth.sqlite"));
  admin = await authStore.bootstrapLocalAdministrator({
    username: "admin",
    password: "correct horse battery staple",
    displayName: "Admin",
  });
  member = await authStore.createLocalIdentity(
    { username: "analyst", password: PASSWORD, displayName: "Analyst" },
    admin,
  );
  authStore.setCaseRole("c1", member.id, "reader", admin);
  teamAuth = new TeamAuth({ store: authStore, cookieSecure: false, sessionTtlMs: 60_000 });
  await startServer(true);
});

afterEach(async () => {
  for (const client of clients.splice(0)) client.socket.terminate();
  wss.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  authStore.close();
});

function sessionCookie(
  identity: AuthIdentity,
  ttlMs = 60_000,
): { cookie: string; token: string; id: string } {
  const created = authStore.createSession(identity, ttlMs);
  return { cookie: `dfir_session=${created.token}`, token: created.token, id: created.record.id };
}

/** Open a socket; resolves "open" or "refused". */
async function connect(cookie?: string): Promise<{ client: Client; outcome: "open" | "refused" }> {
  const socket = new WebSocket(`ws://127.0.0.1:${port}/ws?caseId=c1`, {
    headers: cookie ? { cookie } : {},
  });
  const received: string[] = [];
  let closedFlag = false;
  socket.on("message", (data) => received.push(String(data)));
  const closed = new Promise<void>((resolve) => {
    socket.on("close", () => {
      closedFlag = true;
      resolve();
    });
  });
  const outcome = await new Promise<"open" | "refused">((resolve) => {
    socket.on("open", () => resolve("open"));
    socket.on("error", () => resolve("refused"));
    socket.on("close", () => resolve("refused"));
  });
  const client = { socket, received, closed, isClosed: () => closedFlag };
  clients.push(client);
  return { client, outcome };
}

async function openClient(cookie?: string): Promise<Client> {
  const { client, outcome } = await connect(cookie);
  expect(outcome).toBe("open");
  return client;
}

async function closesSoon(client: Client): Promise<boolean> {
  const timeout = new Promise<false>((resolve) => setTimeout(() => resolve(false), 2_000));
  return Promise.race([client.closed.then(() => true as const), timeout]);
}

async function receivesBroadcast(client: Client): Promise<boolean> {
  const marker = `marker-${randomBytes(4).toString("hex")}`;
  hub.broadcast({ caseId: "c1", findings: [{ secret: marker }] } as unknown as InvestigationState);
  await new Promise((r) => setTimeout(r, 100));
  return client.received.some((m) => m.includes(marker));
}

describe("live sockets lose access with their session (#2449)", () => {
  it("closes a disabled user's socket, and refuses the reconnect", async () => {
    const { cookie } = sessionCookie(member);
    const client = await openClient(cookie);
    await authStore.updateIdentity(member.id, { disabled: true }, admin);
    teamAuth.notifyAccessChanged();
    expect(await closesSoon(client)).toBe(true);
    expect(await receivesBroadcast(client)).toBe(false);
    expect((await connect(cookie)).outcome).toBe("refused");
  });

  it("closes a signed-out session's socket", async () => {
    const { cookie, token } = sessionCookie(member);
    const client = await openClient(cookie);
    authStore.deleteSessionByToken(token);
    teamAuth.notifyAccessChanged();
    expect(await closesSoon(client)).toBe(true);
  });

  it("closes the socket of a user whose case role is removed", async () => {
    const { cookie } = sessionCookie(member);
    const client = await openClient(cookie);
    authStore.removeCaseRole("c1", member.id, admin);
    teamAuth.notifyAccessChanged();
    expect(await closesSoon(client)).toBe(true);
  });

  it("closes the other sessions' sockets on sign-out-others and keeps the caller's own", async () => {
    const kept = sessionCookie(member);
    const other = sessionCookie(member);
    const keptClient = await openClient(kept.cookie);
    const otherClient = await openClient(other.cookie);
    authStore.deleteOtherSessions(member.id, kept.id);
    teamAuth.notifyAccessChanged();
    expect(await closesSoon(otherClient)).toBe(true);
    expect(keptClient.isClosed()).toBe(false);
    expect(await receivesBroadcast(keptClient)).toBe(true);
  });

  it("closes a demoted administrator's socket when they hold no case role", async () => {
    const second = await authStore.createLocalIdentity(
      { username: "admin2", password: PASSWORD, displayName: "Admin 2", globalRole: "administrator" },
      admin,
    );
    const { cookie } = sessionCookie(second);
    const client = await openClient(cookie);
    await authStore.updateIdentity(second.id, { globalRole: "member" }, admin);
    teamAuth.notifyAccessChanged();
    expect(await closesSoon(client)).toBe(true);
  });

  it("keeps a socket open when the role change still grants read", async () => {
    const { cookie } = sessionCookie(member);
    const client = await openClient(cookie);
    authStore.setCaseRole("c1", member.id, "investigator", admin);
    teamAuth.notifyAccessChanged();
    expect(await receivesBroadcast(client)).toBe(true);
    expect(client.isClosed()).toBe(false);
  });

  it("closes an expired session's socket on the next re-check (the reaper tick)", async () => {
    const { cookie } = sessionCookie(member, 800);
    const client = await openClient(cookie);
    await new Promise((r) => setTimeout(r, 900));
    expect(hub.revalidate()).toBe(1);
    expect(await closesSoon(client)).toBe(true);
  });

  it("stops listening for access changes once the socket server closes", async () => {
    const revalidate = vi.spyOn(hub, "revalidate");
    teamAuth.notifyAccessChanged();
    expect(revalidate).toHaveBeenCalledTimes(1);
    // ws emits the server's "close" on the next tick.
    await new Promise<void>((resolve) => wss.close(() => resolve()));
    teamAuth.notifyAccessChanged();
    expect(revalidate).toHaveBeenCalledTimes(1);
  });
});

describe("single-user mode never closes a live socket on a re-check (#2449)", () => {
  it("keeps the socket open and streaming", async () => {
    wss.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await startServer(false);
    const client = await openClient();
    expect(hub.revalidate()).toBe(0);
    teamAuth.notifyAccessChanged();
    expect(await receivesBroadcast(client)).toBe(true);
    expect(client.isClosed()).toBe(false);
  });
});
