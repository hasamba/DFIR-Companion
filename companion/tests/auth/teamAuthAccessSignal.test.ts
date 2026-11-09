import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";

// #2449: TeamAuth tells listeners (the live hub) when an access-ending auth action has committed.
// A listener failure must never fail the auth route that already committed.
describe("TeamAuth access-changed signal (#2449)", () => {
  let store: AuthStore;
  let auth: TeamAuth;

  beforeEach(async () => {
    store = new AuthStore(join(await mkdtemp(join(tmpdir(), "dfir-access-signal-")), "auth.sqlite"));
    auth = new TeamAuth({ store, cookieSecure: false, sessionTtlMs: 60_000 });
  });

  afterEach(() => store.close());

  it("calls every listener, even after one throws, and never throws out", () => {
    const first = vi.fn(() => {
      throw new Error("listener broke");
    });
    const second = vi.fn();
    auth.onAccessChanged(first);
    auth.onAccessChanged(second);
    expect(() => auth.notifyAccessChanged()).not.toThrow();
    expect(first).toHaveBeenCalledTimes(1);
    expect(second).toHaveBeenCalledTimes(1);
  });

  it("stops calling a listener once it unsubscribes", () => {
    const listener = vi.fn();
    const stop = auth.onAccessChanged(listener);
    stop();
    auth.notifyAccessChanged();
    expect(listener).not.toHaveBeenCalled();
  });
});
