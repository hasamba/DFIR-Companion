import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Express } from "express";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// A CONTRACT TEST FOR ROUTE REGISTRATION (#384's third acceptance criterion).
//
// server.ts is 4,077 lines and createApp() alone is ~2,350 of them. Decomposing it means moving
// registration calls and middleware between files, and the failure mode of that work is not a
// crash -- it is one `registerXRoutes(app, options)` silently not being called, or a guard sliding
// below the routes it guards. Either produces a green build, a green type-check, and a 404 (or an
// unguarded request) that nobody notices until a user hits it.
//
// ONE INTERLEAVED SNAPSHOT, NOT TWO ARRAYS. An earlier version recorded routes and middleware
// separately. That preserved order *within* each group and lost it *between* them -- which is
// precisely the ordering that matters. The real stack is not "middleware, then routes": a
// `/cases/:id` middleware sits at index 90, between `/mcp/reconnect` and the `/cases/:id/import*`
// routes, so it covers the routes after it and not the 78 before it. With two arrays that guard
// could be moved below the AI routes and both arrays would be unchanged. One list makes the
// position of every layer relative to every other layer part of the contract.
//
// ORDER IS PRESERVED, NOT SORTED. Express matches layers in registration order, so `/cases/new`
// registered after `/cases/:id` is a different application from the same two in the other order.
//
// Regenerate after an intentional change, and show the diff in the PR:
//   UPDATE_ROUTE_INVENTORY=1 npx vitest run tests/architecture/routeInventory.test.ts

const INVENTORY = new URL("./route-inventory.json", import.meta.url);

interface Layer {
  route?: { path: unknown; methods: Record<string, boolean> };
  name?: string;
  regexp?: RegExp;
  handle?: { length?: number };
}

interface Inventory {
  stack: string[];
}

/**
 * One line per Express layer, in registration order.
 *
 *   ROUTE GET /cases/:id/findings
 *   USE   /^\/cases(?:\/([^/]+?))\/?(?=\/|$)/i  caseIdGate
 *
 * Middleware carry their mount regexp because that is what decides which routes they apply to, and
 * because most of ours are arrow functions that Express can only name `<anonymous>`. Arity is
 * recorded too: a 4-argument layer is an error handler, which must stay last, and a silent change
 * from 4 to 3 would turn error handling off without changing anything else visible.
 */
function inventoryOf(app: Express): Inventory {
  const layers = (app as unknown as { _router: { stack: Layer[] } })._router.stack;
  const stack: string[] = [];
  for (const layer of layers) {
    if (layer.route) {
      // One layer can carry several verbs (app.route().get().post()); list each in the order
      // Express stored them, so losing just the POST of a GET+POST pair still shows up.
      for (const method of Object.keys(layer.route.methods)) {
        stack.push(`ROUTE ${method.toUpperCase()} ${String(layer.route.path)}`);
      }
    } else {
      stack.push(`USE ${String(layer.regexp)} ${layer.name ?? "<unnamed>"}/${layer.handle?.length ?? "?"}`);
    }
  }
  return { stack };
}

describe("route registration contract", () => {
  const app = createApp(new CaseStore(mkdtempSync(join(tmpdir(), "dfir-route-inventory-"))));
  const actual = inventoryOf(app);

  if (process.env.UPDATE_ROUTE_INVENTORY) {
    writeFileSync(INVENTORY, `${JSON.stringify(actual, null, 2)}\n`);
  }

  const expected = JSON.parse(readFileSync(INVENTORY, "utf8")) as Inventory;

  it("registers exactly the recorded layers, in the recorded order", () => {
    // The set difference is what a reviewer wants to read first; the ordered comparison then
    // catches a pure reordering that leaves the set identical.
    const missing = expected.stack.filter((r) => !actual.stack.includes(r));
    const added = actual.stack.filter((r) => !expected.stack.includes(r));
    expect({ missing, added }).toEqual({ missing: [], added: [] });
    expect(actual.stack).toEqual(expected.stack);
  });

  it("keeps every middleware at the same position relative to the routes", () => {
    // Stated separately from the whole-stack comparison because this is the assertion with teeth:
    // a guard that slides past the routes it guards is a security change, and the failure message
    // should say so rather than being one line inside a 468-entry diff.
    const positions = (inv: Inventory) =>
      inv.stack.flatMap((entry, i) => (entry.startsWith("USE ") ? [`${i}: ${entry}`] : []));
    expect(positions(actual)).toEqual(positions(expected));
  });

  it("still registers a route surface of the expected magnitude", () => {
    // A guard against the inventory being regenerated from a half-built app: if an extraction drops
    // thirty route families and someone regenerates without reading the diff, the tests above pass
    // happily. The floor sits just under the current count rather than at a round number, so it
    // cannot quietly absorb a large loss -- 454 routes with a `> 400` floor tolerated 53 vanishing.
    const routes = actual.stack.filter((e) => e.startsWith("ROUTE "));
    expect(routes.length).toBeGreaterThanOrEqual(450);
  });

  it("keeps the error handler last", () => {
    // Express dispatches to a 4-arity layer only for errors, and only if it is registered after the
    // routes that throw. Moving it up silently disables the JSON error response for everything
    // below it.
    const last = actual.stack[actual.stack.length - 1];
    expect(last).toMatch(/^USE .*\/4$/);
  });
});
