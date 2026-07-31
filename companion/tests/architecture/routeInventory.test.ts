import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Express } from "express";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// A CONTRACT TEST FOR ROUTE REGISTRATION (#384's third acceptance criterion).
//
// server.ts is 4,275 lines and createApp() alone is ~2,350 of them. Decomposing it means moving
// registration calls and middleware between files, and the failure mode of that work is not a
// crash -- it is one `registerXRoutes(app, options)` silently not being called, or two middleware
// swapping places. Either produces a green build, a green type-check, and a 404 (or an unguarded
// request) that nobody notices until a user hits it.
//
// So this records the app's whole registered surface and fails on any change to it. It is a
// snapshot on purpose: a diff of `- POST /cases/:id/velociraptor/collect` in review is exactly the
// signal an extraction PR needs, and an intentional route change is one regenerate away.
//
// ORDER IS PRESERVED, NOT SORTED. Express matches layers in registration order, so `/cases/new`
// registered after `/cases/:id` is a different application from the same two in the other order.
// Sorting would hide precisely the reordering this is meant to catch.
//
// Regenerate after an intentional change, and show the diff in the PR:
//   UPDATE_ROUTE_INVENTORY=1 npx vitest run tests/architecture/routeInventory.test.ts

const INVENTORY = new URL("./route-inventory.json", import.meta.url);

interface Layer {
  route?: { path: unknown; methods: Record<string, boolean> };
  name?: string;
}

interface Inventory {
  routes: string[];
  middleware: string[];
}

function inventoryOf(app: Express): Inventory {
  const stack = (app as unknown as { _router: { stack: Layer[] } })._router.stack;
  const routes: string[] = [];
  const middleware: string[] = [];
  for (const layer of stack) {
    if (layer.route) {
      // A single layer can carry several verbs (app.route().get().post()); list each, in the order
      // Express stored them, so losing just the POST of a GET+POST pair still shows up.
      for (const method of Object.keys(layer.route.methods)) {
        routes.push(`${method.toUpperCase()} ${String(layer.route.path)}`);
      }
    } else {
      // Express names a layer after its handler function. Most of ours are arrow functions and come
      // out `<anonymous>`, so an individual entry says little -- but the SEQUENCE is the assertion:
      // moving caseIdGate above jsonParser, or dropping a guard entirely, changes this list.
      middleware.push(layer.name ?? "<unnamed>");
    }
  }
  return { routes, middleware };
}

describe("route registration contract", () => {
  const app = createApp(new CaseStore(mkdtempSync(join(tmpdir(), "dfir-route-inventory-"))));
  const actual = inventoryOf(app);

  if (process.env.UPDATE_ROUTE_INVENTORY) {
    writeFileSync(INVENTORY, `${JSON.stringify(actual, null, 2)}\n`);
  }

  const expected = JSON.parse(readFileSync(INVENTORY, "utf8")) as Inventory;

  it("registers exactly the recorded routes, in the recorded order", () => {
    // Reported as two assertions because the set difference is what a reviewer wants to read first;
    // the ordered comparison then catches a pure reordering that leaves the set identical.
    const missing = expected.routes.filter((r) => !actual.routes.includes(r));
    const added = actual.routes.filter((r) => !expected.routes.includes(r));
    expect({ missing, added }).toEqual({ missing: [], added: [] });
    expect(actual.routes).toEqual(expected.routes);
  });

  it("keeps the middleware chain the same length and in the same order", () => {
    expect(actual.middleware).toEqual(expected.middleware);
  });

  it("still registers a route surface of the expected magnitude", () => {
    // A guard against the inventory being regenerated from a half-built app: if an extraction drops
    // thirty route families and someone regenerates without reading the diff, both tests above pass
    // happily. This one does not.
    expect(actual.routes.length).toBeGreaterThan(400);
  });
});
