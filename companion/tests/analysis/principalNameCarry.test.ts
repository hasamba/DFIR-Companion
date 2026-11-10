// The settle-time caller-name carry (#2490): an Azure activity row whose caller is a GUID shows
// " (<name>)" after the id when the case knows exactly one name for it, and loses it again when a
// conflicting name arrives or the ledger forgets the name. Only what the carry wrote is removed.
import { describe, it, expect } from "vitest";
import { nameCallers, principalNameCarrier } from "../../src/analysis/principalNameCarry.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { PrincipalNameRecord } from "../../src/analysis/principalNames.js";

const SP = "3f2a1b4c-1111-2222-3333-444455556666";

const row = (description: string, extra: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: "az1",
  timestamp: "2026-01-01T00:00:00.000Z",
  description,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: ["Azure Activity"],
  ...extra,
});

const ledger = (...records: PrincipalNameRecord[]) => ({ principalNames: records });
const named = ledger({ id: SP, names: ["backup-automation"] });

describe("principalNameCarrier", () => {
  it("inserts the name right after the id and records what it wrote", () => {
    const e = row(
      `Azure Microsoft.Compute/virtualMachines/write by ${SP} from 10.0.0.1 on virtualMachines/vm1`,
    );
    const out = principalNameCarrier(named)(e);
    expect(out.description).toBe(
      `Azure Microsoft.Compute/virtualMachines/write by ${SP} (backup-automation) from 10.0.0.1 on virtualMachines/vm1`,
    );
    expect(out.callerName).toBe("backup-automation");
    expect(out.canonical).toBe(e.canonical);
  });

  it("matches an upper-case caller, a ':' boundary and an id at the end", () => {
    const carry = principalNameCarrier(named);
    expect(carry(row(`Azure op/write by ${SP.toUpperCase()}: Owner → x`)).description).toBe(
      `Azure op/write by ${SP.toUpperCase()} (backup-automation): Owner → x`,
    );
    expect(carry(row(`Azure op/write by ${SP}`)).description).toBe(
      `Azure op/write by ${SP} (backup-automation)`,
    );
  });

  it("is idempotent", () => {
    const carry = principalNameCarrier(named);
    const once = carry(row(`Azure op/write by ${SP} from 10.0.0.1`));
    expect(carry(once)).toBe(once);
  });

  it("removes its own suffix when the id turns into a conflict or is forgotten", () => {
    const once = principalNameCarrier(named)(row(`Azure op/write by ${SP} from 10.0.0.1`));
    const conflict = principalNameCarrier(ledger({ id: SP, names: ["backup-automation", "other"] }))(once);
    expect(conflict.description).toBe(`Azure op/write by ${SP} from 10.0.0.1`);
    expect(conflict.callerName).toBeUndefined();
    expect(principalNameCarrier({})(once).description).toBe(`Azure op/write by ${SP} from 10.0.0.1`);
  });

  it("swaps nothing silently: a renamed ledger replaces only the suffix it wrote", () => {
    const once = principalNameCarrier(named)(row(`Azure op/write by ${SP}`));
    const next = principalNameCarrier(ledger({ id: SP, names: ["renamed"] }))(once);
    expect(next.description).toBe(`Azure op/write by ${SP} (renamed)`);
  });

  it("never removes record text it did not write, and never doubles a suffix the record carries", () => {
    // A caller field that itself reads "<guid> (backup-automation)" is the record's text.
    const forged = row(`Azure op/write by ${SP} (backup-automation) from 10.0.0.1`);
    expect(principalNameCarrier(named)(forged)).toBe(forged);
    expect(principalNameCarrier({})(forged)).toBe(forged);
  });

  it("leaves a caller that only starts with a GUID, a non-Azure row and an Azure summary alone", () => {
    const carry = principalNameCarrier(named);
    const glued = row(`Azure op/write by ${SP}x from 10.0.0.1`);
    expect(carry(glued)).toBe(glued);
    const other = row(`Azure op/write by ${SP}`, { sources: ["Entra ID"] });
    expect(carry(other)).toBe(other);
    const summary = row(`Azure compute lifecycle: vm1 [recorded write by ${SP} (record:0)]`);
    expect(carry(summary)).toBe(summary);
  });

  it("is the identity on every row when the case has no ledger and no row carries a name", () => {
    const e = row(`Azure op/write by ${SP}`);
    expect(principalNameCarrier({})(e)).toBe(e);
  });
});

describe("nameCallers", () => {
  it("rewrites the whole forensic timeline and counts the rows it changed", () => {
    const state = {
      ...emptyState("c1"),
      ...named,
      forensicTimeline: [
        row(`Azure op/write by ${SP}`),
        row("Azure op/read by someone@x.test", { id: "az2" }),
      ],
    };
    const { state: out, changed } = nameCallers(state);
    expect(changed).toBe(1);
    expect(out.forensicTimeline[0].description).toBe(`Azure op/write by ${SP} (backup-automation)`);
    expect(out.forensicTimeline[1]).toBe(state.forensicTimeline[1]);
    expect(nameCallers(out).state).toBe(out);
  });
});

describe("principalNameCarrier with a stale mark", () => {
  it("names a row whose text was restated without the suffix, dropping the stale mark", () => {
    const restated = row(`Azure op/write by ${SP} from 10.0.0.1`, { callerName: "old" });
    const out = principalNameCarrier(named)(restated);
    expect(out.description).toBe(`Azure op/write by ${SP} (backup-automation) from 10.0.0.1`);
    expect(out.callerName).toBe("backup-automation");
    const cleared = principalNameCarrier({})(restated);
    expect(cleared.description).toBe(restated.description);
    expect(cleared.callerName).toBeUndefined();
  });
});

// Synthesis saves rows from its pre-import snapshot (#453); an import that named a row, or took a
// name away, while the model was thinking must survive that save.
describe("mergeConcurrentAdditions — follows the ledger an import wrote during synthesis (#2490)", () => {
  it("keeps a name learned mid-synthesis", async () => {
    const { mergeConcurrentAdditions } = await import("../../src/analysis/ai/synthesisPersist.js");
    const stale = row(`Azure op/write by ${SP}`);
    const loaded = { ...emptyState("c1"), forensicTimeline: [stale] };
    const next = { ...loaded, lastSummary: "summary" };
    const latest = nameCallers({ ...loaded, ...named }).state;
    const merged = mergeConcurrentAdditions(loaded, next, latest);
    expect(merged.principalNames).toEqual(named.principalNames);
    expect(merged.forensicTimeline[0].description).toBe(`Azure op/write by ${SP} (backup-automation)`);
    expect(merged.lastSummary).toBe("summary");
  });

  it("keeps a name a conflict took away mid-synthesis", async () => {
    const { mergeConcurrentAdditions } = await import("../../src/analysis/ai/synthesisPersist.js");
    const loaded = nameCallers({
      ...emptyState("c1"),
      ...named,
      forensicTimeline: [row(`Azure op/write by ${SP}`)],
    }).state;
    expect(loaded.forensicTimeline[0].callerName).toBe("backup-automation");
    const conflict = ledger({ id: SP, names: ["backup-automation", "other"] });
    const latest = nameCallers({ ...loaded, ...conflict }).state;
    const merged = mergeConcurrentAdditions(loaded, { ...loaded }, latest);
    expect(merged.forensicTimeline[0].description).toBe(`Azure op/write by ${SP}`);
  });
});

// Codex review: Undo while the model runs removes the name; the synthesis save must not bring it back.
describe("mergeConcurrentAdditions — an Undo during synthesis stays undone (#2490)", () => {
  it("a name the snapshot had and Undo took away is not restored, nor its suffix", async () => {
    const { mergeConcurrentAdditions } = await import("../../src/analysis/ai/synthesisPersist.js");
    const loaded = nameCallers({
      ...emptyState("c1"),
      ...named,
      forensicTimeline: [row(`Azure op/write by ${SP}`)],
    }).state;
    const latest = nameCallers({ ...loaded, principalNames: undefined }).state;
    expect(latest.forensicTimeline[0].description).toBe(`Azure op/write by ${SP}`);
    const merged = mergeConcurrentAdditions(loaded, { ...loaded, lastSummary: "s" }, latest);
    expect(merged.principalNames).toBeUndefined();
    expect(merged.forensicTimeline[0].description).toBe(`Azure op/write by ${SP}`);
  });

  it("a conflict Undo took away is not restored either", async () => {
    const { mergeConcurrentAdditions } = await import("../../src/analysis/ai/synthesisPersist.js");
    const conflict = ledger({ id: SP, names: ["backup-automation", "other"] });
    const loaded = { ...emptyState("c1"), ...conflict, forensicTimeline: [row(`Azure op/write by ${SP}`)] };
    const latest = nameCallers({ ...loaded, ...named }).state;
    const merged = mergeConcurrentAdditions(loaded, { ...loaded }, latest);
    expect(merged.principalNames).toEqual(named.principalNames);
    expect(merged.forensicTimeline[0].description).toBe(`Azure op/write by ${SP} (backup-automation)`);
  });
});
