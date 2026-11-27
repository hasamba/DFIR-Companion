import { describe, expect, it } from "vitest";
import type { VeloLabelsApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-velo-labels.js — the include/exclude label filter on a bundle run.
//
// IT OFFERS WHAT THE FLEET CARRIES, NOT WHAT THE ANALYST CAN SPELL. The filter used to be two free
// text boxes whose contents went straight into a hunt's include_labels/exclude_labels. A typo there
// does not fail — it silently matches no client, so the hunt launches, reports success, and
// collects from nobody. The picker can only offer labels that are really in the cached inventory,
// which is why the label set is DERIVED from that snapshot rather than typed.
const lbl = loadDashboardModule<VeloLabelsApi>("dashboard-velo-labels.js", [
  "dashboard-escape.js",
  "dashboard-velo-clients.js",
]);

// A stub checkbox, and a form whose querySelector walks a hand-built picker. The module never
// touches anything else on the element.
function fakeForm(inc: { value: string; checked: boolean }[], exc: { value: string; checked: boolean }[]) {
  const picker = (boxes: { value: string; checked: boolean }[]) => {
    const summary = { textContent: "", tagName: "SUMMARY" };
    return {
      querySelector: (sel: string) => (sel === "summary" ? summary : null),
      querySelectorAll: () => boxes,
      summary,
    };
  };
  const pickers: Record<string, ReturnType<typeof picker>> = {
    ".velo-lbl-inc": picker(inc),
    ".velo-lbl-exc": picker(exc),
  };
  return { querySelector: (sel: string) => pickers[sel] ?? null, pickers };
}

describe("veloFleetLabels", () => {
  it("is the deduped, sorted union of every cached client's labels", () => {
    expect(
      lbl.veloFleetLabels([
        { clientId: "C.a", labels: ["workstation", "dmz"] },
        { clientId: "C.b", labels: ["DMZ", "server"] },
        { clientId: "C.c" },
      ]),
    ).toEqual(["DMZ", "dmz", "server", "workstation"]);
  });

  // Velociraptor label matching is case-sensitive, so DMZ and dmz are two different filters and both
  // have to stay offerable. They sort next to each other so the analyst can see there are two.
  it("keeps labels that differ only by case, and sorts them together", () => {
    const out = lbl.veloFleetLabels([{ clientId: "C.a", labels: ["dmz", "DMZ", "alpha"] }]);
    expect(out).toEqual(["alpha", "DMZ", "dmz"]);
  });

  it("survives a fleet with no labels, no clients, or no inventory at all", () => {
    expect(lbl.veloFleetLabels([{ clientId: "C.a" }])).toEqual([]);
    expect(lbl.veloFleetLabels([])).toEqual([]);
    expect(lbl.veloFleetLabels(null)).toEqual([]);
  });
});

describe("veloLabelPickerHtml", () => {
  it("renders one checkbox per label, so several can be picked at once", () => {
    const html = lbl.veloLabelPickerHtml("inc", ["DC", "WORKSTATION"]);
    expect(html).toContain('class="velo-lbl velo-lbl-inc"');
    expect(html.match(/type="checkbox"/g)).toHaveLength(2);
    expect(html).toContain('value="DC"');
    expect(html).toContain('value="WORKSTATION"');
    expect(html).toContain("include labels: all clients");
  });

  it("escapes a label rather than letting it into the markup", () => {
    const html = lbl.veloLabelPickerHtml("exc", ['a"><img src=x onerror=alert(1)>']);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });

  // The empty state is the one that has to teach. A picker-only filter with an empty cache offers
  // nothing and gives no reason, which reads as a broken control rather than a stale snapshot.
  it("says how to fill an empty picker instead of rendering an empty dropdown", () => {
    const html = lbl.veloLabelPickerHtml("inc", []);
    expect(html).not.toContain('type="checkbox"');
    expect(html).toContain("Refresh client list");
  });
});

describe("veloLabelSummaryText", () => {
  it("names the one label picked, and counts more than one", () => {
    expect(lbl.veloLabelSummaryText("inc", [])).toBe("include labels: all clients");
    expect(lbl.veloLabelSummaryText("inc", ["DC"])).toBe("include labels: DC");
    expect(lbl.veloLabelSummaryText("inc", ["DC", "WORKSTATION"])).toBe("include labels: 2 picked");
    expect(lbl.veloLabelSummaryText("exc", [])).toBe("exclude labels: nothing");
    expect(lbl.veloLabelSummaryText("exc", ["DC"])).toBe("exclude labels: DC");
  });
});

describe("veloPickedLabels", () => {
  it("reads back every checked box, and only the checked ones", () => {
    const form = fakeForm(
      [
        { value: "DC", checked: true },
        { value: "WORKSTATION", checked: false },
        { value: "dmz", checked: true },
      ],
      [{ value: "SENSITIVE", checked: true }],
    );
    expect(lbl.veloPickedLabels(form, "inc")).toEqual(["DC", "dmz"]);
    expect(lbl.veloPickedLabels(form, "exc")).toEqual(["SENSITIVE"]);
  });

  // The empty state renders a note, not a dropdown — reading it must give an empty filter rather
  // than throw, or Run dies on a fleet whose inventory was never refreshed.
  it("is empty when the picker is the empty-state note", () => {
    expect(lbl.veloPickedLabels({ querySelector: () => null }, "inc")).toEqual([]);
    expect(lbl.veloPickedLabels(null, "inc")).toEqual([]);
  });
});

describe("veloWireLabelPickers", () => {
  it("keeps the collapsed summary in step with what is checked", () => {
    const form = fakeForm(
      [
        { value: "DC", checked: false },
        { value: "dmz", checked: false },
      ],
      [],
    );
    lbl.veloWireLabelPickers(form);
    const boxes = form.pickers[".velo-lbl-inc"].querySelectorAll() as {
      value: string;
      checked: boolean;
      onchange?: () => void;
    }[];
    boxes[0].checked = true;
    boxes[0].onchange?.();
    expect(form.pickers[".velo-lbl-inc"].summary.textContent).toBe("include labels: DC");
    boxes[1].checked = true;
    boxes[1].onchange?.();
    expect(form.pickers[".velo-lbl-inc"].summary.textContent).toBe("include labels: 2 picked");
  });

  it("does nothing on an empty-state picker", () => {
    expect(() => lbl.veloWireLabelPickers({ querySelector: () => null })).not.toThrow();
  });
});

// #2970 — the run form refreshes the client list when it opens and re-renders the pickers in place.
// What the analyst already ticked, and whether a picker is open, must survive that re-render.
describe("veloLabelPickerHtml with a selection (#2970)", () => {
  it("ticks the picked labels and names them in the summary", () => {
    const html = lbl.veloLabelPickerHtml("inc", ["DC", "WORKSTATION"], { picked: ["DC"] });
    expect(html).toMatch(/value="DC" checked/);
    expect(html).not.toMatch(/value="WORKSTATION" checked/);
    expect(html).toContain("include labels: DC");
  });

  // A ticked label that the fresh list no longer carries stays visible and ticked: dropping it would
  // silently widen or narrow the hunt the analyst already set up. A truncated list makes "missing"
  // an unreliable signal of "removed" anyway.
  it("keeps a picked label the fresh list no longer carries", () => {
    const html = lbl.veloLabelPickerHtml("exc", ["DC"], { picked: ["lab-gone"] });
    expect(html).toMatch(/value="lab-gone" checked/);
    expect(html).toContain('value="DC"');
  });

  it("escapes a picked label in the summary, not only in the checkbox", () => {
    const html = lbl.veloLabelPickerHtml("inc", [], { picked: ["<b>x</b>"] });
    expect(html).not.toContain("<b>x</b>");
    expect(html).toContain("include labels: &lt;b&gt;x&lt;/b&gt;");
  });

  it("stays open when it was open", () => {
    expect(lbl.veloLabelPickerHtml("inc", ["DC"], { open: true })).toMatch(
      /<details class="velo-lbl velo-lbl-inc"[^>]*\sopen/,
    );
    expect(lbl.veloLabelPickerHtml("inc", ["DC"])).not.toMatch(/<details[^>]*\sopen/);
  });

  // After a successful refresh, "use Refresh client list" is the wrong advice for a fleet with no labels.
  it("says no client carries a label after a successful refresh of an unlabelled fleet", () => {
    const html = lbl.veloLabelPickerHtml("inc", [], { refreshed: true });
    expect(html).not.toContain("Refresh client list");
    expect(html).toContain("no client carries a label");
  });
});

describe("veloLabelFreshnessText (#2970)", () => {
  it("says it is refreshing while the request runs", () => {
    expect(lbl.veloLabelFreshnessText({ pending: true })).toBe("refreshing labels…");
  });

  it("gives the time the list was read", () => {
    const at = new Date(2026, 10, 27, 9, 5).toISOString();
    expect(lbl.veloLabelFreshnessText({ ok: true, updatedAt: at })).toBe("labels as of 09:05");
  });

  it("adds the cut notice when the server truncated the list", () => {
    const at = new Date(2026, 10, 27, 9, 5).toISOString();
    expect(lbl.veloLabelFreshnessText({ ok: true, updatedAt: at, truncated: true })).toContain(
      "first 100,000 clients",
    );
  });

  it("says the list may be out of date, and why, when the refresh failed", () => {
    expect(lbl.veloLabelFreshnessText({ ok: false, error: "connection refused" })).toBe(
      "labels may be out of date — refresh failed (connection refused)",
    );
    expect(lbl.veloLabelFreshnessText({ ok: false })).toBe("labels may be out of date — refresh failed");
  });
});

describe("veloLabelPickerState (#2970)", () => {
  it("reads what is ticked and whether each picker is open", () => {
    const form = fakeForm([{ value: "DC", checked: true }], [{ value: "dmz", checked: false }]);
    (form.pickers[".velo-lbl-inc"] as unknown as { open: boolean }).open = true;
    expect(lbl.veloLabelPickerState(form)).toEqual({
      inc: { picked: ["DC"], open: true },
      exc: { picked: [], open: false },
    });
  });
});
