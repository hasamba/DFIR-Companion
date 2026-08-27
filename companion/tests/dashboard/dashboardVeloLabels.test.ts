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
const lbl = loadDashboardModule<VeloLabelsApi>("dashboard-velo-labels.js", ["dashboard-escape.js"]);

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
    expect(html).toContain("include: all clients");
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
    expect(lbl.veloLabelSummaryText("inc", [])).toBe("include: all clients");
    expect(lbl.veloLabelSummaryText("inc", ["DC"])).toBe("include: DC");
    expect(lbl.veloLabelSummaryText("inc", ["DC", "WORKSTATION"])).toBe("include: 2 labels");
    expect(lbl.veloLabelSummaryText("exc", [])).toBe("exclude: nothing");
    expect(lbl.veloLabelSummaryText("exc", ["DC"])).toBe("exclude: DC");
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
    expect(form.pickers[".velo-lbl-inc"].summary.textContent).toBe("include: DC");
    boxes[1].checked = true;
    boxes[1].onchange?.();
    expect(form.pickers[".velo-lbl-inc"].summary.textContent).toBe("include: 2 labels");
  });

  it("does nothing on an empty-state picker", () => {
    expect(() => lbl.veloWireLabelPickers({ querySelector: () => null })).not.toThrow();
  });
});
