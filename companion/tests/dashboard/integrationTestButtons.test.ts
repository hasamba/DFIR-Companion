import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { dashboardClientSource } from "../helpers/dashboardModule.js";

// Settings used to carry exactly two connection tests: Presidio and DFIR-IRIS. Every other
// integration was configure-and-hope - the analyst saved a URL and a token, closed the modal, and
// found out whether the credentials were right the next time a push failed mid-investigation. This
// suite pins the control for each one.
//
// The dashboard has no DOM harness here (see dashboardTicketPush.test.ts), so what is asserted is
// the wiring that makes each button real rather than decorative: the markup exists, a handler is
// registered for it, and the handler posts to the route that actually probes that integration.
//
// `pane` is the settings tab the group is on. MISP is the odd one: its keys feed the IOC
// enrichment provider as well as the push, so its group sits under Enrichment rather than
// Integrations - and a test scoped to the wrong pane would pass on markup the analyst never
// reaches from there.
const INTEGRATIONS = [
  {
    id: "timesketch",
    pane: "integrations",
    button: "timesketchReconnectBtn",
    msg: "timesketchReconnectMsg",
    url: "/timesketch/reconnect",
  },
  {
    id: "notion",
    pane: "integrations",
    button: "notionReconnectBtn",
    msg: "notionReconnectMsg",
    url: "/notion/reconnect",
  },
  {
    id: "clickup",
    pane: "integrations",
    button: "clickupReconnectBtn",
    msg: "clickupReconnectMsg",
    url: "/clickup/reconnect",
  },
  {
    id: "velociraptor",
    pane: "integrations",
    button: "veloSettingsReconnectBtn",
    msg: "veloSettingsReconnectMsg",
    url: "/velociraptor/reconnect",
  },
  { id: "jira", pane: "integrations", button: "jiraTestBtn", msg: "jiraTestMsg", url: "/jira/test" },
  {
    id: "servicenow",
    pane: "integrations",
    button: "snowTestBtn",
    msg: "snowTestMsg",
    url: "/servicenow/test",
  },
  {
    id: "misp",
    pane: "enrichment",
    button: "mispReconnectBtn",
    msg: "mispReconnectMsg",
    url: "/misp/reconnect",
  },
] as const;

// Where each settings pane starts and ends in the markup, so "is the button on the right tab?" is
// a real question rather than a substring search over the whole file.
const PANE_BOUNDS: Record<string, [string, string]> = {
  integrations: [
    '<div class="stab-pane" id="stab-integrations">',
    '<div class="stab-pane" id="stab-velociraptor">',
  ],
  enrichment: ['<div class="stab-pane" id="stab-enrichment">', '<div class="stab-pane" id="stab-exposure">'],
};

let html: string;
let client: string;

beforeAll(() => {
  html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  client = dashboardClientSource();
});

describe("Settings connection tests", () => {
  it.each(INTEGRATIONS)("gives $id a test button on the $pane tab", ({ pane, button, msg }) => {
    const [start, end] = PANE_BOUNDS[pane];
    const markup = html.slice(html.indexOf(start), html.indexOf(end));
    expect(markup).toContain(`id="${button}"`);
    expect(markup).toContain(`id="${msg}"`);
  });

  it.each(INTEGRATIONS)("wires $id to the route that probes it", ({ button, url }) => {
    expect(client).toContain(button);
    expect(client).toContain(`"${url}"`);
  });

  it("keeps the two tests that already existed", () => {
    expect(html).toContain('id="presidioTestBtn"');
    expect(html).toContain('id="irisReconnectBtn"');
  });

  it("saves pending edits before testing the integrations whose config the dashboard owns", () => {
    // The failure this prevents: type a corrected token, hit Test, and the server probes the OLD
    // value still on disk - a green result for a config that was never saved. Jira/ServiceNow are
    // excluded because their fields are read-only here (.env + restart), so there is nothing to save.
    const wiring = client.slice(client.indexOf("INTEGRATION_TESTS"));
    expect(wiring).toMatch(/save\s*:\s*true/);
  });
});
