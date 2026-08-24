import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { dashboardClientSource } from "../helpers/dashboardModule.js";

// Settings -> Integrations used to carry exactly two connection tests: Presidio and DFIR-IRIS.
// Every other integration on that tab was configure-and-hope - the analyst saved a URL and a
// token, closed the modal, and found out whether the credentials were right the next time a push
// failed mid-investigation. This suite pins the control for each one.
//
// The dashboard has no DOM harness here (see dashboardTicketPush.test.ts), so what is asserted is
// the wiring that makes each button real rather than decorative: the markup exists, a handler is
// registered for it, and the handler posts to the route that actually probes that integration.

const INTEGRATIONS = [
  {
    id: "timesketch",
    button: "timesketchReconnectBtn",
    msg: "timesketchReconnectMsg",
    url: "/timesketch/reconnect",
  },
  { id: "notion", button: "notionReconnectBtn", msg: "notionReconnectMsg", url: "/notion/reconnect" },
  { id: "clickup", button: "clickupReconnectBtn", msg: "clickupReconnectMsg", url: "/clickup/reconnect" },
  {
    id: "velociraptor",
    button: "veloSettingsReconnectBtn",
    msg: "veloSettingsReconnectMsg",
    url: "/velociraptor/reconnect",
  },
  { id: "jira", button: "jiraTestBtn", msg: "jiraTestMsg", url: "/jira/test" },
  { id: "servicenow", button: "snowTestBtn", msg: "snowTestMsg", url: "/servicenow/test" },
] as const;

let html: string;
let client: string;

beforeAll(() => {
  html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  client = dashboardClientSource();
});

describe("Settings -> Integrations connection tests", () => {
  it.each(INTEGRATIONS)("gives $id a test button with a result line", ({ button, msg }) => {
    const pane = html.slice(
      html.indexOf('<div class="stab-pane" id="stab-integrations">'),
      html.indexOf('<div class="stab-pane" id="stab-velociraptor">'),
    );
    expect(pane).toContain(`id="${button}"`);
    expect(pane).toContain(`id="${msg}"`);
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
