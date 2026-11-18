import { describe, expect, it } from "vitest";
import { falconConsoleOrigin } from "../../src/integrations/crowdstrike/falconConsole.js";

// #2685: "Open in Falcon" — the console host follows the SIEM client's cloud setting.

describe("falconConsoleOrigin", () => {
  it.each([
    [undefined, "https://falcon.crowdstrike.com"],
    ["us-1", "https://falcon.crowdstrike.com"],
    ["us-2", "https://falcon.us-2.crowdstrike.com"],
    ["eu-1", "https://falcon.eu-1.crowdstrike.com"],
    ["gov-us-1", "https://falcon.laggar.gcw.crowdstrike.com"],
    ["US2", "https://falcon.us-2.crowdstrike.com"],
  ])("cloud %s -> %s", (cloud, origin) => {
    expect(falconConsoleOrigin(cloud ? { cloud } : {})).toBe(origin);
  });

  it("gov-us-2 has no confirmed console address, so no link", () => {
    expect(falconConsoleOrigin({ cloud: "gov-us-2" })).toBeUndefined();
  });

  it("a base URL override on a known API host picks that host's console", () => {
    expect(falconConsoleOrigin({ cloud: "us-1", baseUrl: "https://api.eu-1.crowdstrike.com/" })).toBe(
      "https://falcon.eu-1.crowdstrike.com",
    );
  });

  it("an override on any other host leaves the console on the cloud default", () => {
    expect(falconConsoleOrigin({ cloud: "us-2", baseUrl: "https://proxy.example.invalid:8443" })).toBe(
      "https://falcon.us-2.crowdstrike.com",
    );
    expect(falconConsoleOrigin({ baseUrl: "not a url" })).toBe("https://falcon.crowdstrike.com");
  });
});
