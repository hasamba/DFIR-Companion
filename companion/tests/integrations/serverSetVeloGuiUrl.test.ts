import { describe, expect, it } from "vitest";
import { normalizeVeloGuiUrl } from "../../src/integrations/serverSets/veloGuiUrl.js";
import { parseServerSetInput } from "../../src/routes/serverSetBody.js";
import { buildVelociraptorClientFrom } from "../../src/composition/integrationClients.js";

// Deep links are `${guiUrl}/app/index.html?…`. A GUI served under a base path is entered with that
// path, and the address an analyst copies from the browser (…/app/index.html#/hunts) works too.
describe("Velociraptor GUI URL in a server set", () => {
  it.each([
    ["https://host/velociraptor", "https://host/velociraptor"],
    ["https://host/velociraptor/", "https://host/velociraptor"],
    ["https://host/velociraptor/app/index.html#/hunts", "https://host/velociraptor"],
    ["https://host/velociraptor/app/index.html?org_id=root#/hunts/H.1", "https://host/velociraptor"],
    ["https://host:8889/app/index.html", "https://host:8889"],
    ["https://host:8889", "https://host:8889"],
    ["https://host:8889/", "https://host:8889"],
    ["", ""],
  ])("%s → %s", (raw, want) => {
    expect(normalizeVeloGuiUrl(raw)).toBe(want);
  });

  it("is stored without the pasted /app/index.html part", () => {
    const parsed = parseServerSetInput({
      name: "Lab",
      velociraptor: {
        apiConfigPath: "/srv/api.config.yaml",
        guiUrl: "https://host/velociraptor/app/index.html#/hunts",
      },
    });
    expect(parsed.ok && parsed.value.velociraptor?.guiUrl).toBe("https://host/velociraptor");
  });

  it("hunt links keep the base path, also for a set saved before the change", () => {
    const client = buildVelociraptorClientFrom(
      {
        apiConfigPath: "/srv/api.config.yaml",
        guiUrl: "https://host/velociraptor/app/index.html#/hunts",
      },
      {},
    );
    expect(client?.huntGuiUrlFor("H.1")).toBe(
      "https://host/velociraptor/app/index.html?org_id=root#/hunts/H.1",
    );
    const plain = buildVelociraptorClientFrom(
      { apiConfigPath: "/srv/api.config.yaml", guiUrl: "https://host:8889" },
      {},
    );
    expect(plain?.huntGuiUrlFor("H.1")).toBe("https://host:8889/app/index.html?org_id=root#/hunts/H.1");
  });
});
