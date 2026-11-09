import { describe, it, expect } from "vitest";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { azureRoleName, AZURE_BUILT_IN_ROLES } from "../../src/analysis/azureBuiltInRoles.js";
import { decodeAzureRoleAssignment, shortAzureScope } from "../../src/analysis/azureRoleAssignment.js";

const SUB = "11111111-2222-4333-8444-555555555555";
const ASSIGN = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const PRINCIPAL = "99999999-8888-4777-8666-555555555555";
const UAA = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";
const OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const OP = "Microsoft.Authorization/roleAssignments/write";

function body(role = UAA, principal = PRINCIPAL, extra: object = {}): string {
  return JSON.stringify({
    id: ASSIGN,
    properties: {
      principalId: principal,
      roleDefinitionId: `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/${role}`,
      scope: `/subscriptions/${SUB}`,
      ...extra,
    },
  });
}

function rec(over: object = {}, props: object = {}, op = OP): object {
  return {
    eventTimestamp: "2026-11-01T10:00:00Z",
    eventName: { value: "BeginRequest" },
    operationName: { value: op },
    status: { value: "Started" },
    caller: "admin@example.com",
    resourceId: `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleAssignments/${ASSIGN}`,
    httpRequest: { clientIpAddress: "203.0.113.249", method: "PUT" },
    properties: { requestbody: body(), entity: `/subscriptions/${SUB}`, ...props },
    ...over,
  };
}

const parse = (records: object[], aggregate = true) =>
  parseCloudActivity(JSON.stringify(records), { aggregate }).events;

describe("Azure built-in role table", () => {
  it("names the privileged roles by their Microsoft Learn guid", () => {
    expect(azureRoleName(OWNER)).toBe("Owner");
    expect(azureRoleName(UAA.toUpperCase())).toBe("User Access Administrator");
    expect(azureRoleName("f58310d9-a9f6-439a-9e8d-f62e7b41a168")).toBe(
      "Role Based Access Control Administrator",
    );
    expect(azureRoleName("00000000-0000-0000-0000-000000000000")).toBeUndefined();
    expect(Object.keys(AZURE_BUILT_IN_ROLES).length).toBeGreaterThanOrEqual(22);
  });
});

describe("shortAzureScope", () => {
  it("names the scope kind and its id", () => {
    expect(shortAzureScope(`/subscriptions/${SUB}`)).toBe(`subscription ${SUB}`);
    expect(shortAzureScope(`/subscriptions/${SUB}/resourceGroups/rg-prod`)).toBe("resource group rg-prod");
    expect(
      shortAzureScope(`/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1`),
    ).toBe("resource vaults/kv1");
    expect(shortAzureScope("/providers/Microsoft.Management/managementGroups/mg1")).toBe(
      "management group mg1",
    );
    expect(shortAzureScope("/")).toBe("tenant root /");
  });
});

describe("Azure role assignment rows", () => {
  it("a BeginRequest with a body names the role, the principal and the scope", () => {
    const [e] = parse([rec()]);
    expect(e.description).toBe(
      `Azure ${OP} by admin@example.com from 203.0.113.249: User Access Administrator → ${PRINCIPAL} at subscription ${SUB}`,
    );
    expect(e.message).toBe(
      [
        `Role: User Access Administrator (${UAA})`,
        `Assigned to: ${PRINCIPAL}`,
        `Scope: /subscriptions/${SUB}`,
        `Assignment id: ${ASSIGN}`,
      ].join("\n"),
    );
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1098.003");
  });

  it("carries principal type and condition when the body has them", () => {
    const [e] = parse([
      rec(
        {},
        {
          requestbody: body(UAA, PRINCIPAL, {
            principalType: "ServicePrincipal",
            condition: "@Resource[x] == 'y'",
          }),
        },
      ),
    ]);
    expect(e.message).toContain(`Assigned to: ${PRINCIPAL} (ServicePrincipal)`);
    expect(e.message).toContain("Condition: @Resource(x) == 'y'");
  });

  it("an EndRequest with no body still gets a message with status and assignment id", () => {
    const [e] = parse([
      rec(
        { eventName: { value: "EndRequest" }, status: { value: "Succeeded" } },
        { requestbody: undefined, statusCode: "Created" },
      ),
    ]);
    expect(e.description).toBe(
      `Azure ${OP} by admin@example.com from 203.0.113.249 on roleAssignments/${ASSIGN}`,
    );
    expect(e.message).toContain(`Assignment id: ${ASSIGN}`);
    expect(e.message).toContain("HTTP status: Created");
    expect(e.message).toContain("matching Begin request row (same correlationId)");
  });

  it("an unknown role guid is a custom or unlisted role", () => {
    const g = "11111111-2222-3333-4444-555555555555";
    const [e] = parse([rec({}, { requestbody: body(g) })]);
    expect(e.description).toContain(`custom or unlisted role ${g} → ${PRINCIPAL}`);
    expect(e.message).toContain(`Role: custom or unlisted role ${g}`);
  });

  it("a delete says removes", () => {
    const [e] = parse([
      rec(
        { httpRequest: { clientIpAddress: "203.0.113.249", method: "DELETE" } },
        {},
        "Microsoft.Authorization/roleAssignments/delete",
      ),
    ]);
    expect(e.description).toContain(
      `: removes User Access Administrator from ${PRINCIPAL} at subscription ${SUB}`,
    );
    expect(e.message).toContain(`Removed from: ${PRINCIPAL}`);
  });

  it("a malformed or oversized body never throws and keeps the old title", () => {
    for (const bad of ["{not json", `{"properties":"${"A".repeat(70_000)}"}`, "[1,2,3]", "null"]) {
      const [e] = parse([rec({}, { requestbody: bad })]);
      expect(e.description).toBe(
        `Azure ${OP} by admin@example.com from 203.0.113.249 on roleAssignments/${ASSIGN}`,
      );
      expect(e.message ?? "").toContain(`Assignment id: ${ASSIGN}`);
    }
  });

  it("two grants by one caller stay two aggregated rows", () => {
    const events = parse([
      rec(),
      rec({}, { requestbody: body(OWNER, "99999999-8888-7777-6666-555555555555") }),
    ]);
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.description).join("\n")).toContain("Owner → 99999999-");
  });

  it("two bodiless End rows for two different assignments stay two rows", () => {
    const end = (id: string) =>
      rec(
        {
          eventName: { value: "EndRequest" },
          status: { value: "Succeeded" },
          resourceId: `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleAssignments/${id}`,
        },
        { requestbody: undefined, statusCode: "Created" },
      );
    expect(parse([end(ASSIGN), end("c0ffee00-0000-4000-8000-000000000001")])).toHaveLength(2);
  });

  it("a failed grant keeps the [status] suffix after the grant phrase and stays High", () => {
    const [e] = parse([rec({ status: { value: "Failed" } })]);
    expect(e.description.endsWith(`at subscription ${SUB} [Failed]`)).toBe(true);
    expect(e.severity).toBe("High");
  });

  it("the same grant twice still aggregates into one row", () => {
    expect(parse([rec(), rec()])).toHaveLength(1);
  });

  it("other operations are unchanged", () => {
    const [e] = parse([rec({}, {}, "Microsoft.Authorization/roleDefinitions/write")]);
    expect(e.description).toContain(" on roleAssignments/");
    expect(e.message).toBeUndefined();
  });

  it("neutralises adversary text in the body", () => {
    const d = decodeAzureRoleAssignment(
      OP,
      rec({}, { requestbody: body(UAA, `${PRINCIPAL}\n[fake] ‮`) }) as never,
    );
    expect(d?.message).not.toContain("[fake]");
    expect(d?.message).not.toContain("‮");
  });
});
