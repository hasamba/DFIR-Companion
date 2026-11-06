import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  GCP_ROLES,
  MICROSOFT_AZURE_ROLE,
  MICROSOFT_GRAPH_PERMISSIONS,
  MINIMUM_POLICIES,
} from "../../../src/integrations/cloudCheck/minimumPolicies.js";

// #2309: the minimum policies the add form shows are the ones the manual publishes.

const docs = readFileSync(
  new URL("../../../../mkdocs-docs/reference/cloud-collection.md", import.meta.url),
  "utf8",
).replace(/\r\n/g, "\n"); // Windows CI checks the docs out with CRLF
const nav = readFileSync(new URL("../../../../mkdocs.yml", import.meta.url), "utf8").replace(/\r\n/g, "\n");

describe("mkdocs-docs/reference/cloud-collection.md", () => {
  it("is in the manual's navigation", () => {
    expect(nav).toContain("reference/cloud-collection.md");
  });

  it("publishes the AWS policy document exactly as the add form shows it", () => {
    expect(docs).toContain(MINIMUM_POLICIES.aws.grant);
  });

  it("#2363: the AWS policy grants ec2:DescribeRegions and the manual explains the region picker", () => {
    expect(MINIMUM_POLICIES.aws.grant).toContain('"ec2:DescribeRegions"');
    expect(MINIMUM_POLICIES.aws.notes.join(" ")).toMatch(/ec2:DescribeRegions/);
    expect(docs).toContain("### Regions");
    expect(docs).toMatch(/skipped by choice/);
    expect(docs).toMatch(/Without `ec2:DescribeRegions`/);
  });

  it("names every Microsoft permission and the Azure role", () => {
    for (const p of MICROSOFT_GRAPH_PERMISSIONS) expect(docs).toContain(`\`${p}\``);
    expect(docs).toContain(`**${MICROSOFT_AZURE_ROLE}**`);
  });

  it("names every GCP role", () => {
    for (const r of GCP_ROLES) expect(docs).toContain(`\`${r}\``);
  });

  it("never calls an account read-only verified", () => {
    expect(docs).not.toMatch(/read-only verified|verified read-only/i);
    for (const p of Object.values(MINIMUM_POLICIES)) expect(JSON.stringify(p)).not.toMatch(/verified/i);
  });
});
