// #931 item 11 (record half): a Google Drive sharing change read for what the record states —
// the permission direction along the documented chain, the overall-visibility direction from
// Google's own `visibility_change`, the resulting visibility, the target as recorded — and an
// access record read for what its event means. Nothing the record does not say.
import { describe, expect, it } from "vitest";
import { parseGoogleWorkspaceReport } from "../../src/analysis/googleWorkspaceImport.js";
import { decodeGwsDrive } from "../../src/analysis/gwsDrive.js";
import { readGwsParams } from "../../src/analysis/gwsOAuth.js";
import {
  canonicalConformanceIssues,
  canonicalEventEnvelopeSchema,
} from "../../src/analysis/canonicalEvent.js";

const OWNER = "alice@corp.example";
const DOC = "1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
const p = (name: string, value: string | boolean) =>
  typeof value === "boolean" ? { name, boolValue: value } : { name, value };
const docParams = (over: Record<string, string | boolean> = {}) => {
  const base: Record<string, string | boolean> = {
    doc_id: DOC,
    doc_title: "Q3 plan",
    doc_type: "spreadsheet",
    owner: OWNER,
    owner_is_shared_drive: false,
    primary_event: true,
    billable: true,
  };
  return Object.entries({ ...base, ...over }).map(([k, v]) => p(k, v));
};
const act = (over: Record<string, unknown> = {}): Record<string, unknown> => {
  const { events, id, ...rest } = over as { events?: unknown; id?: Record<string, unknown> } & Record<
    string,
    unknown
  >;
  return {
    kind: "admin#reports#activity",
    id: {
      time: "2026-05-02T10:00:00.000Z",
      uniqueQualifier: "-1",
      applicationName: "drive",
      customerId: "C01abc",
      ...(id ?? {}),
    },
    actor: { email: OWNER, profileId: "1234" },
    ipAddress: "203.0.113.10",
    events,
    ...rest,
  };
};
const drive = (name: string, params: unknown[], type = "acl_change", over: Record<string, unknown> = {}) =>
  act({ events: [{ type, name, parameters: params }], ...over });
const one = (name: string, params: unknown[], type = "acl_change", over: Record<string, unknown> = {}) =>
  parseGoogleWorkspaceReport(JSON.stringify([drive(name, params, type, over)]), { aggregate: false })
    .events[0];
const decode = (name: string, params: unknown[]) =>
  decodeGwsDrive(name, readGwsParams({ parameters: params }));

describe("decodeGwsDrive — sharing changes: direction along the documented chain", () => {
  it("none → can_edit for a target is a broadening of edit capability: Medium; the target may be a user, a group or a domain", () => {
    const e = one(
      "change_user_access",
      docParams({
        old_value: "none",
        new_value: "can_edit",
        target_user: "bob@corp.example",
        visibility_change: "none",
        visibility: "shared_internally",
      }),
    );
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toEqual([]);
    expect(e.description).toContain("Google Workspace drive: change_user_access by alice@corp.example");
    expect(e.description).toContain(
      "broadens: none → can_edit for bob@corp.example (may be a user, a group or a domain)",
    );
    expect(e.description).toContain("overall visibility unchanged; now shared_internally");
    expect(e.description).toContain(`on Q3 plan (doc ${DOC}, spreadsheet, owner alice@corp.example)`);
    expect(e.description).toContain("from 203.0.113.10");
    expect(e.description).not.toContain("outside");
    const env = canonicalEventEnvelopeSchema.parse(e.canonical);
    expect(env.event).toEqual({
      category: "cloud",
      type: "drive-sharing",
      action: "change_user_access",
      outcome: "success",
    });
    expect(env.object).toEqual({ kind: "file", id: DOC, name: "Q3 plan" });
    expect(env.cloud?.resource).toBe(DOC);
    expect(env.driveSharing).toMatchObject({
      direction: "broadens",
      from: "none",
      to: "can_edit",
      target: "bob@corp.example",
      targetDomainDiffers: false,
      visibilityChange: "none",
      visibility: "shared_internally",
      primary: true,
      reconciled: false,
    });
    expect(canonicalConformanceIssues(env)).toEqual([]);
  });

  it("a view or comment grant inside the domain is Low; owner / organizer grants are Medium", () => {
    expect(
      one(
        "change_user_access",
        docParams({
          old_value: "none",
          new_value: "can_view",
          target_user: "bob@corp.example",
          visibility_change: "none",
        }),
      ).severity,
    ).toBe("Low");
    expect(
      one(
        "change_user_access",
        docParams({
          old_value: "can_view",
          new_value: "can_comment",
          target_user: "bob@corp.example",
          visibility_change: "none",
        }),
      ).severity,
    ).toBe("Low");
    expect(
      one(
        "change_user_access",
        docParams({
          old_value: "can_edit",
          new_value: "owner",
          target_user: "bob@corp.example",
          visibility_change: "none",
        }),
      ).severity,
    ).toBe("Medium");
    expect(
      one(
        "change_user_access",
        docParams({
          old_value: "none",
          new_value: "organizer",
          target_user: "bob@corp.example",
          visibility_change: "none",
        }),
      ).severity,
    ).toBe("Medium");
  });

  it("newly external comes only from Google's visibility_change — a differing address domain is said, and grades nothing", () => {
    const external = one(
      "change_user_access",
      docParams({
        old_value: "none",
        new_value: "can_view",
        target_user: "bob@partner.example",
        visibility_change: "external",
        visibility: "shared_externally",
      }),
    );
    expect(external.severity).toBe("High");
    expect(external.mitreTechniques).toContain("T1537");
    expect(external.description).toContain(
      "broadens: none → can_view for bob@partner.example (may be a user, a group or a domain; the recorded address domains differ)",
    );
    expect(external.description).toContain("overall visibility newly external; now shared_externally");
    expect(external.description).not.toContain("outside the owner");
    const differsOnly = one(
      "change_user_access",
      docParams({
        old_value: "none",
        new_value: "can_view",
        target_user: "bob@partner.example",
        visibility_change: "none",
        visibility: "shared_externally",
      }),
    );
    expect(differsOnly.severity).toBe("Low");
    expect(differsOnly.description).toContain("the recorded address domains differ");
    expect(differsOnly.description).toContain("overall visibility unchanged; now shared_externally");
    const env = canonicalEventEnvelopeSchema.parse(differsOnly.canonical);
    expect(env.driveSharing?.targetDomainDiffers).toBe(true);
    expect(env.driveSharing?.visibilityChange).toBe("none");
  });

  it("a removal or a narrowing is Low and says so; back to internal is a narrowing of overall visibility", () => {
    const removed = one(
      "change_user_access",
      docParams({
        old_value: "can_edit",
        new_value: "none",
        target_user: "bob@partner.example",
        visibility_change: "internal",
        visibility: "private",
      }),
    );
    expect(removed.severity).toBe("Low");
    expect(removed.description).toContain(
      "narrows: can_edit → none (access removed) for bob@partner.example",
    );
    expect(removed.description).toContain("overall visibility back to internal; now private");
    const down = one(
      "change_user_access",
      docParams({
        old_value: "can_edit",
        new_value: "can_view",
        target_user: "bob@corp.example",
        visibility_change: "none",
      }),
    );
    expect(down.severity).toBe("Low");
    expect(down.description).toContain("narrows: can_edit → can_view");
  });

  it("a transition involving a resource-specific value, or an unknown value, is 'direction not established' with both values shown — Medium", () => {
    const respond = one(
      "change_user_access",
      docParams({
        old_value: "can_view",
        new_value: "can_respond",
        target_user: "bob@corp.example",
        visibility_change: "none",
      }),
    );
    expect(respond.severity).toBe("Medium");
    expect(respond.description).toContain("direction not established: can_view → can_respond");
    const unknown = one(
      "change_user_access",
      docParams({
        old_value: "can_view",
        new_value: "can_fly",
        target_user: "bob@corp.example",
        visibility_change: "none",
      }),
    );
    expect(unknown.severity).toBe("Medium");
    expect(unknown.description).toContain("direction not established: can_view → can_fly");
    expect(
      one(
        "change_user_access",
        docParams({
          old_value: "none",
          new_value: "can_respond",
          target_user: "bob@corp.example",
          visibility_change: "none",
        }),
      ).description,
    ).toContain("broadens: none → can_respond");
    const same = one(
      "change_user_access",
      docParams({
        old_value: "can_view",
        new_value: "can_view",
        target_user: "bob@corp.example",
        visibility_change: "none",
      }),
    );
    expect(same.severity).toBe("Low");
    expect(same.description).toContain("no change in level: can_view → can_view");
  });

  it("document visibility: link and public audiences are High, domain-wide is Medium, back to private is Low; the two domain states are ranked apart", () => {
    const link = one(
      "change_document_visibility",
      docParams({
        old_value: "private",
        new_value: "people_with_link",
        visibility_change: "external",
        visibility: "people_with_link",
      }),
    );
    expect(link.severity).toBe("High");
    expect(link.description).toContain("broadens: private → people_with_link (anyone with the link)");
    expect(
      one(
        "change_document_visibility",
        docParams({ old_value: "private", new_value: "public_on_the_web", visibility_change: "external" }),
      ).description,
    ).toContain("public_on_the_web (anyone on the web)");
    const domain = one(
      "change_document_visibility",
      docParams({ old_value: "private", new_value: "public_in_the_domain", visibility_change: "none" }),
    );
    expect(domain.severity).toBe("Medium");
    expect(domain.description).toContain("public_in_the_domain (anyone in the domain)");
    const domainLink = one(
      "change_document_visibility",
      docParams({
        old_value: "public_in_the_domain",
        new_value: "people_within_domain_with_link",
        visibility_change: "none",
      }),
    );
    expect(domainLink.severity).toBe("Low");
    expect(domainLink.description).toContain(
      "narrows: public_in_the_domain → people_within_domain_with_link (anyone in the domain with the link)",
    );
    const closed = one(
      "change_document_visibility",
      docParams({ old_value: "public_on_the_web", new_value: "private", visibility_change: "internal" }),
    );
    expect(closed.severity).toBe("Low");
    expect(closed.description).toContain("narrows: public_on_the_web → private");
  });

  it("a link access scope names the domain, 'all' is every domain with visibility and High; editors-may-share is Medium; owner transfer is Medium", () => {
    const all = one(
      "change_document_access_scope",
      docParams({
        old_value: "none",
        new_value: "can_edit",
        target_domain: "all",
        visibility_change: "none",
      }),
    );
    expect(all.severity).toBe("High");
    expect(all.description).toContain(
      "broadens: none → can_edit for the link across all domains with visibility",
    );
    const dom = one(
      "change_document_access_scope",
      docParams({
        old_value: "none",
        new_value: "can_view",
        target_domain: "corp.example",
        visibility_change: "none",
      }),
    );
    expect(dom.severity).toBe("Low");
    expect(dom.description).toContain("broadens: none → can_view for the link in domain corp.example");
    const editors = one(
      "change_acl_editors",
      docParams({ old_value: "owner", new_value: "writers", visibility_change: "none" }),
    );
    expect(editors.severity).toBe("Medium");
    expect(editors.description).toContain("writers may now change sharing (was: owner)");
    expect(
      one(
        "change_acl_editors",
        docParams({ old_value: "writers", new_value: "owner", visibility_change: "none" }),
      ).severity,
    ).toBe("Low");
    const owner = one(
      "change_owner",
      docParams({
        old_value: OWNER,
        new_value: "bob@corp.example",
        target_user: "bob@corp.example",
        visibility_change: "none",
      }),
    );
    expect(owner.severity).toBe("Medium");
    expect(owner.description).toContain("ownership transferred to bob@corp.example");
  });

  it("shared-drive membership: an add or role raise is Medium, a removal Low; the roles as recorded", () => {
    const add = one(
      "shared_drive_membership_change",
      docParams({
        membership_change_type: "add_to_shared_drive",
        added_role: "content_manager",
        removed_role: "none",
        target_user: "bob@corp.example",
        shared_drive_id: "0AJx",
        owner_is_shared_drive: true,
        owner: "Finance",
      }),
    );
    expect(add.severity).toBe("Medium");
    expect(add.description).toContain("add_to_shared_drive: bob@corp.example added as content_manager");
    expect(add.description).toContain("shared drive Finance (0AJx)");
    const remove = one(
      "shared_drive_membership_change",
      docParams({
        membership_change_type: "remove_from_shared_drive",
        removed_role: "editor",
        added_role: "none",
        target_user: "bob@corp.example",
      }),
    );
    expect(remove.severity).toBe("Low");
    expect(remove.description).toContain("remove_from_shared_drive: bob@corp.example removed from editor");
    const roles = one(
      "shared_drive_membership_change",
      docParams({
        membership_change_type: "change_roles",
        removed_role: "viewer",
        added_role: "organizer",
        target_user: "bob@corp.example",
      }),
    );
    expect(roles.severity).toBe("Medium");
    expect(roles.description).toContain("change_roles: bob@corp.example viewer → organizer");
  });

  it("a hierarchy-reconciled side effect is Info and says it is not an action on this item; primary_event=false is a side effect; inherited-permission changes claim no direction", () => {
    const reconciled = one(
      "change_user_access_hierarchy_reconciled",
      docParams({
        old_value: "none",
        new_value: "can_edit",
        target_user: "bob@partner.example",
        visibility_change: "external",
      }),
    );
    expect(reconciled.severity).toBe("Info");
    expect(reconciled.mitreTechniques).toEqual([]);
    expect(reconciled.description).toContain(
      "reconciled from a parent folder change — not an action on this item",
    );
    expect(reconciled.description).toContain("broadens: none → can_edit");
    const side = one(
      "change_user_access",
      docParams({
        old_value: "none",
        new_value: "can_edit",
        target_user: "bob@corp.example",
        visibility_change: "none",
        primary_event: false,
      }),
    );
    expect(side.severity).toBe("Info");
    expect(side.description).toContain("side effect of another event (primary_event=false)");
    const inherited = one("disable_inherited_permissions", docParams({}));
    expect(inherited.severity).toBe("Low");
    expect(inherited.description).toContain(
      "inherited permissions disabled — direction not established by this record",
    );
  });

  it("an application actor is kept beside the user it acted as; the originating app is a project number", () => {
    const e = one(
      "change_user_access",
      docParams({
        old_value: "none",
        new_value: "can_view",
        target_user: "bob@corp.example",
        visibility_change: "none",
        originating_app_id: "1234567890",
      }),
      "acl_change",
      {
        actor: {
          email: OWNER,
          profileId: "1234",
          callerType: "APPLICATION",
          applicationInfo: { oauthClientId: "abc.apps", applicationName: "Sync Tool" },
        },
      },
    );
    expect(e.description).toContain("by Sync Tool as alice@corp.example");
    expect(e.description).toContain("by application project 1234567890");
    const env = canonicalEventEnvelopeSchema.parse(e.canonical);
    expect(env.actor?.kind).toBe("cloud_principal");
    expect(env.subject).toEqual({ kind: "account", name: OWNER, id: "1234" });
    expect(env.driveSharing?.originatingApp).toBe("1234567890");
  });

  it("a record with no doc_id never folds with another and says the document is not identified", () => {
    const a = drive("change_user_access", [
      p("old_value", "none"),
      p("new_value", "can_edit"),
      p("target_user", "bob@corp.example"),
    ]);
    const b = drive("change_user_access", [
      p("old_value", "none"),
      p("new_value", "can_edit"),
      p("target_user", "bob@corp.example"),
    ]);
    const r = parseGoogleWorkspaceReport(JSON.stringify([a, b]), { aggregate: true });
    expect(r.events).toHaveLength(2);
    expect(r.events[0].description).toContain("document not identified in this record");
  });

  it("two sharees of one action are two rows; a broaden and a later narrow of one sharee are two rows; a re-import folds", () => {
    const share = (target: string, oldValue = "none", newValue = "can_edit") =>
      drive(
        "change_user_access",
        docParams({
          old_value: oldValue,
          new_value: newValue,
          target_user: target,
          visibility_change: "none",
        }),
      );
    const two = parseGoogleWorkspaceReport(
      JSON.stringify([share("bob@corp.example"), share("carol@corp.example")]),
      { aggregate: true },
    );
    expect(two.events).toHaveLength(2);
    const flip = parseGoogleWorkspaceReport(
      JSON.stringify([share("bob@corp.example"), share("bob@corp.example", "can_edit", "none")]),
      { aggregate: true },
    );
    expect(flip.events).toHaveLength(2);
    const dup = parseGoogleWorkspaceReport(
      JSON.stringify([share("bob@corp.example"), share("bob@corp.example")]),
      { aggregate: true },
    );
    expect(dup.events).toHaveLength(1);
  });
});

describe("decodeGwsDrive — access records read for what the event means", () => {
  it("download reads 'download recorded', a preview is never a download, sync and application content access are said as such; the table grades stand", () => {
    const dl = one("download", docParams({ visibility: "people_with_link" }), "access");
    expect(dl.severity).toBe("Low");
    expect(dl.description).toContain("download recorded");
    expect(dl.description).toContain("visibility at the time: people_with_link");
    const env = canonicalEventEnvelopeSchema.parse(dl.canonical);
    expect(env.event).toEqual({
      category: "cloud",
      type: "drive-access",
      action: "download",
      outcome: "success",
    });
    expect(env.driveAccess).toMatchObject({ meaning: "download recorded", visibility: "people_with_link" });
    const preview = one("preview", docParams({}), "access");
    expect(preview.severity).toBe("Info");
    expect(preview.description).toContain("previewed");
    expect(preview.description).not.toContain("download");
    expect(one("view", docParams({}), "access").description).toContain("viewed");
    expect(one("sync_item_content", docParams({}), "access").description).toContain("item content synced");
    const app = one(
      "access_item_content",
      docParams({ originating_app_id: "1234567890", api_method: "drive.files.get" }),
      "access",
    );
    expect(app.description).toContain("an application accessed content on behalf of the recorded user");
    expect(app.description).toContain("api_method drive.files.get");
    expect(app.description).toContain("by application project 1234567890");
    expect(one("prefetch_item_content", docParams({}), "access").description).toContain(
      "an application prefetched content on behalf of the recorded user",
    );
    expect(one("email_as_attachment", docParams({}), "access").description).toContain(
      "sent as an attachment",
    );
  });

  it("a record with no actor identity says so and never says anonymous; a download by an application is an application's fetch", () => {
    const none = one("download", docParams({}), "access", { actor: {} });
    expect(none.description).toContain("no actor identity in this record");
    expect(none.description).not.toMatch(/anonymous/i);
    expect(none.severity).toBe("Low");
    const app = one("download", docParams({ originating_app_id: "1234567890" }), "access");
    expect(app.description).toContain(
      "download recorded by application project 1234567890 — an application's fetch, not shown to be a person's download",
    );
  });

  it("an access event the decoder does not name still imports as before", () => {
    const e = one("rename", docParams({}), "access");
    expect(e.description).toBe(
      "Google Workspace drive: rename by alice@corp.example → Q3 plan from 203.0.113.10",
    );
    expect(e.canonical).toBeUndefined();
  });
});

describe("decodeGwsDrive — neutralisation and bounds", () => {
  it("every displayed string is neutralised and bounded: titles, addresses, targets, project numbers, domains", () => {
    const evil = 'Q3] [fake: shared by root\n=HYPERLINK("x")|<b>\u202e';
    const e = one(
      "change_user_access",
      docParams({
        doc_title: evil,
        owner: "own] [x@corp.example",
        old_value: "none",
        new_value: "can_edit",
        target_user: "bob] [fake@partner.example\u200b",
        visibility_change: "none",
        originating_app_id: "123] [456",
        target_domain: "dom] [ain",
      }),
    );
    // The words are neutralised; the envelope carries the values as recorded and the renderers escape them.
    for (const s of [e.description]) {
      expect(s).not.toContain("] [");
      expect(s).not.toContain("\u202e");
      expect(s).not.toContain("\u200b");
      expect(s).not.toContain("\n");
    }
    expect(canonicalEventEnvelopeSchema.parse(e.canonical).driveSharing?.target).toBe(
      "bob] [fake@partner.example\u200b",
    );
    expect(e.description.length).toBeLessThanOrEqual(600);
    const long = one(
      "change_user_access",
      docParams({
        doc_title: "T".repeat(500),
        old_value: "none",
        new_value: "can_edit",
        target_user: `${"u".repeat(300)}@corp.example`,
        visibility_change: "none",
      }),
    );
    expect(long.description.length).toBeLessThanOrEqual(600);
    expect(long.description).toContain("broadens: none → can_edit");
  });

  it("the decoder returns null for a non-Drive event name", () => {
    expect(decode("login_success", [])).toBeNull();
    expect(decode("change_user_access", docParams({ old_value: "none", new_value: "can_edit" }))?.kind).toBe(
      "sharing",
    );
  });
});
