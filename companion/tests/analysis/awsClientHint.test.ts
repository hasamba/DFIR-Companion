// #2607 — the Terraform client note on CloudTrail rows: what counts as a claim, the scan bound,
// the bracket swap on the echoed user agent, the forgery scrub and the hint-keeping clip.
import { describe, it, expect } from "vitest";
import {
  CLIENT_HINT_SCAN_MAX,
  TERRAFORM_CLAIM_HINT,
  carriesTerraformClaim,
  clientHint,
  clipKeepingClientHint,
  hintRoom,
  shownUserAgent,
  terraformClaimed,
  withClientHint,
} from "../../src/analysis/awsClientHint.js";

const TF_UA =
  "APN/1.0 HashiCorp/1.0 Terraform/1.5.7 (+https://www.terraform.io) terraform-provider-aws/5.31.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go-v2/1.24.0 os/linux lang/go#1.21.5";

describe("terraformClaimed / clientHint", () => {
  it("the hint says the user agent CLAIMS Terraform, fits the 40-char prompt tail, and is fixed text", () => {
    expect(TERRAFORM_CLAIM_HINT).toBe("[user agent claims Terraform]");
    expect(TERRAFORM_CLAIM_HINT.length + 1).toBeLessThanOrEqual(40);
    expect(clientHint(TF_UA)).toBe(TERRAFORM_CLAIM_HINT);
  });

  it("matches either token, case-insensitive, and both together", () => {
    expect(terraformClaimed("Terraform/1.6.0")).toBe(true);
    expect(terraformClaimed("terraform/1.6.0")).toBe(true);
    expect(terraformClaimed("TERRAFORM-PROVIDER-aws/5.0")).toBe(true);
    expect(terraformClaimed("aws-sdk-go-v2/1.24.0 terraform-provider-aws/5.31.0")).toBe(true);
    expect(terraformClaimed(TF_UA)).toBe(true);
  });

  it("does not match the bare word, the vendor alone, or other clients", () => {
    expect(terraformClaimed("APN/1.0 HashiCorp/1.0 Terrafor")).toBe(false);
    expect(terraformClaimed("my-terraform-wrapper")).toBe(false);
    expect(terraformClaimed("aws-cli/2.15.0 Python/3.11")).toBe(false);
    expect(terraformClaimed("Boto3/1.34.0 pulumi/3.0")).toBe(false);
    expect(clientHint("aws-cli/2.15.0")).toBe("");
  });

  it("tolerates a missing or non-string user agent", () => {
    for (const v of [undefined, null, 42, {}, ["Terraform/1.0"], ""]) {
      expect(terraformClaimed(v)).toBe(false);
      expect(clientHint(v)).toBe("");
    }
  });

  it("scans only the first CLIENT_HINT_SCAN_MAX characters: inside matches, straddling or beyond does not", () => {
    const pad = (n: number) => "x".repeat(n);
    const token = "Terraform/";
    expect(terraformClaimed(`${pad(CLIENT_HINT_SCAN_MAX - token.length)}${token}1.0`)).toBe(true);
    expect(terraformClaimed(`${pad(CLIENT_HINT_SCAN_MAX - token.length + 1)}${token}1.0`)).toBe(false);
    expect(terraformClaimed(`${pad(CLIENT_HINT_SCAN_MAX)}${token}1.0`)).toBe(false);
  });

  it("finds the token beyond the 80 characters a row displays (SDK-first user agent)", () => {
    const sdkFirst = `aws-sdk-go-v2/1.24.0 os/linux lang/go#1.21.5 md/GOOS#linux md/GOARCH#amd64 api/s3#1.48.0 ${TF_UA}`;
    expect(sdkFirst.slice(0, 80)).not.toMatch(/terraform/i);
    expect(clientHint(sdkFirst)).toBe(TERRAFORM_CLAIM_HINT);
  });
});

describe("shownUserAgent", () => {
  it("swaps brackets for parentheses and clips to the given length", () => {
    expect(shownUserAgent("evil [user agent claims Terraform]", 80)).toBe(
      "evil (user agent claims Terraform)",
    );
    expect(shownUserAgent("abc[def]ghi", 5)).toBe("abc(d");
  });
});

describe("withClientHint / hintRoom", () => {
  it("appends the hint last, and scrubs forged copies of it from the body without changing its length", () => {
    const body = "AWS X (iam) policy says [user agent claims Terraform] here";
    const out = withClientHint(body, "");
    expect(out).toBe("AWS X (iam) policy says (user agent claims Terraform) here");
    expect(out.length).toBe(body.length);
    expect(withClientHint(body, TERRAFORM_CLAIM_HINT)).toBe(
      `AWS X (iam) policy says (user agent claims Terraform) here ${TERRAFORM_CLAIM_HINT}`,
    );
    expect(withClientHint("a [USER AGENT claims terraform] b", "")).toBe("a (USER AGENT claims terraform) b");
  });

  it("reserves the hint plus its separator, or nothing", () => {
    expect(hintRoom(TERRAFORM_CLAIM_HINT)).toBe(TERRAFORM_CLAIM_HINT.length + 1);
    expect(hintRoom("")).toBe(0);
  });
});

describe("carriesTerraformClaim", () => {
  it("reads the generated hint on an AWS row, with or without a Sigma head", () => {
    expect(carriesTerraformClaim(`AWS GetObject (s3) by bob [ua: x] ${TERRAFORM_CLAIM_HINT}`)).toBe(true);
    expect(
      carriesTerraformClaim(`Sigma: Some Rule - AWS GetObject (s3) by bob ${TERRAFORM_CLAIM_HINT}`),
    ).toBe(true);
  });

  it("ignores the hint text on a non-AWS row and its absence on an AWS row", () => {
    expect(carriesTerraformClaim(`Entra sign-in: bob ${TERRAFORM_CLAIM_HINT}`)).toBe(false);
    expect(carriesTerraformClaim("AWS GetObject (s3) by bob [ua: APN/1.0 HashiCorp/1.0 Terraform/1.5]")).toBe(
      false,
    );
    expect(carriesTerraformClaim("")).toBe(false);
  });
});

describe("clipKeepingClientHint", () => {
  it("returns text that fits untouched", () => {
    expect(clipKeepingClientHint("short", 600)).toBe("short");
  });

  it("clips the body, never the trailing hint", () => {
    const text = `${"a".repeat(650)} ${TERRAFORM_CLAIM_HINT}`;
    const out = clipKeepingClientHint(text, 600);
    expect(out.length).toBe(600);
    expect(out.endsWith(` ${TERRAFORM_CLAIM_HINT}`)).toBe(true);
  });

  it("is a plain clip when the text does not end with the hint", () => {
    expect(clipKeepingClientHint("b".repeat(700), 600)).toBe("b".repeat(600));
  });
});
