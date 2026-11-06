// Synthetic GuardDuty findings for the #2361 tests: the documentation account id, TEST-NET
// addresses, example.* domains and made-up ids. Shaped like `aws guardduty get-findings` output.

export const GD_ACCOUNT = "123456789012";
export const GD_DETECTOR = "12abc34d567e8fa901bc2d34e56789f0";

type Row = Record<string, unknown>;

/** One finding; `over` replaces top-level fields, `service` merges into Service. */
export function gdFinding(
  i: number,
  over: Row = {},
  service: Row = {},
  region = "eu-west-1",
): Record<string, unknown> {
  const id = `f${String(i).padStart(4, "0")}aa11bb22cc33dd44ee55ff66`;
  return {
    AccountId: GD_ACCOUNT,
    Arn: `arn:aws:guardduty:${region}:${GD_ACCOUNT}:detector/${GD_DETECTOR}/finding/${id}`,
    CreatedAt: "2026-10-01T01:00:00.000Z",
    Description: `EC2 instance i-0abc${i} is performing outbound port scans against remote hosts.`,
    Id: id,
    Partition: "aws",
    Region: region,
    Resource: {
      ResourceType: "Instance",
      InstanceDetails: { InstanceId: `i-0abc${i}` },
    },
    SchemaVersion: "2.0",
    Service: {
      ServiceName: "guardduty",
      DetectorId: GD_DETECTOR,
      Archived: false,
      Count: 3,
      EventFirstSeen: "2026-10-01T00:55:00.000Z",
      EventLastSeen: "2026-10-01T01:30:00.000Z",
      Action: {
        ActionType: "NETWORK_CONNECTION",
        NetworkConnectionAction: {
          ConnectionDirection: "OUTBOUND",
          RemoteIpDetails: { IpAddressV4: "203.0.113.50" },
        },
      },
      ...service,
    },
    Severity: 5,
    Title: "Unusual outbound port scan",
    Type: "Recon:EC2/Portscan",
    UpdatedAt: "2026-10-01T01:30:00.000Z",
    ...over,
  };
}

/** The `aws guardduty get-findings` document. */
export const gdExport = (findings: unknown[]): string => JSON.stringify({ Findings: findings });
