// Hand-written declarations, matching the convention used by the other public/js modules.
// announcementText is the DOM-free half and is what the node-environment unit tests import.
export declare function announcementText(kind: "job" | "error" | "ai", detail: string): string;
export declare function isAssertive(text: string): boolean;
export declare function announce(message: string, opts?: { assertive?: boolean }): void;
