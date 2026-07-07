// Mint a new Chrome Web Store API refresh token via Google's loopback OAuth flow — the
// supported replacement for the deprecated "urn:ietf:wg:oauth:2.0:oob" flow. Desktop-type
// OAuth clients accept any http://127.0.0.1:<port> redirect without pre-registering it in
// Cloud Console, so this needs no dashboard changes.
//
//   npx tsx scripts/chrome-refresh-token.ts <client-id> <client-secret>
//   CHROME_CLIENT_ID=... CHROME_CLIENT_SECRET=... npx tsx scripts/chrome-refresh-token.ts
import { createServer } from "node:http";

interface TokenResponse {
  refresh_token?: string;
  access_token?: string;
  error?: string;
  error_description?: string;
}

const clientId = process.argv[2] ?? process.env.CHROME_CLIENT_ID ?? "";
const clientSecret = process.argv[3] ?? process.env.CHROME_CLIENT_SECRET ?? "";
if (!clientId || !clientSecret) {
  console.error(
    "usage: npx tsx scripts/chrome-refresh-token.ts <client-id> <client-secret>\n" +
      "       (or set CHROME_CLIENT_ID / CHROME_CLIENT_SECRET env vars)",
  );
  process.exit(2);
}

const port = 8091;
const redirectUri = `http://127.0.0.1:${port}`;
const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
authUrl.searchParams.set("client_id", clientId);
authUrl.searchParams.set("redirect_uri", redirectUri);
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("access_type", "offline");
authUrl.searchParams.set("prompt", "consent");
authUrl.searchParams.set("scope", "https://www.googleapis.com/auth/chromewebstore");

const server = createServer((req, res) => {
  void handleCallback(req.url ?? "/", res);
});

async function handleCallback(reqUrl: string, res: import("node:http").ServerResponse): Promise<void> {
  const url = new URL(reqUrl, redirectUri);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");

  if (error) {
    res.end(`Google returned an error: ${error}. Check the terminal and try again.`);
    console.error(`Authorization failed: ${error}`);
    server.close();
    process.exit(1);
  }
  if (!code) {
    res.end("Waiting for authorization...");
    return;
  }

  res.end("Authorized -- you can close this tab and return to the terminal.");
  server.close();

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    }),
  });
  const body = (await tokenRes.json()) as TokenResponse;
  if (!tokenRes.ok || !body.refresh_token) {
    console.error("Token exchange failed:", body.error, body.error_description ?? "");
    process.exit(1);
  }

  console.log("\nNew CHROME_REFRESH_TOKEN:\n");
  console.log(body.refresh_token);
  console.log("\nUpdate it at: https://github.com/hasamba/DFIR-Companion/settings/secrets/actions");
}

server.listen(port, () => {
  console.log("Open this URL, sign in with the Chrome Web Store developer account, and approve access:\n");
  console.log(authUrl.toString());
  console.log(`\nWaiting for the redirect on ${redirectUri} ...`);
});
