import {
  constants,
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
  type JsonWebKey as NodeJsonWebKey,
  type KeyObject,
} from "node:crypto";
import type { OidcConfig } from "./authConfig.js";

const FLOW_TTL_MS = 10 * 60_000;
const CLOCK_SKEW_SECONDS = 60;

// Hard ceiling on in-flight OIDC logins. A flow is a handful of short strings, so this is a few
// hundred KB at worst — far more concurrent logins than any deployment of this tool will see, and
// small enough that an unauthenticated caller cannot make it matter. See sweepFlows.
const MAX_OUTSTANDING_FLOWS = 1000;

interface OidcDiscovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  codeChallengeMethods?: string[];
  signingAlgorithms?: string[];
}

interface OidcFlow {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  expiresAt: number;
}

export interface OidcClaims {
  issuer: string;
  subject: string;
  displayName: string;
  username?: string;
}

export interface OidcStart {
  authorizationUrl: string;
  state: string;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

function requiredString(source: Record<string, unknown>, field: string): string {
  const value = source[field];
  if (typeof value !== "string" || !value) throw new Error(`OIDC ${field} is missing`);
  return value;
}

function optionalStrings(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return undefined;
  return value;
}

function httpsEndpoint(value: string, field: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`OIDC ${field} is not an absolute URL`);
  }
  if (parsed.protocol !== "https:") throw new Error(`OIDC ${field} must use HTTPS`);
  return parsed.toString();
}

function safeReturnTo(value: string | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/dashboard";
  try {
    const parsed = new URL(value, "https://dfir.invalid");
    if (parsed.origin !== "https://dfir.invalid") return "/dashboard";
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return "/dashboard";
  }
}

function formEncode(value: string): string {
  return new URLSearchParams({ value }).toString().slice("value=".length);
}

function decodePart(value: string, label: string): Record<string, unknown> {
  try {
    return object(JSON.parse(Buffer.from(value, "base64url").toString("utf8")), label);
  } catch {
    throw new Error(`OIDC ${label} is malformed`);
  }
}

function stringClaim(claims: Record<string, unknown>, name: string): string | undefined {
  const value = claims[name];
  return typeof value === "string" && value.trim() ? value.trim().slice(0, 320) : undefined;
}

function keyForAlgorithm(
  algorithm: string,
  key: KeyObject,
):
  | KeyObject
  | {
      key: KeyObject;
      padding?: number;
      saltLength?: number;
      dsaEncoding?: "ieee-p1363";
    } {
  if (algorithm.startsWith("PS")) {
    return {
      key,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
    };
  }
  if (algorithm.startsWith("ES")) return { key, dsaEncoding: "ieee-p1363" };
  return key;
}

function nodeJsonWebKey(source: Record<string, unknown>): NodeJsonWebKey {
  const converted: NodeJsonWebKey = {};
  for (const field of ["crv", "d", "dp", "dq", "e", "k", "kty", "n", "p", "q", "qi", "x", "y"]) {
    if (typeof source[field] === "string") converted[field] = source[field];
  }
  return converted;
}

function digestForAlgorithm(algorithm: string): string | null {
  if (algorithm === "EdDSA") return null;
  const bits = algorithm.slice(-3);
  if (!["256", "384", "512"].includes(bits))
    throw new Error(`OIDC ID token algorithm ${algorithm} is unsupported`);
  return `sha${bits}`;
}

export class OidcClient {
  private readonly flows = new Map<string, OidcFlow>();
  private discoveryPromise?: Promise<OidcDiscovery>;

  constructor(
    readonly config: OidcConfig & { redirectUri: string },
    private readonly fetchFn: typeof fetch = fetch,
  ) {}

  private async json(url: string, init?: RequestInit): Promise<Record<string, unknown>> {
    const response = await this.fetchFn(url, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.headers ?? {}),
      },
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok)
      throw new Error(`OIDC request to ${new URL(url).origin} failed with HTTP ${response.status}`);
    const parsed: unknown = await response.json();
    return object(parsed, "response");
  }

  private discovery(): Promise<OidcDiscovery> {
    if (!this.discoveryPromise) {
      this.discoveryPromise = this.loadDiscovery().catch((err) => {
        this.discoveryPromise = undefined;
        throw err;
      });
    }
    return this.discoveryPromise;
  }

  private async loadDiscovery(): Promise<OidcDiscovery> {
    const source = await this.json(`${this.config.issuer}/.well-known/openid-configuration`);
    const issuer = requiredString(source, "issuer").replace(/\/+$/, "");
    if (issuer !== this.config.issuer) throw new Error("OIDC discovery issuer does not match configuration");
    return {
      issuer,
      authorizationEndpoint: httpsEndpoint(
        requiredString(source, "authorization_endpoint"),
        "authorization_endpoint",
      ),
      tokenEndpoint: httpsEndpoint(requiredString(source, "token_endpoint"), "token_endpoint"),
      jwksUri: httpsEndpoint(requiredString(source, "jwks_uri"), "jwks_uri"),
      codeChallengeMethods: optionalStrings(source.code_challenge_methods_supported),
      signingAlgorithms: optionalStrings(source.id_token_signing_alg_values_supported),
    };
  }

  /**
   * Drop expired flows, then enforce a hard ceiling on how many can be outstanding at once.
   *
   * The sweep alone never bounded anything: it only ran when another flow started, and every flow
   * lives for ten minutes, so a caller issuing starts faster than they expire grew the map without
   * limit — no credentials required, since /auth/oidc/start is public. The route is rate-limited per
   * IP now, but a limiter is a rate, not a ceiling: enough distinct clients still add up. The cap is
   * what actually bounds the memory.
   *
   * Eviction is oldest-first (Map preserves insertion order), which is the least-harmful choice
   * available: the oldest outstanding flow is the one closest to expiring anyway, and losing it
   * costs its owner a restarted login rather than anything durable.
   */
  private sweepFlows(now = Date.now()): void {
    for (const [state, flow] of this.flows) {
      if (flow.expiresAt <= now) this.flows.delete(state);
    }
    while (this.flows.size >= MAX_OUTSTANDING_FLOWS) {
      const oldest = this.flows.keys().next();
      if (oldest.done) break;
      this.flows.delete(oldest.value);
    }
  }

  async begin(returnToInput?: string): Promise<OidcStart> {
    const discovery = await this.discovery();
    if (discovery.codeChallengeMethods && !discovery.codeChallengeMethods.includes("S256")) {
      throw new Error("OIDC provider does not advertise S256 PKCE support");
    }
    this.sweepFlows();
    const state = randomBytes(32).toString("base64url");
    const nonce = randomBytes(32).toString("base64url");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
    this.flows.set(state, {
      state,
      nonce,
      verifier,
      returnTo: safeReturnTo(returnToInput),
      expiresAt: Date.now() + FLOW_TTL_MS,
    });
    const authorization = new URL(discovery.authorizationEndpoint);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("client_id", this.config.clientId);
    authorization.searchParams.set("redirect_uri", this.config.redirectUri);
    authorization.searchParams.set("scope", this.config.scopes.join(" "));
    authorization.searchParams.set("state", state);
    authorization.searchParams.set("nonce", nonce);
    authorization.searchParams.set("code_challenge", challenge);
    authorization.searchParams.set("code_challenge_method", "S256");
    return { authorizationUrl: authorization.toString(), state };
  }

  async complete(input: {
    state: string;
    browserState: string;
    code: string;
    responseIssuer?: string;
  }): Promise<{ claims: OidcClaims; returnTo: string }> {
    const flow = this.flows.get(input.state);
    this.flows.delete(input.state);
    if (!flow || flow.expiresAt <= Date.now()) throw new Error("OIDC state is invalid or expired");
    if (input.browserState !== flow.state)
      throw new Error("OIDC callback is not bound to the browser that started it");
    if (input.responseIssuer && input.responseIssuer.replace(/\/+$/, "") !== this.config.issuer) {
      throw new Error("OIDC authorization response issuer does not match configuration");
    }
    const discovery = await this.discovery();
    const form = new URLSearchParams({
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: flow.verifier,
    });
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    if (this.config.clientSecret) {
      headers.Authorization = `Basic ${Buffer.from(
        `${formEncode(this.config.clientId)}:${formEncode(this.config.clientSecret)}`,
        "utf8",
      ).toString("base64")}`;
    }
    const tokenResponse = await this.json(discovery.tokenEndpoint, {
      method: "POST",
      headers,
      body: form.toString(),
    });
    const idToken = requiredString(tokenResponse, "id_token");
    const claims = await this.verifyIdToken(idToken, flow.nonce, discovery);
    return { claims, returnTo: flow.returnTo };
  }

  private async verifyIdToken(
    token: string,
    expectedNonce: string,
    discovery: OidcDiscovery,
  ): Promise<OidcClaims> {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("OIDC ID token is malformed");
    const header = decodePart(parts[0], "ID token header");
    const claims = decodePart(parts[1], "ID token claims");
    const algorithm = requiredString(header, "alg");
    if (algorithm === "none" || !/^(?:RS|PS|ES)(?:256|384|512)$|^EdDSA$/.test(algorithm)) {
      throw new Error(`OIDC ID token algorithm ${algorithm} is unsupported`);
    }
    if (discovery.signingAlgorithms && !discovery.signingAlgorithms.includes(algorithm)) {
      throw new Error("OIDC ID token algorithm was not advertised by the provider");
    }
    const kid = requiredString(header, "kid");
    const jwks = await this.json(discovery.jwksUri);
    const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
    const candidate = keys
      .map((value) => object(value, "JWK"))
      .find(
        (value) =>
          value.kid === kid &&
          (value.use === undefined || value.use === "sig") &&
          (value.alg === undefined || value.alg === algorithm),
      );
    if (!candidate) throw new Error("OIDC signing key was not found");
    let key: KeyObject;
    try {
      key = createPublicKey({ key: nodeJsonWebKey(candidate), format: "jwk" });
    } catch {
      throw new Error("OIDC signing key is invalid");
    }
    const validSignature = verifySignature(
      digestForAlgorithm(algorithm),
      Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"),
      keyForAlgorithm(algorithm, key),
      Buffer.from(parts[2], "base64url"),
    );
    if (!validSignature) throw new Error("OIDC ID token signature is invalid");
    return this.validateClaims(claims, expectedNonce);
  }

  private validateClaims(claims: Record<string, unknown>, expectedNonce: string): OidcClaims {
    const issuer = requiredString(claims, "iss").replace(/\/+$/, "");
    if (issuer !== this.config.issuer) throw new Error("OIDC ID token issuer does not match");
    const audiences =
      typeof claims.aud === "string"
        ? [claims.aud]
        : Array.isArray(claims.aud) && claims.aud.every((item) => typeof item === "string")
          ? claims.aud
          : [];
    if (!audiences.includes(this.config.clientId)) throw new Error("OIDC ID token audience does not match");
    if (audiences.length > 1 && claims.azp !== this.config.clientId) {
      throw new Error("OIDC ID token authorized party does not match");
    }
    const now = Math.floor(Date.now() / 1_000);
    if (typeof claims.exp !== "number" || claims.exp < now - CLOCK_SKEW_SECONDS) {
      throw new Error("OIDC ID token is expired");
    }
    if (typeof claims.iat !== "number" || claims.iat > now + CLOCK_SKEW_SECONDS) {
      throw new Error("OIDC ID token issued-at time is invalid");
    }
    if (typeof claims.nbf === "number" && claims.nbf > now + CLOCK_SKEW_SECONDS) {
      throw new Error("OIDC ID token is not valid yet");
    }
    if (claims.nonce !== expectedNonce) throw new Error("OIDC ID token nonce does not match");
    const subject = requiredString(claims, "sub");
    if (subject.length > 255) throw new Error("OIDC subject is too long");
    const username = stringClaim(claims, "preferred_username") ?? stringClaim(claims, "email");
    const displayName = stringClaim(claims, "name") ?? username ?? subject;
    return {
      issuer,
      subject,
      displayName: displayName.slice(0, 120),
      ...(username ? { username: username.slice(0, 120) } : {}),
    };
  }
}
