// Interactive login for the workbench (design/13 §7 step 1, 05 §3.4) — now
// dual-client per implementation/agent-sidecar.md §5.
//
// OIDC authorization-code + PKCE against the bundled Keycloak, twice: the
// interactive flow on the HUMAN client (`reckon`), then a second flow on the
// AGENT client (`reckon-agent`, the one whose mapper stamps delegate_kind
// issuer-side). The second flow completes silently on the realm SSO session
// cookie the first one set — no re-prompt, no password, public clients only.
// The extension never sees a password: it opens the browser to Keycloak,
// catches the redirect on a loopback listener, and exchanges the code (+ PKCE
// verifier) for tokens.
//
// The extension is the SOLE auth owner: both refresh tokens live in
// vscode.SecretStorage — never in settings, never on disk in the clear, and
// never handed to the sidecar (which receives short-lived access tokens over
// the getToken RPC callback, per call). A 401 downstream forces a refresh.
//
// The issuer + both clients are discovered from the backend's
// /api/auth-config, so nothing here hardcodes Keycloak's port, realm, or
// client ids.

import * as crypto from "crypto";
import * as http from "http";
import { AddressInfo } from "net";
import * as vscode from "vscode";

/** Which realm client a token comes from — the actor-attribution axis. */
export type TokenKind = "human" | "delegate";

/** Where each persisted refresh token lives in SecretStorage. */
const REFRESH_TOKEN_KEYS: Record<TokenKind, string> = {
  human: "reckon.refreshToken",
  delegate: "reckon.agentRefreshToken",
};

/** Renew this many ms before the access token's expiry (matches agent/auth.go). */
const REFRESH_SKEW_MS = 30_000;

interface AuthConfig {
  issuer: string;
  clientId: string;
  agentClientId?: string;
}

interface OidcEndpoints {
  authorization: string;
  token: string;
}

interface TokenSet {
  accessToken: string;
  refreshToken: string;
  /** Epoch ms at which the access token expires. */
  expiresAt: number;
}

/** Public claims the UI shows; parsed from /api/me, not the raw token. */
export interface Identity {
  subject: string;
  username: string;
  tenantId: string;
  roles: string[];
}

/**
 * Session owns both clients' tokens and their lifecycle. `token(kind)` always
 * returns a currently-valid access token for that kind (refreshing silently
 * when near expiry; `force` mints fresh regardless — the 401 backstop),
 * mirroring agent.TokenSource on the Go side. `onDidChange` fires whenever
 * signed-in state flips so the UI can re-render.
 */
export class Session {
  private readonly tokens = new Map<TokenKind, TokenSet>();
  private endpoints: OidcEndpoints | null = null;
  private config: AuthConfig | null = null;
  private readonly refreshTimers = new Map<TokenKind, ReturnType<typeof setTimeout>>();

  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changed.event;

  constructor(
    private readonly secrets: vscode.SecretStorage,
    private readonly loadAuthConfig: () => Promise<AuthConfig>,
    private readonly log: vscode.LogOutputChannel,
  ) {}

  /** Signed in means the HUMAN session is live; the delegate side may lag (see token). */
  get signedIn(): boolean {
    return this.tokens.has("human");
  }

  /**
   * Attempt a silent restore from the persisted refresh tokens. Safe to call
   * on activation — a failure (expired/revoked refresh token, backend down)
   * just leaves that side signed out. The human side is the signed-in
   * criterion; a delegate-side failure surfaces later, at first agent turn.
   */
  async restore(): Promise<void> {
    for (const kind of ["human", "delegate"] as TokenKind[]) {
      const refreshToken = await this.secrets.get(REFRESH_TOKEN_KEYS[kind]);
      if (!refreshToken) {
        continue;
      }
      try {
        await this.ensureDiscovery();
        const clientId = this.clientIdFor(kind);
        if (!clientId) {
          continue;
        }
        await this.grant(kind, new URLSearchParams({
          grant_type: "refresh_token",
          client_id: clientId,
          refresh_token: refreshToken,
        }));
        this.log.info(`${kind} session restored from stored refresh token`);
      } catch (err) {
        this.log.info(`${kind} session restore failed (${errText(err)}); signed out on that side`);
        await this.secrets.delete(REFRESH_TOKEN_KEYS[kind]);
        this.tokens.delete(kind);
      }
    }
    if (this.signedIn) {
      this.changed.fire();
    }
  }

  /**
   * Run the interactive PKCE login on the human client, then the silent
   * second flow on the agent client (rides the realm SSO session — the
   * browser bounces straight back without a form). Resolves signed-in, throws
   * on failure/cancel of the HUMAN flow; an agent-flow failure logs and
   * defers (turns will surface it) rather than blocking sign-in.
   */
  async signIn(): Promise<void> {
    await this.ensureDiscovery();
    await this.pkceFlow("human", this.config!.clientId);
    this.log.info("signed in (human client)");

    const agentClient = this.config!.agentClientId;
    if (agentClient) {
      try {
        await this.pkceFlow("delegate", agentClient);
        this.log.info("agent session established (silent second flow)");
      } catch (err) {
        this.log.warn(`agent-client flow failed (${errText(err)}); agent turns will prompt to sign in again`);
      }
    } else {
      this.log.info("backend advertises no agent client — delegate tokens unavailable");
    }
    this.changed.fire();
  }

  async signOut(): Promise<void> {
    for (const timer of this.refreshTimers.values()) {
      clearTimeout(timer);
    }
    this.refreshTimers.clear();
    this.tokens.clear();
    for (const key of Object.values(REFRESH_TOKEN_KEYS)) {
      await this.secrets.delete(key);
    }
    this.log.info("signed out");
    this.changed.fire();
  }

  /**
   * A currently-valid access token of the given kind, refreshing if within
   * the skew window (or unconditionally when force — the 401 backstop).
   * Throws if that side is not signed in or the refresh fails — callers
   * surface that as a signed-out state, never a silent unauthenticated
   * request.
   */
  async token(kind: TokenKind = "human", force = false): Promise<string> {
    const set = this.tokens.get(kind);
    if (!set) {
      throw new Error(kind === "delegate"
        ? "no agent session — sign in again to establish it"
        : "not signed in");
    }
    if (force || Date.now() >= set.expiresAt - REFRESH_SKEW_MS) {
      const clientId = this.clientIdFor(kind);
      if (!clientId) {
        throw new Error(`no ${kind} client configured`);
      }
      await this.grant(kind, new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: set.refreshToken,
      }));
    }
    return this.tokens.get(kind)!.accessToken;
  }

  dispose(): void {
    for (const timer of this.refreshTimers.values()) {
      clearTimeout(timer);
    }
    this.changed.dispose();
  }

  // --- internals ------------------------------------------------------------

  private clientIdFor(kind: TokenKind): string | undefined {
    return kind === "human" ? this.config?.clientId : this.config?.agentClientId;
  }

  private async ensureDiscovery(): Promise<void> {
    if (this.endpoints && this.config) {
      return;
    }
    this.config = await this.loadAuthConfig();
    const wellKnown = `${trimSlash(this.config.issuer)}/.well-known/openid-configuration`;
    const res = await fetch(wellKnown, { signal: AbortSignal.timeout(5_000) });
    if (!res.ok) {
      throw new Error(`OIDC discovery ${res.status} at ${wellKnown}`);
    }
    const doc = (await res.json()) as {
      authorization_endpoint?: string;
      token_endpoint?: string;
    };
    if (!doc.authorization_endpoint || !doc.token_endpoint) {
      throw new Error("OIDC discovery missing authorization/token endpoint");
    }
    this.endpoints = { authorization: doc.authorization_endpoint, token: doc.token_endpoint };
  }

  /** One full PKCE authorization-code flow against the given client. */
  private async pkceFlow(kind: TokenKind, clientId: string): Promise<void> {
    const verifier = base64url(crypto.randomBytes(32));
    const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
    const state = base64url(crypto.randomBytes(16));

    const { code, redirectUri } = await this.captureAuthCode(clientId, challenge, state);
    await this.grant(kind, new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }));
  }

  /**
   * Open the browser to Keycloak and capture the redirect on a loopback
   * listener. The realm allows http://localhost:* redirect URIs
   * (keycloak_realm.json), so a random loopback port is a valid target. On an
   * existing SSO session (the second, agent-client flow) Keycloak redirects
   * straight back without showing a form.
   */
  private captureAuthCode(
    clientId: string,
    challenge: string,
    state: string,
  ): Promise<{ code: string; redirectUri: string }> {
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        if (url.pathname !== "/callback") {
          res.writeHead(404).end();
          return;
        }
        const returnedState = url.searchParams.get("state");
        const code = url.searchParams.get("code");
        const err = url.searchParams.get("error");
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(
          `<html><body style="font-family:sans-serif;padding:2rem">` +
          `<h2>reckon</h2><p>${err ? "Sign-in failed." : "Signed in. You can close this tab."}</p>` +
          `</body></html>`,
        );
        server.close();
        if (err) {
          reject(new Error(`authorization error: ${err}`));
        } else if (returnedState !== state) {
          reject(new Error("state mismatch (possible CSRF) — sign-in aborted"));
        } else if (!code) {
          reject(new Error("no authorization code in redirect"));
        } else {
          resolve({ code, redirectUri });
        }
      });

      let redirectUri = "";
      server.on("error", reject);
      // Bind the listener to the IPv4 loopback (deterministic), but advertise
      // the redirect as `localhost` — Keycloak matches redirect URIs by exact
      // host string, and the realm allows `http://localhost:*`, not 127.0.0.1
      // (keycloak_realm.json). The browser resolves localhost → 127.0.0.1
      // (directly, or via Happy-Eyeballs fallback), so it still hits this listener.
      server.listen(0, "127.0.0.1", () => {
        const port = (server.address() as AddressInfo).port;
        redirectUri = `http://localhost:${port}/callback`;
        const authUrl = new URL(this.endpoints!.authorization);
        authUrl.searchParams.set("client_id", clientId);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("scope", "openid");
        authUrl.searchParams.set("state", state);
        authUrl.searchParams.set("code_challenge", challenge);
        authUrl.searchParams.set("code_challenge_method", "S256");
        void vscode.env.openExternal(vscode.Uri.parse(authUrl.toString()));
      });

      // Don't leave a dangling listener if the user never completes the flow.
      setTimeout(() => {
        if (server.listening) {
          server.close();
          reject(new Error("sign-in timed out (no redirect within 5 minutes)"));
        }
      }, 5 * 60_000);
    });
  }

  /** POST the token endpoint, store the result under kind, arm its refresh timer. */
  private async grant(kind: TokenKind, form: URLSearchParams): Promise<void> {
    await this.ensureDiscovery();
    const res = await fetch(this.endpoints!.token, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      signal: AbortSignal.timeout(10_000),
    });
    const body = (await res.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
      error?: string;
      error_description?: string;
    };
    if (!res.ok || !body.access_token) {
      throw new Error(`token request ${res.status}: ${body.error_description ?? body.error ?? "no access_token"}`);
    }
    const ttlMs = (body.expires_in && body.expires_in > 0 ? body.expires_in : 60) * 1000;
    this.tokens.set(kind, {
      accessToken: body.access_token,
      refreshToken: body.refresh_token ?? "",
      expiresAt: Date.now() + ttlMs,
    });
    if (body.refresh_token) {
      await this.secrets.store(REFRESH_TOKEN_KEYS[kind], body.refresh_token);
    }
    this.armRefresh(kind, ttlMs);
  }

  private armRefresh(kind: TokenKind, ttlMs: number): void {
    const existing = this.refreshTimers.get(kind);
    if (existing) {
      clearTimeout(existing);
    }
    const delay = Math.max(ttlMs - REFRESH_SKEW_MS, 5_000);
    this.refreshTimers.set(kind, setTimeout(() => {
      const set = this.tokens.get(kind);
      const clientId = this.clientIdFor(kind);
      if (!set || !clientId) {
        return;
      }
      this.grant(kind, new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: set.refreshToken,
      })).catch((err) => {
        this.log.info(`background ${kind} token refresh failed (${errText(err)}); will retry on demand`);
      });
    }, delay));
  }
}

function base64url(b: Buffer): string {
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function trimSlash(s: string): string {
  return s.replace(/\/+$/, "");
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
