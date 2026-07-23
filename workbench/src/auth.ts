// Interactive human login for the workbench (design/13 §7 step 1, 05 §3.4).
//
// OIDC authorization-code + PKCE against the bundled Keycloak. The extension
// never sees a password: it opens the browser to Keycloak, catches the redirect
// on a loopback listener, and exchanges the code (+ PKCE verifier) for tokens.
// Tokens live in vscode.SecretStorage — never in settings, never on disk in the
// clear. A background timer refreshes before expiry; a 401 forces a refresh.
//
// The issuer + client are discovered from the backend's /api/auth-config, so
// nothing here hardcodes Keycloak's port, realm, or client id.

import * as crypto from "crypto";
import * as http from "http";
import { AddressInfo } from "net";
import * as vscode from "vscode";

/** Where the persisted refresh token lives in SecretStorage. */
const REFRESH_TOKEN_KEY = "reckon.refreshToken";

/** Renew this many ms before the access token's expiry (matches agent/auth.go). */
const REFRESH_SKEW_MS = 30_000;

interface AuthConfig {
  issuer: string;
  clientId: string;
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
 * Session owns the human's tokens and their lifecycle. It exposes a single
 * `token()` accessor that always returns a currently-valid access token
 * (refreshing silently when near expiry), mirroring agent.TokenSource on the
 * Go side. `onDidChange` fires whenever signed-in state flips so the UI can
 * re-render.
 */
export class Session {
  private tokens: TokenSet | null = null;
  private endpoints: OidcEndpoints | null = null;
  private config: AuthConfig | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | undefined;

  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changed.event;

  constructor(
    private readonly secrets: vscode.SecretStorage,
    private readonly loadAuthConfig: () => Promise<AuthConfig>,
    private readonly log: vscode.LogOutputChannel,
  ) {}

  get signedIn(): boolean {
    return this.tokens !== null;
  }

  /**
   * Attempt a silent restore from a persisted refresh token. Safe to call on
   * activation — a failure (expired/revoked refresh token, backend down) just
   * leaves the session signed out.
   */
  async restore(): Promise<void> {
    const refreshToken = await this.secrets.get(REFRESH_TOKEN_KEY);
    if (!refreshToken) {
      return;
    }
    try {
      await this.ensureDiscovery();
      await this.grant(new URLSearchParams({
        grant_type: "refresh_token",
        client_id: this.config!.clientId,
        refresh_token: refreshToken,
      }));
      this.log.info("session restored from stored refresh token");
      this.changed.fire();
    } catch (err) {
      this.log.info(`session restore failed (${errText(err)}); signed out`);
      await this.secrets.delete(REFRESH_TOKEN_KEY);
      this.tokens = null;
    }
  }

  /** Run the interactive PKCE login. Resolves signed-in, throws on failure/cancel. */
  async signIn(): Promise<void> {
    await this.ensureDiscovery();
    const verifier = base64url(crypto.randomBytes(32));
    const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
    const state = base64url(crypto.randomBytes(16));

    const { code, redirectUri } = await this.captureAuthCode(challenge, state);
    await this.grant(new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config!.clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }));
    this.log.info("signed in");
    this.changed.fire();
  }

  async signOut(): Promise<void> {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    this.tokens = null;
    await this.secrets.delete(REFRESH_TOKEN_KEY);
    this.log.info("signed out");
    this.changed.fire();
  }

  /**
   * A currently-valid access token, refreshing if within the skew window.
   * Throws if not signed in or the refresh fails — callers surface that as a
   * signed-out state, never a silent unauthenticated request.
   */
  async token(): Promise<string> {
    if (!this.tokens) {
      throw new Error("not signed in");
    }
    if (Date.now() >= this.tokens.expiresAt - REFRESH_SKEW_MS) {
      await this.grant(new URLSearchParams({
        grant_type: "refresh_token",
        client_id: this.config!.clientId,
        refresh_token: this.tokens.refreshToken,
      }));
    }
    return this.tokens.accessToken;
  }

  dispose(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    this.changed.dispose();
  }

  // --- internals ------------------------------------------------------------

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

  /**
   * Open the browser to Keycloak and capture the redirect on a loopback
   * listener. The realm allows http://localhost:* redirect URIs
   * (keycloak_realm.json), so a random loopback port is a valid target.
   */
  private captureAuthCode(challenge: string, state: string): Promise<{ code: string; redirectUri: string }> {
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
      server.listen(0, "127.0.0.1", () => {
        const port = (server.address() as AddressInfo).port;
        redirectUri = `http://127.0.0.1:${port}/callback`;
        const authUrl = new URL(this.endpoints!.authorization);
        authUrl.searchParams.set("client_id", this.config!.clientId);
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

  /** POST the token endpoint, store the result, arm the refresh timer. */
  private async grant(form: URLSearchParams): Promise<void> {
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
    this.tokens = {
      accessToken: body.access_token,
      refreshToken: body.refresh_token ?? "",
      expiresAt: Date.now() + ttlMs,
    };
    if (body.refresh_token) {
      await this.secrets.store(REFRESH_TOKEN_KEY, body.refresh_token);
    }
    this.armRefresh(ttlMs);
  }

  private armRefresh(ttlMs: number): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    const delay = Math.max(ttlMs - REFRESH_SKEW_MS, 5_000);
    this.refreshTimer = setTimeout(() => {
      if (!this.tokens) {
        return;
      }
      this.grant(new URLSearchParams({
        grant_type: "refresh_token",
        client_id: this.config!.clientId,
        refresh_token: this.tokens.refreshToken,
      })).catch((err) => {
        this.log.info(`background token refresh failed (${errText(err)}); will retry on demand`);
      });
    }, delay);
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
