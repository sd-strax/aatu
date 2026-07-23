// Thin client for the reckon backend's public HTTP surface.
//
// Mirrors server.StatusResponse (server/backend.go), including the API contract
// version that drives the design/13 §2 handshake: the extension pins a set of
// backend API versions it supports and fails closed with a diagnostic on
// mismatch, rather than dispatching against an incompatible surface.

/**
 * SUPPORTED_API_VERSIONS is the set of backend API contract versions
 * (server.APIVersion) this build of the workbench speaks. Add a version here
 * when the extension is updated to handle a new backend contract; a backend
 * outside this set is a hard, diagnosable incompatibility — never a silent
 * best-effort call.
 */
export const SUPPORTED_API_VERSIONS: readonly number[] = [1];

/** Mirrors server.ComponentStatus. */
export interface ComponentStatus {
  ready: boolean;
  message: string;
}

/** Mirrors server.StatusResponse, plus reachability and derived compatibility. */
export interface BackendStatus {
  reachable: boolean;
  overall: string;
  components: Record<string, ComponentStatus>;
  /** Backend's advertised API version, or null if it predates the field. */
  apiVersion: number | null;
  /** True only when reachable AND apiVersion is in SUPPORTED_API_VERSIONS. */
  compatible: boolean;
}

/** Login config from GET /api/auth-config (mirrors server.AuthConfigResponse). */
export interface AuthConfig {
  issuer: string;
  clientId: string;
}

/** Mirrors server.MeResponse (the fields the UI uses). */
export interface Me {
  subject: string;
  username: string;
  tenantId: string;
  roles: string[];
}

/** One investigation summary row (subset of the /api/investigations item). */
export interface InvestigationSummary {
  id: string;
  title: string;
  state: string;
}

/** Raw server.InvestigationView row, as served under {investigations: [...]}. */
interface RawInvestigation {
  aggregate_id: string;
  title: string;
  status: string;
}

export class BackendClient {
  /**
   * @param baseUrl read per-call so a settings change needs no reload.
   * @param token   supplies a bearer token for authenticated calls; omitted for
   *                the public /status and /auth-config probes.
   */
  constructor(
    private readonly baseUrl: () => string,
    private readonly token?: () => Promise<string>,
  ) {}

  async status(): Promise<BackendStatus> {
    try {
      const res = await fetch(`${this.baseUrl()}/status`, {
        signal: AbortSignal.timeout(3_000),
      });
      const body = (await res.json()) as {
        overall?: string;
        components?: Record<string, ComponentStatus>;
        api_version?: number;
      };
      const apiVersion = typeof body.api_version === "number" ? body.api_version : null;
      return {
        reachable: true,
        overall: body.overall ?? "unknown",
        components: body.components ?? {},
        apiVersion,
        compatible: apiVersion !== null && SUPPORTED_API_VERSIONS.includes(apiVersion),
      };
    } catch {
      return {
        reachable: false,
        overall: "unreachable",
        components: {},
        apiVersion: null,
        compatible: false,
      };
    }
  }

  /** GET /api/auth-config — public; the login prerequisites. Throws on 503/unreachable. */
  async authConfig(): Promise<AuthConfig> {
    const res = await fetch(`${this.baseUrl()}/api/auth-config`, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) {
      throw new Error(`auth-config ${res.status} (interactive login may be unconfigured)`);
    }
    const body = (await res.json()) as { issuer?: string; client_id?: string };
    if (!body.issuer || !body.client_id) {
      throw new Error("auth-config missing issuer/client_id");
    }
    return { issuer: body.issuer, clientId: body.client_id };
  }

  /** GET /api/me — the signed-in identity. Authenticated. */
  async me(): Promise<Me> {
    const body = await this.authedGet<{
      subject?: string;
      preferred_username?: string;
      tenant_id?: string;
      roles?: string[];
    }>("/api/me");
    return {
      subject: body.subject ?? "",
      username: body.preferred_username ?? "",
      tenantId: body.tenant_id ?? "",
      roles: body.roles ?? [],
    };
  }

  /** GET /api/capabilities — count of resolvable verbs. Authenticated. */
  async capabilityCount(): Promise<number> {
    const body = await this.authedGet<{ capabilities?: unknown[] } | unknown[]>("/api/capabilities");
    if (Array.isArray(body)) {
      return body.length;
    }
    return body.capabilities?.length ?? 0;
  }

  /** GET /api/investigations — the investigation list (server.InvestigationView). Authenticated. */
  async investigations(): Promise<InvestigationSummary[]> {
    const body = await this.authedGet<{ investigations?: RawInvestigation[] }>("/api/investigations");
    return (body.investigations ?? []).map((r) => ({
      id: r.aggregate_id,
      title: r.title || "(untitled)",
      state: r.status,
    }));
  }

  private async authedGet<T>(path: string): Promise<T> {
    if (!this.token) {
      throw new Error("no token source configured");
    }
    const bearer = await this.token();
    const res = await fetch(`${this.baseUrl()}${path}`, {
      headers: { Authorization: `Bearer ${bearer}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      throw new Error(`GET ${path} → ${res.status}`);
    }
    return (await res.json()) as T;
  }

  /** A one-line diagnostic for an incompatible/unreachable backend, or null when compatible. */
  incompatibilityReason(status: BackendStatus): string | null {
    if (!status.reachable) {
      return "backend not reachable — run `reckon start`";
    }
    if (status.apiVersion === null) {
      return "backend predates the version handshake — upgrade the backend";
    }
    if (!status.compatible) {
      return `backend API v${status.apiVersion} unsupported (this workbench speaks v${SUPPORTED_API_VERSIONS.join(", v")}) — align versions`;
    }
    return null;
  }
}
