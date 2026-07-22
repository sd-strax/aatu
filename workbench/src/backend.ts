// Thin client for the reckon backend's public HTTP surface.
//
// Mirrors server.StatusResponse (server/backend.go). The design/13 §2 version
// handshake (extension asserts a compatible backend version, fails closed on
// mismatch) needs /status to carry a version field first — a backend addition
// that lands with the session/auth step of the v0 slice.

/** Mirrors server.ComponentStatus. */
export interface ComponentStatus {
  ready: boolean;
  message: string;
}

/** Mirrors server.StatusResponse, plus reachability. */
export interface BackendStatus {
  reachable: boolean;
  overall: string;
  components: Record<string, ComponentStatus>;
}

export class BackendClient {
  /** baseUrl is read per-call so a settings change needs no reload. */
  constructor(private readonly baseUrl: () => string) {}

  async status(): Promise<BackendStatus> {
    try {
      const res = await fetch(`${this.baseUrl()}/status`, {
        signal: AbortSignal.timeout(3_000),
      });
      const body = (await res.json()) as { overall?: string; components?: Record<string, ComponentStatus> };
      return {
        reachable: true,
        overall: body.overall ?? "unknown",
        components: body.components ?? {},
      };
    } catch {
      return { reachable: false, overall: "unreachable", components: {} };
    }
  }
}
