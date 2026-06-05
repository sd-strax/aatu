package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// ctxKey is a private type for context.WithValue keys so other packages
// can't accidentally collide with ours.
type ctxKey int

const claimsCtxKey ctxKey = 0

// FromContext returns the Claims attached to the request context by the
// auth middleware, or false if the request did not pass through it.
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey).(Claims)
	return c, ok
}

// WithClaims returns a copy of ctx carrying the given Claims. Tests use
// this directly to bypass the middleware; production code goes through
// RequireAuth.
func WithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey, c)
}

// RequireAuth is HTTP middleware that requires a valid bearer token. On
// failure it writes a JSON error body and an appropriate status:
//
//   - 401 Unauthorized: missing or malformed Authorization header,
//     signature failure, expired token.
//
// On success the request is forwarded with Claims attached to the context;
// downstream handlers retrieve them via FromContext.
func RequireAuth(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing or malformed Authorization header (expected `Bearer <token>`)")
				return
			}
			claims, err := v.Verify(r.Context(), raw)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}
			r = r.WithContext(WithClaims(r.Context(), claims))
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole is HTTP middleware that gates access on the principal
// holding at least one of the named roles. Must be composed AFTER
// RequireAuth (which attaches Claims to the context). Returns 403 with the
// missing-role list surfaced.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := FromContext(r.Context())
			if !ok {
				// Defensive: indicates RequireAuth isn't composed ahead of
				// RequireRole. This is a wiring bug, not a user error.
				writeAuthError(w, http.StatusInternalServerError,
					"authorization wiring error: RequireRole used without RequireAuth")
				return
			}
			if !claims.HasAnyRole(roles...) {
				writeAuthErrorWithRoles(w, http.StatusForbidden,
					"required role(s) missing", roles)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerToken extracts the token from a `Bearer <token>` Authorization
// header. Returns ("", false) if absent or malformed.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// writeAuthError renders a JSON error body matching the auth scheme
// downstream callers expect. Keeps the contract simple: { error: string }.
func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

// writeAuthErrorWithRoles surfaces the missing-role list — the A.5 done-bar
// explicitly asks for the missing role to be visible in 403 responses.
func writeAuthErrorWithRoles(w http.ResponseWriter, status int, msg string, requiredRoles []string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":          msg,
		"required_roles": requiredRoles,
		"required_any":   true,
	})
}
