package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"go.lumeweb.com/portal/core"
)

// Middleware gates the MCP streamable-HTTP endpoint with OAuth bearer-token
// validation. Tokens are validated in-process against the portal's OAuth
// provider service (core.OAuthProviderService). Unauthenticated or invalid
// requests receive a 401 carrying a full RFC 6750 invalid_token challenge
// pointing at the protected-resource metadata, so OAuth-capable MCP clients
// can discover and complete the authorization flow.
type Middleware struct {
	oauthSvc core.OAuthProviderService
	// baseURL is the MCP API's public base URL (e.g. https://mcp.example.com).
	// The protected-resource metadata is served at
	// baseURL + "/.well-known/oauth-protected-resource".
	baseURL string
}

// NewMiddleware builds an OAuth bearer middleware backed by the portal's
// OAuth provider service.
func NewMiddleware(oauthSvc core.OAuthProviderService, baseURL string) *Middleware {
	return &Middleware{oauthSvc: oauthSvc, baseURL: strings.TrimRight(baseURL, "/")}
}

// Protect wraps the MCP handler so only valid OAuth bearer tokens can proceed.
func (mw *Middleware) Protect(next http.Handler) http.Handler {
	if mw.oauthSvc == nil {
		// OAuth provider disabled or unavailable; deny everything rather than
		// serving MCP without authorization.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			deny(w, mw.metadataURL(), "the OAuth provider is not enabled")
		})
	}

	// TODO: enforce RFC 8707 resource binding (and token scopes) here. The
	// current validation proves only that the token is known and unexpired, not
	// that it was issued for this MCP resource. core.OAuthProviderService only
	// surfaces (userID, expiry, ok), so resource/scope enforcement is tracked
	// as a follow-up that extends the OAuth provider service to return the
	// token's bound resource and granted scopes.
	verifier := func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		_, exp, ok := mw.oauthSvc.ValidateAccessToken(ctx, token)
		if !ok {
			return nil, fmt.Errorf("%w: the access token is unknown or has expired", auth.ErrInvalidToken)
		}
		return &auth.TokenInfo{
			Expiration: exp,
			UserID:     tokenPrincipal(token),
		}, nil
	}
	protected := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: mw.metadataURL(),
		ClockSkew:           2 * time.Minute,
	})(next)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(&oauthChallengeWriter{
			ResponseWriter:   w,
			metadataURL:      mw.metadataURL(),
			errorDescription: "the access token is invalid, expired, or has been revoked",
		}, r)
	})
}

// metadataURL returns the RFC 9728 protected-resource metadata URL served by
// the MCP API.
func (mw *Middleware) metadataURL() string {
	return mw.baseURL + "/.well-known/oauth-protected-resource"
}

// deny writes an RFC 9728 bearer challenge with a full RFC 6750
// error="invalid_token" attributes so MCP clients can refresh or re-authorize.
func deny(w http.ResponseWriter, metadataURL, desc string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer resource_metadata=%q, error="invalid_token", error_description=%q`,
		metadataURL, desc))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_token",
		"error_description": desc,
	})
}

// tokenPrincipal derives a stable, opaque principal from a bearer token so a
// session is bound to a single user without leaking the token's value.
func tokenPrincipal(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// oauthChallengeWriter upgrades the go-sdk's bare bearer-auth 401 into a full
// RFC 6750 invalid_token challenge. The SDK's RequireBearerToken only emits a
// resource_metadata attribute on WWW-Authenticate and a plain-text body. Some
// MCP connectors (notably Grok's rmcp) key off error="invalid_token" to decide
// whether to refresh an access token instead of treating the 401 as fatal, so
// the challenge must carry it. Valid-token requests pass through untouched.
type oauthChallengeWriter struct {
	http.ResponseWriter
	status           int
	metadataURL      string
	errorDescription string
	body             []byte
	upgraded         bool
	wrote            bool
}

// isOAuthBearerFailure reports whether the response is a genuine bearer-auth
// 401 (the go-sdk sets a resource_metadata challenge only when it rejects the
// request) rather than a downstream 401 from a handler.
func isOAuthBearerFailure(h http.Header) bool {
	for _, v := range h.Values("WWW-Authenticate") {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "bearer") && strings.Contains(lower, "resource_metadata=") {
			return true
		}
	}
	return false
}

// Unwrap exposes the wrapped ResponseWriter so http.NewResponseController can
// reach the underlying http.Flusher for SSE streaming behind OAuth.
func (w *oauthChallengeWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *oauthChallengeWriter) WriteHeader(code int) {
	if w.status != 0 {
		return // headers already committed
	}
	w.status = code
	if code == http.StatusUnauthorized && isOAuthBearerFailure(w.Header()) {
		w.upgraded = true
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(
			`Bearer resource_metadata=%q, error="invalid_token", error_description=%q`,
			w.metadataURL, w.errorDescription))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Del("Content-Length")
		if j, err := json.Marshal(map[string]string{
			"error":             "invalid_token",
			"error_description": w.errorDescription,
		}); err == nil {
			w.body = j
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *oauthChallengeWriter) Write(b []byte) (int, error) {
	if w.upgraded {
		if !w.wrote && len(w.body) > 0 {
			w.wrote = true
			return w.ResponseWriter.Write(w.body)
		}
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}
