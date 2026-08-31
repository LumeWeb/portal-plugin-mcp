package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-mcp/internal/testing/mocks"
)

func passthrough() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestMiddlewareProtect_NilServiceDenies(t *testing.T) {
	mw := NewMiddleware(nil, "https://mcp.example.com")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	auth := rec.Header().Get("WWW-Authenticate")
	require.Contains(t, auth, `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`)
	require.Contains(t, auth, `error="invalid_token"`)
}

func TestMiddlewareProtect_ValidTokenPassesThrough(t *testing.T) {
	oauthSvc := mocks.NewMockOAuthProviderService(t)
	oauthSvc.EXPECT().ValidateAccessToken(mock.Anything, "valid-token").
		Return(uint(7), time.Now().Add(time.Hour), true)

	mw := NewMiddleware(oauthSvc, "https://mcp.example.com")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

func TestMiddlewareProtect_InvalidTokenChallenges(t *testing.T) {
	oauthSvc := mocks.NewMockOAuthProviderService(t)
	oauthSvc.EXPECT().ValidateAccessToken(mock.Anything, "expired-token").
		Return(uint(0), time.Time{}, false)

	mw := NewMiddleware(oauthSvc, "https://mcp.example.com")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer expired-token")

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	auth := rec.Header().Get("WWW-Authenticate")
	require.Contains(t, strings.ToLower(auth), "bearer")
	require.Contains(t, strings.ToLower(auth), "error=\"invalid_token\"")
	require.Contains(t, auth, `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`)
}

func TestMiddlewareProtect_MissingTokenChallenges(t *testing.T) {
	oauthSvc := mocks.NewMockOAuthProviderService(t)

	mw := NewMiddleware(oauthSvc, "https://mcp.example.com")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
}

func TestTokenPrincipalDeterministic(t *testing.T) {
	a := tokenPrincipal("token-1")
	b := tokenPrincipal("token-1")
	c := tokenPrincipal("token-2")
	require.Equal(t, a, b)
	require.NotEqual(t, a, c)
	require.Len(t, a, 64) // sha256 hex
}

func TestIsOAuthBearerFailure(t *testing.T) {
	h := http.Header{}
	require.False(t, isOAuthBearerFailure(h))

	h.Set("WWW-Authenticate", `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", error="invalid_token"`)
	require.True(t, isOAuthBearerFailure(h))

	h.Set("WWW-Authenticate", `Bearer realm="none"`)
	require.False(t, isOAuthBearerFailure(h))
}

func TestDenyWritesChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	deny(rec, "https://mcp.example.com/.well-known/oauth-protected-resource", "the OAuth provider is not enabled")

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	require.Contains(t, rec.Body.String(), `"error":"invalid_token"`)
}
