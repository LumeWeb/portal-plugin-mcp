package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/oauth"
	portalMocks "go.lumeweb.com/portal/core/testing/mocks"
)

const (
	testBaseURL    = "https://mcp.example.com"
	testResource   = "https://mcp.example.com/mcp"
	testScope      = "mcp offline_access"
	testExpiry     = 1 * time.Hour
)

func passthrough() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func validToken(userID uint, resource, scope string, ok bool) oauth.ValidatedToken {
	vt := oauth.ValidatedToken{
		UserID:   userID,
		Expiry:   time.Now().Add(testExpiry),
		Resource: resource,
		ClientID: "client_test",
		Scope:    scope,
	}
	if !ok {
		vt.Expiry = time.Time{}
		vt.Resource = ""
	}
	return vt
}

func TestMiddlewareProtect_NilServiceDenies(t *testing.T) {
	mw := NewMiddleware(nil, testBaseURL, testResource, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	auth := rec.Header().Get("WWW-Authenticate")
	require.Contains(t, auth, `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`)
	require.Contains(t, auth, `error="invalid_token"`)
}

func TestMiddlewareProtect_ValidTokenPassesThrough(t *testing.T) {
	oauthSvc := portalMocks.NewMockOAuthProviderService(t)
	oauthSvc.EXPECT().ValidateAccessTokenInfo(mock.Anything, "valid-token").
		Return(validToken(7, testResource, testScope, true), true)

	mw := NewMiddleware(oauthSvc, testBaseURL, testResource, []string{"mcp", "offline_access"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

func TestMiddlewareProtect_WrongResourceChallenges(t *testing.T) {
	// Token minted for a sibling resource must not be accepted (RFC 8707
	// audience binding), even though it is otherwise valid and unexpired.
	oauthSvc := portalMocks.NewMockOAuthProviderService(t)
	oauthSvc.EXPECT().ValidateAccessTokenInfo(mock.Anything, "other-resource-token").
		Return(validToken(7, "https://sibling.example.com/api", testScope, true), true)

	mw := NewMiddleware(oauthSvc, testBaseURL, testResource, []string{"mcp", "offline_access"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer other-resource-token")

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, strings.ToLower(rec.Header().Get("WWW-Authenticate")), "error=\"invalid_token\"")
}

func TestMiddlewareProtect_MissingScopeRejects(t *testing.T) {
	// Correct resource but token grants only "offline_access", not the required
	// "mcp" scope: the SDK's scope check returns 403 insufficient_scope.
	oauthSvc := portalMocks.NewMockOAuthProviderService(t)
	oauthSvc.EXPECT().ValidateAccessTokenInfo(mock.Anything, "under-scoped-token").
		Return(validToken(7, testResource, "offline_access", true), true)

	mw := NewMiddleware(oauthSvc, testBaseURL, testResource, []string{"mcp", "offline_access"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer under-scoped-token")

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestMiddlewareProtect_InvalidTokenChallenges(t *testing.T) {
	oauthSvc := portalMocks.NewMockOAuthProviderService(t)
	oauthSvc.EXPECT().ValidateAccessTokenInfo(mock.Anything, "expired-token").
		Return(validToken(0, "", "", false), false)

	mw := NewMiddleware(oauthSvc, testBaseURL, testResource, nil)
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
	oauthSvc := portalMocks.NewMockOAuthProviderService(t)

	mw := NewMiddleware(oauthSvc, testBaseURL, testResource, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)

	mw.Protect(passthrough()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
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
