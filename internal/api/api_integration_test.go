package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/oauth"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestMCPProtectedResourceMetadata(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		mcpOAuth(ctx).EXPECT().ProtectedResourceMetadata(mock.Anything, mock.Anything).
			Return(&oauth.ProtectedResourceMetadata{
				Resource:             "https://mcp.example.com/mcp",
				ScopesSupported:      []string{"offline_access"},
				AuthorizationServers: []string{"https://dashboard.example.com"},
			}, nil)

		rec := request(t, ctx, http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Body.String(), "https://mcp.example.com/mcp")
	}, getMCPAPITestOptions())
}

func TestMCPEndpointUnauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		rec := request(t, ctx, http.MethodPost, "/mcp", []byte(`{}`))
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
		require.Contains(t, rec.Header().Get("WWW-Authenticate"), "oauth-protected-resource")
	}, getMCPAPITestOptions())
}

func TestMCPEndpointAuthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		mcpOAuth(ctx).EXPECT().ValidateAccessTokenInfo(mock.Anything, "valid-token").
			Return(oauth.ValidatedToken{
				UserID:   1,
				Expiry:   time.Now().Add(time.Hour),
				Resource: mcpResource,
				ClientID: "client_test",
				Scope:    mcpScope,
			}, true)

		req := ctx.NewAPIRequest(http.MethodPost, "/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		// The OAuth gate must pass; the SDK then responds to the (incomplete)
		// initialize request, so anything except a 401 means authorization worked.
		require.NotEqual(t, http.StatusUnauthorized, rec.Code)
		require.Empty(t, rec.Header().Get("WWW-Authenticate"))
	}, getMCPAPITestOptions())
}
