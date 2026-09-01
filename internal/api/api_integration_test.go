package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/oauth"
	coreTesting "go.lumeweb.com/portal/core/testing"
	portalservice "go.lumeweb.com/portal/service"
)

// TestMCPEndpointCORSPreflight guards the OPTIONS route that replaced the
// previous echoRouter.Any (which served CORS preflight). Cross-origin browser
// MCP clients send OPTIONS before their POST/GET; without a matching route the
// server would 405 and break them.
func TestMCPEndpointCORSPreflight(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		req := ctx.NewAPIRequest(http.MethodOptions, "/mcp", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		// The shared CORS middleware requires the requested non-simple headers
		// in lexicographic order (what Chromium sends for CORS preflight).
		req.Header.Set("Access-Control-Request-Headers",
			"authorization, content-type, mcp-method, mcp-name, mcp-protocol-version")
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		// The key regression: preflight is answered (204), not 405, and every
		// header a conforming stateless MCP client sends (the MCP protocol
		// headers plus the OAuth bearer Authorization) is allowed.
		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), http.MethodPost)
		require.Equal(t, "http://localhost:5173", rec.Header().Get("Access-Control-Allow-Origin"))
		allowHeaders := strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers"))
		for _, h := range []string{"authorization", "content-type", "mcp-method", "mcp-name", "mcp-protocol-version"} {
			require.Contains(t, allowHeaders, h)
		}
	}, getMCPAPITestOptions())
}

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

func TestMCPProtectedResourceCORS(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		mcpOAuth(ctx).EXPECT().ProtectedResourceMetadata(mock.Anything, mock.Anything).
			Return(&oauth.ProtectedResourceMetadata{Resource: mcpResource}, nil)

		// GET with an Origin reflects the requesting origin back so cross-origin
		// browser MCP clients can read the discovery document.
		req := ctx.NewAPIRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "http://localhost:5173", rec.Header().Get("Access-Control-Allow-Origin"))

		// The OPTIONS preflight is answered (204), never 405, and the discovery
		// method/headers a browser probes are allowed (echoed back).
		pre := ctx.NewAPIRequest(http.MethodOptions, "/.well-known/oauth-protected-resource", nil)
		pre.Header.Set("Origin", "http://localhost:5173")
		pre.Header.Set("Access-Control-Request-Method", http.MethodGet)
		pre.Header.Set("Access-Control-Request-Headers", "accept, mcp-protocol-version")
		preRec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(preRec, pre)
		require.Equal(t, http.StatusNoContent, preRec.Code)
		allowMethods := strings.ToLower(preRec.Header().Get("Access-Control-Allow-Methods"))
		require.Contains(t, allowMethods, "get")
		allowHeaders := strings.ToLower(preRec.Header().Get("Access-Control-Allow-Headers"))
		require.Contains(t, allowHeaders, "accept")
		require.Contains(t, allowHeaders, "mcp-protocol-version")
	}, getMCPAPITestOptions())
}

func TestMCPProtectedResourceMetadataNotRegistered(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		mcpOAuth(ctx).EXPECT().ProtectedResourceMetadata(mock.Anything, mock.Anything).
			Return(nil, portalservice.ErrResourceNotRegistered)

		rec := request(t, ctx, http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		var body map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Equal(t, serverErrorCode, body["error"])
	}, getMCPAPITestOptions())
}

func TestMCPRootRedirectsToResourcePath(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		rec := request(t, ctx, http.MethodGet, "/", nil)
		require.Equal(t, http.StatusPermanentRedirect, rec.Code)
		require.Equal(t, "/mcp", rec.Header().Get("Location"))
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
