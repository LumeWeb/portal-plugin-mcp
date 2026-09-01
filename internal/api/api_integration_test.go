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

// TestMCPProtectedResourceMetadataResourcePath guards the resource-path alias
// of the RFC 9728 metadata: /.well-known/oauth-protected-resource/mcp (which
// mirrors the /mcp server path) must serve the identical document as the root
// PRM endpoint, since some clients resolve the resource identifier under the
// resource path's directory.
func TestMCPProtectedResourceMetadataResourcePath(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		mcpOAuth(ctx).EXPECT().ProtectedResourceMetadata(mock.Anything, mock.Anything).
			Return(&oauth.ProtectedResourceMetadata{
				Resource:             "https://mcp.example.com/mcp",
				ScopesSupported:      []string{"offline_access"},
				AuthorizationServers: []string{"https://dashboard.example.com"},
			}, nil)

		rec := request(t, ctx, http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
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

func TestMCPRootServesHomepage(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		rec := request(t, ctx, http.MethodGet, "/", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
		body := rec.Body.String()
		// The landing page must point users at the MCP resource path and render
		// the endpoint URL, not redirect.
		require.Contains(t, body, mcpResource)
		require.Contains(t, body, "/mcp")
		// The setup wizard must be present with its client tabs, the endpoint
		// to copy, and the domain clients ask users to allowlist.
		require.Contains(t, body, "Choose your assistant")
		require.Contains(t, body, "Grok")
		require.Contains(t, body, "Claude")
		require.Contains(t, body, "ChatGPT")
		require.Contains(t, body, "mcp.example.com")
		// The wizard supports nested sub-steps and the copy ships them.
		require.Contains(t, body, "subSteps")
		require.Contains(t, body, "allowed domains")

		// The page loads the embedded Handlebars runtime and the Handlebars
		// templates are injected verbatim (Go must not have re-parsed their
		// {{ }} actions).
		require.Contains(t, body, `<script src="/static/handlebars.min.js"></script>`)
		require.Contains(t, body, `id="tpl-step-body"`)
		require.Contains(t, body, `{{#if detail}}`)

		// The injected wizard payload must be valid JSON (regression: placeholders
		// previously added unbalanced quotes and broke JSON.parse client-side).
		const startMarker = `<script id="mcp-wizard-data" type="application/json">`
		const endMarker = "</script>"
		start := strings.Index(body, startMarker)
		require.GreaterOrEqual(t, start, 0)
		remainder := body[start+len(startMarker):]
		end := strings.Index(remainder, endMarker)
		require.GreaterOrEqual(t, end, 0)
		wizardJSON := remainder[:end]
		require.True(t, json.Valid([]byte(wizardJSON)), "wizard JSON must parse")

		// The wizard must check for the Handlebars runtime before using it, so a
		// failed /static/handlebars.min.js load degrades to a visible fallback
		// message instead of throwing a ReferenceError after the JSON guard
		// already passed (regression from Kody review round 2).
		require.Contains(t, body, `typeof Handlebars === "undefined"`)
	}, getMCPAPITestOptions())
}

func TestMCPStaticServesHandlebars(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		rec := request(t, ctx, http.MethodGet, "/static/handlebars.min.js", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Header().Get("Content-Type"), "javascript")
		require.Contains(t, rec.Body.String(), "Handlebars")
	}, getMCPAPITestOptions())
}

func TestMCPEndpointUnauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		rec := request(t, ctx, http.MethodPost, "/mcp", []byte(`{}`))
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
		// The bearer challenge must keep advertising the root PRM URL (not the
		// resource-path alias), so unauthenticated clients always discover the
		// metadata from the canonical location.
		require.Contains(t, rec.Header().Get("WWW-Authenticate"),
			`resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`)
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
