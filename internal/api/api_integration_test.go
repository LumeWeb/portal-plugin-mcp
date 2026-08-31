package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/oauth"
	"go.lumeweb.com/portal-plugin-mcp/internal"
	pluginConfig "go.lumeweb.com/portal-plugin-mcp/internal/config"
	"go.lumeweb.com/portal-plugin-mcp/internal/testing/mocks"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

// mcpAPITestOptions boots the MCP API against a mocked OAuth provider service,
// following the portal-plugin-sia API test harness pattern.
var mcpAPITestOptions = coreTesting.CombineOptions(
	coreTesting.WithMockServiceFactory(core.OAUTH_PROVIDER_SERVICE, mocks.NewMockOAuthProviderService),
	coreTesting.WithAPIConfig(internal.PluginName, &pluginConfig.APIConfig{}),
	coreTesting.WithDomain("example.com"),
	// The API's startup registers the MCP resource on the OAuth provider, so
	// the expectation must be in place before startup runs (context.go starts
	// services after all options have been applied).
	func(ctx coreTesting.TestContext) (coreTesting.TestContext, error) {
		mockHTTPSvc := coreTesting.GetMockHTTPService(ctx)
		mockHTTPSvc.EXPECT().APISubdomain(mock.AnythingOfType("string"), mock.AnythingOfType("bool")).
			Return("https://mcp.example.com").Maybe()
		core.GetService[*mocks.MockOAuthProviderService](ctx, core.OAUTH_PROVIDER_SERVICE).
			EXPECT().RegisterResource(mock.Anything, mock.Anything).Return(nil).Maybe()
		return ctx, nil
	},
	coreTesting.WithAPI(internal.PluginName, NewAPI),
	coreTesting.WithAPIID(internal.PluginName),
	coreTesting.WithPlugins(),
)

func mcpOAuth(ctx coreTesting.TestContext) *mocks.MockOAuthProviderService {
	return core.GetService[*mocks.MockOAuthProviderService](ctx, core.OAUTH_PROVIDER_SERVICE)
}

func request(t *testing.T, ctx coreTesting.TestContext, method, path string, body []byte) *httptest.ResponseRecorder {
	req := ctx.NewAPIRequest(method, path, body)
	rec := httptest.NewRecorder()
	ctx.Router().ServeHTTP(rec, req)
	return rec
}

func TestMCPHealthz(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
				rec := request(t, ctx, http.MethodGet, "/healthz", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, `{"ok":true}`, rec.Body.String())
	}, mcpAPITestOptions)
}

func TestMCPProtectedResourceMetadata(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		mcpOAuth(ctx).EXPECT().ProtectedResourceMetadata(mock.Anything, mock.Anything).
			Return(&oauth.ProtectedResourceMetadata{
				Resource:        "https://mcp.example.com/mcp",
				ScopesSupported: []string{"offline_access"},
				AuthorizationServers: []string{"https://dashboard.example.com"},
			}, nil)

		rec := request(t, ctx, http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Body.String(), "https://mcp.example.com/mcp")
	}, mcpAPITestOptions)
}

func TestMCPEndpointUnauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
				rec := request(t, ctx, http.MethodPost, "/mcp", []byte(`{}`))
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
		require.Contains(t, rec.Header().Get("WWW-Authenticate"), "oauth-protected-resource")
	}, mcpAPITestOptions)
}

func TestMCPEndpointAuthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		mcpOAuth(ctx).EXPECT().ValidateAccessToken(mock.Anything, "valid-token").
			Return(uint(1), time.Now().Add(time.Hour), true)

		req := ctx.NewAPIRequest(http.MethodPost, "/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		// The OAuth gate must pass; the SDK then responds to the (incomplete)
		// initialize request, so anything except a 401 means authorization worked.
		require.NotEqual(t, http.StatusUnauthorized, rec.Code)
		require.Empty(t, rec.Header().Get("WWW-Authenticate"))
	}, mcpAPITestOptions)
}
