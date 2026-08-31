package api

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"go.lumeweb.com/portal-plugin-mcp/internal"
	pluginConfig "go.lumeweb.com/portal-plugin-mcp/internal/config"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	portalMocks "go.lumeweb.com/portal/core/testing/mocks"
)

// The MCP API's default config registers resource URL https://mcp.example.com/mcp
// (the API always builds it as an https URL, see BuildAbsoluteURL) with the
// supported scope "offline_access", so authorized tokens must carry that same
// resource and scope.
const (
	mcpResource = "https://mcp.example.com/mcp"
	mcpScope    = "offline_access"
)

// getMCPAPITestOptions boots the MCP API against a mocked OAuth provider
// service, mirroring the portal-plugin-billing test helper pattern.
func getMCPAPITestOptions() coreTesting.TestContextBuilderOption {
	return coreTesting.CombineOptions(
		coreTesting.WithMockServiceFactory(core.OAUTH_PROVIDER_SERVICE, portalMocks.NewMockOAuthProviderService),
		coreTesting.WithAPIConfig(internal.PluginName, &pluginConfig.APIConfig{}),
		coreTesting.WithDomain("example.com"),
		// The API's startup registers the MCP resource on the OAuth provider,
		// so the expectation must be in place before startup runs (context.go
		// starts services after all options have been applied).
		func(ctx coreTesting.TestContext) (coreTesting.TestContext, error) {
			mockHTTPSvc := coreTesting.GetMockHTTPService(ctx)
			mockHTTPSvc.EXPECT().APISubdomain(mock.AnythingOfType("string"), mock.AnythingOfType("bool")).
				Return("mcp.example.com").Maybe()
			core.GetService[*portalMocks.MockOAuthProviderService](ctx, core.OAUTH_PROVIDER_SERVICE).
				EXPECT().RegisterResource(mock.Anything, mock.Anything).Return(nil).Maybe()
			return ctx, nil
		},
		coreTesting.WithAPI(internal.PluginName, NewAPI),
		coreTesting.WithAPIID(internal.PluginName),
		coreTesting.WithPlugins(),
	)
}

// getOAuthExtensionTestOptions boots the dashboard API extension against a
// mocked OAuth provider service and the default mock auth service, mirroring
// the portal-plugin-billing test helper pattern.
func getOAuthExtensionTestOptions() coreTesting.TestContextBuilderOption {
	return coreTesting.CombineOptions(
		coreTesting.WithMockServiceFactory(core.OAUTH_PROVIDER_SERVICE, portalMocks.NewMockOAuthProviderService),
		coreTesting.WithDomain("example.com"),
		func(ctx coreTesting.TestContext) (coreTesting.TestContext, error) {
			mockHTTPSvc := coreTesting.GetMockHTTPService(ctx)
			mockHTTPSvc.EXPECT().APISubdomain(mock.AnythingOfType("string"), mock.AnythingOfType("bool")).
				Return("dashboard.example.com").Maybe()
			return ctx, nil
		},
		coreTesting.WithAPIExtension(NewOAuthExtension()),
	)
}

// mcpOAuth returns the mocked OAuth provider service for the MCP API tests.
func mcpOAuth(ctx coreTesting.TestContext) *portalMocks.MockOAuthProviderService {
	return core.GetService[*portalMocks.MockOAuthProviderService](ctx, core.OAUTH_PROVIDER_SERVICE)
}

// oauthExt returns the mocked OAuth provider service for the OAuth extension
// tests.
func oauthExt(ctx coreTesting.TestContext) *portalMocks.MockOAuthProviderService {
	return core.GetService[*portalMocks.MockOAuthProviderService](ctx, core.OAUTH_PROVIDER_SERVICE)
}

// request performs an API request against the test router and returns the
// response recorder.
func request(t *testing.T, ctx coreTesting.TestContext, method, path string, body []byte) *httptest.ResponseRecorder {
	req := ctx.NewAPIRequest(method, path, body)
	rec := httptest.NewRecorder()
	ctx.Router().ServeHTTP(rec, req)
	return rec
}
