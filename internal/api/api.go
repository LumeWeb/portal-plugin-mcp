package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-plugin-mcp/internal"
	pluginConfig "go.lumeweb.com/portal-plugin-mcp/internal/config"
	"go.lumeweb.com/portal-plugin-mcp/internal/mcp"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	portalservice "go.lumeweb.com/portal/service"
	"go.uber.org/zap"
)

var _ core.API = (*API)(nil)

// API is the MCP API. It serves the MCP streamable-HTTP endpoint and OAuth
// discovery metadata on the "mcp" subdomain. The MCP endpoint is gated behind
// OAuth bearer-token validation backed by the portal's OAuth provider service,
// so only authorized MCP clients can reach it.
type API struct {
	*core.BaseComponent
	oauthSvc core.OAuthProviderService
	server   *mcp.Server

	// baseURL is the public URL of the MCP API (e.g. https://mcp.example.com).
	baseURL string
	// resourceURL is the canonical URI of the MCP server resource
	// (e.g. https://mcp.example.com/mcp), registered with the OAuth provider.
	resourceURL string
	// resourcePath is the MCP streamable-HTTP endpoint path (default /mcp).
	resourcePath string
	// scopes are the scopes this MCP server supports.
	scopes []string
}

func (a *API) ID() string            { return a.Name() }
func (a *API) Name() string          { return internal.PluginName }
func (a *API) Subdomain() string     { return internal.PluginName }
func (a *API) AuthTokenName() string { return internal.PluginName }

func (a *API) OpenAPIInfo() router.APIInfoDefinition {
	return router.APIInfo().
		Title("MCP API").
		Description("Model Context Protocol endpoints exposed from the portal.")
}

func (a *API) GetConfig() config.APIConfig {
	return &pluginConfig.APIConfig{}
}

func NewAPI() (core.API, []core.ContextBuilderOption, error) {
	api := &API{}

	opts := core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)

			cfg := ctx.Config().GetAPI(internal.PluginName).(*pluginConfig.APIConfig)
			api.resourcePath = cfg.ResourcePath
			if api.resourcePath == "" {
				api.resourcePath = "/mcp"
			}
			api.scopes = cfg.Scopes

			baseURL := httpSvc.APISubdomain(api.Name(), true)
			if baseURL == "" {
				// Fall back to the root domain when the MCP subdomain cannot be
				// resolved in tests or single-host deployments.
				baseURL = ctx.Config().Config().Core.Domain
			}
			api.baseURL = baseURL
			api.resourceURL = baseURL + api.resourcePath

			// GetService fails fast (Fatal) when the service is missing.
			api.oauthSvc = core.GetService[core.OAuthProviderService](ctx, core.OAUTH_PROVIDER_SERVICE)

			// Register this MCP server as a protected resource so the OAuth
			// provider can issue tokens for it (RFC 8707) and serve its
			// RFC 9728 protected-resource metadata.
			if err := api.oauthSvc.RegisterResource(ctx, core.OAuthProtectedResource{
				ResourceURL: api.resourceURL,
				Scopes:      api.scopes,
				DisplayName: "Portal MCP Server",
			}); err != nil {
				// MCP is unusable without OAuth. When the provider is disabled
				// (oauth.enabled=false) fail closed: skip registration and let
				// the OAuth middleware deny all MCP requests, rather than taking
				// down the whole portal.
				if errors.Is(err, portalservice.ErrOAuthDisabled) {
					ctx.Logger().Warn("mcp: oauth provider disabled; MCP endpoint unavailable",
						zap.Error(err))
					return nil
				}
				return fmt.Errorf("mcp: register resource: %w", err)
			}

			return nil
		}),
	)

	return api, opts, nil
}

func (a *API) Configure(gRouter router.Router, accessSvc core.AccessService) error {
	a.server = mcp.NewServer(nil)

	handler := mcp.NewMiddleware(a.oauthSvc, a.baseURL).Protect(mcp.NewStreamableHandler(a.server))

	echoRouter := router.GetRouter(gRouter)
	if echoRouter == nil {
		return fmt.Errorf("mcp: underlying echo router is nil")
	}

	// The MCP streamable-HTTP endpoint accepts GET and POST on the same path.
	echoRouter.Any(a.resourcePath, echo.WrapHandler(handler))

	// RFC 9728 protected-resource metadata; MCP clients discover the
	// authorization server from this document. The RFC 8414 authorization-
	// server metadata is served by the dashboard API extension at the issuer
	// URL.
	echoRouter.GET("/.well-known/oauth-protected-resource", echo.WrapHandler(a.protectedResourceHandler()))

	echoRouter.GET("/healthz", echo.WrapHandler(http.HandlerFunc(healthzHandler)))

	return nil
}

// protectedResourceHandler returns RFC 9728 protected-resource metadata for
// the MCP server, delegating to the OAuth provider service.
func (a *API) protectedResourceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta, err := a.oauthSvc.ProtectedResourceMetadata(r.Context(), a.resourceURL)
		if err != nil {
			writeServerError(w)
			return
		}
		writeJSON(w, http.StatusOK, meta)
	})
}
