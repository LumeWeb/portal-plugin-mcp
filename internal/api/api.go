package api

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/pinner-cli/mcpembed"
	"go.lumeweb.com/portal-middleware/cors"
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

	// baseURL is the public URL of the MCP API (e.g. https://mcp.example.com).
	baseURL string
	// resourceURL is the canonical URI of the MCP server resource
	// (e.g. https://mcp.example.com/mcp), registered with the OAuth provider.
	resourceURL string
	// resourcePath is the MCP streamable-HTTP endpoint path (default /mcp).
	resourcePath string
	// scopes are the scopes this MCP server supports.
	scopes []string

	// portalEndpoint is the portal base domain the hosted operations target
	// (account/ipfs/websites/dns subdomains resolve under it).
	portalEndpoint string
	// secure indicates the API operations use HTTPS.
	secure bool
	// identityKey signs the per-user Portal API JWTs the pinner operations send.
	identityKey ed25519.PrivateKey
	// domain is the portal domain used as the JWT issuer/audience.
	domain string
	// portalName is the portal's display name (core.portal_name), used to label
	// the MCP subdomain landing page. Falls back to the domain when unset.
	portalName string
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

			// The OAuth/MCP flow requires TLS, so the resource URL and the
			// protected-resource metadata URL are always built as https. See
			// BuildAbsoluteURL (mirrors the portal-plugin-billing helper).
			api.baseURL = BuildAbsoluteURL(httpSvc, api.Name(), "", true)
			if api.baseURL == "" {
				// Fall back to the root domain when the MCP subdomain cannot be
				// resolved in tests or single-host deployments.
				api.baseURL = ctx.Config().Config().Core.Domain
			}
			api.resourceURL = api.baseURL + api.resourcePath

			// GetService fails fast (Fatal) when the service is missing.
			api.oauthSvc = core.GetService[core.OAuthProviderService](ctx, core.OAUTH_PROVIDER_SERVICE)

			// The hosted operations call the Portal API's account/ipfs/
			// websites/dns subdomains, which resolve under the portal's base
			// domain. They authenticate with per-user Portal API JWTs, so
			// capture the identity key and domain here.
			coreCfg := ctx.Config().Config().Core
			api.portalEndpoint = coreCfg.Domain
			api.secure = true
			api.identityKey = coreCfg.Identity.PrivateKey()
			api.domain = coreCfg.Domain
			api.portalName = coreCfg.PortalName
			if api.portalName == "" {
				api.portalName = coreCfg.Domain
			}

			return nil
		}),
	)

	return api, opts, nil
}

func (a *API) Configure(gRouter router.Router, accessSvc core.AccessService) error {
	catalogDeps, err := mcpembed.NewCatalogDeps(a.portalEndpoint, a.secure)
	if err != nil {
		return fmt.Errorf("mcp: build catalog deps: %w", err)
	}

	handler, err := mcpembed.New(mcpembed.Options{
		// The hosted surface: account/subscription plus IPFS/websites/dns/ipns/
		// ens/upload operations (never the Sia vault or portal admin).
		Surface:     mcpembed.SurfaceHosted,
		CatalogDeps: catalogDeps,
		// Resolve the OAuth-authenticated caller to a per-user Portal API JWT.
		CredentialResolver: mcp.NewCredentialResolver(a.identityKey, a.domain, 0).WithLogger(a.Logger().Named("mcp.credential")),
		// Reuse the existing OAuth bearer gate as the handler-level OAuth
		// enforcement (RFC 6750/9728 challenges).
		OAuthHandler: mcp.NewMiddleware(a.oauthSvc, a.baseURL, a.resourceURL, a.scopes).WithLogger(a.Logger().Named("mcp.auth")),
		// The handler is served through the portal's router/proxy, which
		// presents a non-loopback Origin; disable the localhost protection.
		DisableLocalhostProtection: true,
		// Point the hosted IPFS byte-route coordinators at the externally
		// reachable MCP resource path so presigned upload PUT and filedrop GET
		// URLs mint against the public subdomain (/mcp/upload/<token>,
		// /mcp/download/<token>) instead of a loopback temp port
		// (127.0.0.1:<random>) a hosted agent cannot reach. The coordinators
		// mount under the same resource path below, so those URLs route back
		// through the portal on the mcp subdomain.
		BaseURL: a.baseURL + a.resourcePath,
	})
	if err != nil {
		return fmt.Errorf("mcp: build hosted server: %w", err)
	}

	// The MCP routes are registered through the portal router so they are
	// tracked by the gswagger stack and appear in /swagger.json, while the
	// handlers still forward into the embedded hosted MCP server. The portal
	// router's default access role is not attached: /mcp enforces its own
	// OAuth bearer gate at the handler level, and the metadata route is
	// public.
	//
	// The MCP streamable-HTTP endpoint accepts GET and POST on the same path.
	// CORS is enabled on every method so cross-origin browser MCP clients can
	// complete the OAuth authorization-code redirect and talk to the server;
	// the OPTIONS route answers CORS preflight (the CORS middleware
	// short-circuits it), which the previous echoRouter.Any used to serve.
	// A bespoke config allows the headers a conforming stateless MCP client is
	// required to send (MCP-Protocol-Version, Mcp-Method, Mcp-Name) plus the
	// bearer Authorization header used by the OAuth gate; the portal default
	// only permits Content-Type and Authorization, which would fail preflight.
	mcpCORS := mcpCORSConfig()
	mcpHandler := echo.WrapHandler(handler)

	// The pinner byte-route coordinators mount their token-gated handlers at
	// /upload/ and /download/ on the embedded mux root (see mcpembed.New).
	// Serve them under the MCP resource path so the presigned URLs the hosted
	// agent mints resolve through the portal on the mcp subdomain; StripPrefix
	// rewrites /mcp/upload/<token> -> /upload/<token> for the mux. The
	// coordinators answer their own CORS (the token-gated routes reflect any
	// Origin and allow the Upload-* preflight headers via transferCORS), so no
	// portal-level CORS config is attached to these routes.
	byteHandler := echo.WrapHandler(http.StripPrefix(a.resourcePath, handler))

	routes := router.DefineRoutes(
		router.NewRoute(http.MethodGet, a.resourcePath, mcpHandler,
			router.WithAccess(""),
			router.WithCors(mcpCORS),
			router.WithSwagger(
				router.WithSummary("MCP streamable HTTP endpoint (GET)"),
				router.WithDescription("Model Context Protocol endpoint backed by the hosted pinner MCP server."),
				router.WithTags("MCP"),
			),
		),
		router.NewRoute(http.MethodPost, a.resourcePath, mcpHandler,
			router.WithAccess(""),
			router.WithCors(mcpCORS),
			router.WithSwagger(
				router.WithSummary("MCP streamable HTTP endpoint (POST)"),
				router.WithDescription("Model Context Protocol endpoint backed by the hosted pinner MCP server."),
				router.WithTags("MCP"),
			),
		),
		// CORS preflight for the /mcp endpoint.
		router.NewRoute(http.MethodOptions, a.resourcePath,
			func(c echo.Context) error { return c.NoContent(http.StatusNoContent) },
			router.WithAccess(""),
			router.WithCors(mcpCORS),
			router.WithSwagger(
				router.WithSummary("MCP streamable HTTP endpoint (CORS preflight)"),
				router.WithDescription("Answers CORS preflight for cross-origin MCP clients."),
				router.WithTags("MCP"),
			),
		),
		// The MCP server's out-of-band IPFS byte routes: the presigned upload
		// PUT (/mcp/upload/<token>) and filedrop GET (/mcp/download/<token>)
		// mount under the resource path (matching the BaseURL they mint against
		// above). They are token-gated (unguessable, expiring, single-use), so
		// like /mcp they carry no portal access role and enforce their own CORS
		// at the handler level via transferCORS — reflecting any Origin and
		// allowing the Upload-* preflight headers a browser PUT needs. The
		// wildcards are scoped to exactly the /upload/ and /download/ prefixes
		// so no other path under the resource path is forwarded to the byte
		// handlers, and the exact /mcp streamable endpoint stays the only OAuth-
		// gated surface on the resource path.
		router.NewRoute(http.MethodPut, a.resourcePath+"/upload/*", byteHandler,
			router.WithAccess(""),
			router.WithSwagger(
				router.WithSummary("MCP presigned upload PUT"),
				router.WithDescription("Streams file bytes to a minted one-time upload endpoint under the MCP resource path."),
				router.WithTags("MCP"),
			),
		),
		// A wrong method on the upload route is answered by the coordinator
		// (405 + Allow: PUT) rather than a router 404, so an upload token never
		// silently resolves to a different surface.
		router.NewRoute(http.MethodGet, a.resourcePath+"/upload/*", byteHandler,
			router.WithAccess(""),
			router.WithSwagger(
				router.WithSummary("MCP presigned upload (method guard)"),
				router.WithDescription("Rejects non-PUT methods on the presigned upload endpoint with 405."),
				router.WithTags("MCP"),
			),
		),
		// CORS preflight for the token-gated upload route; the coordinator
		// answers it with the upload method and header allow-list.
		router.NewRoute(http.MethodOptions, a.resourcePath+"/upload/*", byteHandler,
			router.WithAccess(""),
			router.WithSwagger(
				router.WithSummary("MCP presigned upload (CORS preflight)"),
				router.WithDescription("Answers CORS preflight for the MCP presigned upload byte route."),
				router.WithTags("MCP"),
			),
		),
		router.NewRoute(http.MethodGet, a.resourcePath+"/download/*", byteHandler,
			router.WithAccess(""),
			router.WithSwagger(
				router.WithSummary("MCP filedrop GET"),
				router.WithDescription("Serves a one-time filedrop download under the MCP resource path."),
				router.WithTags("MCP"),
			),
		),
		// CORS preflight for the token-gated filedrop route; the coordinator
		// answers it with the download method and header allow-list.
		router.NewRoute(http.MethodOptions, a.resourcePath+"/download/*", byteHandler,
			router.WithAccess(""),
			router.WithSwagger(
				router.WithSummary("MCP filedrop (CORS preflight)"),
				router.WithDescription("Answers CORS preflight for the MCP filedrop byte route."),
				router.WithTags("MCP"),
			),
		),
		// RFC 9728 protected-resource metadata; MCP clients discover the
		// authorization server from this document. The RFC 8414 authorization-
		// server metadata is served by the dashboard API extension at the issuer
		// URL. CORS (wildcard origin, GET/OPTIONS) is served on the GET handler
		// itself and on the OPTIONS preflight route below, so cross-origin
		// browser MCP clients can fetch it during discovery.
		router.NewRoute(http.MethodGet, "/.well-known/oauth-protected-resource",
			a.protectedResourceHandler(),
			router.WithAccess(""),
			router.WithCors(discoveryCORSConfig()),
			router.WithSwagger(
				router.WithSummary("OAuth protected-resource metadata"),
				router.WithDescription("RFC 9728 protected-resource metadata describing the MCP server resource."),
				router.WithTags("MCP"),
			),
		),
		// CORS preflight for the protected-resource metadata endpoint.
		router.NewRoute(http.MethodOptions, "/.well-known/oauth-protected-resource",
			discoveryPreflight,
			router.WithAccess(""),
			router.WithCors(discoveryCORSConfig()),
			router.WithSwagger(
				router.WithSummary("OAuth protected-resource metadata (CORS preflight)"),
				router.WithDescription("Answers CORS preflight for the protected-resource metadata endpoint."),
				router.WithTags("MCP"),
			),
		),
		// Serve the same protected-resource metadata under the resource path's
		// directory too, so clients that resolve the resource identifier
		// /.well-known/oauth-protected-resource/mcp (mirroring the /mcp server
		// path) get the identical document. The bearer challenge in the 401
		// continues to advertise the root PRM URL.
		router.NewRoute(http.MethodGet, "/.well-known/oauth-protected-resource/mcp",
			a.protectedResourceHandler(),
			router.WithAccess(""),
			router.WithCors(discoveryCORSConfig()),
			router.WithSwagger(
				router.WithSummary("OAuth protected-resource metadata (resource path)"),
				router.WithDescription("RFC 9728 protected-resource metadata describing the MCP server resource."),
				router.WithTags("MCP"),
			),
		),
		// CORS preflight for the resource-path protected-resource metadata.
		router.NewRoute(http.MethodOptions, "/.well-known/oauth-protected-resource/mcp",
			discoveryPreflight,
			router.WithAccess(""),
			router.WithCors(discoveryCORSConfig()),
			router.WithSwagger(
				router.WithSummary("OAuth protected-resource metadata (resource path, CORS preflight)"),
				router.WithDescription("Answers CORS preflight for the resource-path protected-resource metadata endpoint."),
				router.WithTags("MCP"),
			),
		),
		// Serve the MCP subdomain root as a server-rendered landing page that
		// explains what the server is and how to connect an MCP client to the
		// resource path (/mcp). The MCP endpoint itself never sits at the root.
		router.NewRoute(http.MethodGet, "/",
			a.homepageHandler(),
			router.WithAccess(""),
			router.WithSwagger(
				router.WithSummary("MCP subdomain landing page"),
				router.WithDescription("Server-rendered setup instructions for connecting an MCP client to the MCP resource path."),
				router.WithTags("MCP"),
			),
		),
	)

	if err := router.RegisterRoutes(gRouter, accessSvc, a.Subdomain(), routes); err != nil {
		return err
	}

	// Serve the embedded static assets (the Handlebars runtime the landing page
	// loads via <script src="/static/...">) with echo's own StaticFS. This
	// mounts the static/ embed at router.StaticAssetsPath ("/static") with
	// content-type, range and caching handled by echo, so no bespoke file
	// handler is needed.
	staticFs, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("mcp: open embedded static assets: %w", err)
	}
	router.GetRouter(gRouter).StaticFS(router.StaticAssetsPath, staticFs)

	// Register this MCP server as a protected resource so the OAuth provider
	// can issue tokens for it (RFC 8707) and serve its RFC 9728
	// protected-resource metadata. This runs in Configure (not the startup
	// func) because the provider service reports ErrOAuthDisabled until its own
	// startup func has built the AuthorizationServer; Configure runs after all
	// startup funcs complete, so registration is reliable.
	if err := a.oauthSvc.RegisterResource(a.Context(), core.OAuthProtectedResource{
		ResourceURL: a.resourceURL,
		Scopes:      a.scopes,
		DisplayName: "Portal MCP Server",
	}); err != nil {
		// MCP is unusable without OAuth. When the provider is disabled
		// (oauth.enabled=false) fail closed: skip registration and let the OAuth
		// middleware deny all MCP requests, rather than taking down the whole
		// portal. The routes above stay registered regardless.
		if errors.Is(err, portalservice.ErrOAuthDisabled) {
			a.Context().Logger().Warn("mcp: oauth provider disabled; MCP endpoint unavailable",
				zap.Error(err), zap.String("resource_url", a.resourceURL))
			return nil
		}
		return fmt.Errorf("mcp: register resource: %w", err)
	}

	// Read the resource back to confirm registration landed, so a
	// provider-side registry issue is visible at boot rather than surfacing
	// later as a 404 on the PRM endpoint. A read-back failure is logged, not
	// fatal: registration already succeeded and the portal must keep serving.
	reg, err := a.oauthSvc.GetResource(a.Context(), a.resourceURL)
	if err != nil {
		a.Logger().Error("mcp: failed to read back registered resource",
			zap.Error(err), zap.String("resource_url", a.resourceURL))
	} else {
		a.Logger().Info("mcp: protected resource registered",
			zap.String("resource_url", a.resourceURL),
			zap.Bool("visible", reg != nil),
			zap.Strings("scopes", a.scopes))
		if reg == nil {
			a.Logger().Error("mcp: protected resource not visible after registration",
				zap.String("resource_url", a.resourceURL))
		}
	}

	return nil
}

// mcpCORSConfig returns the CORS policy for the /mcp endpoint. It allows the
// headers that conforming stateless MCP HTTP clients must send on every POST
// (MCP-Protocol-Version, Mcp-Method, Mcp-Name) in addition to the bearer
// Authorization header used by the OAuth gate, on the GET/POST/OPTIONS methods
// the endpoint serves. Browsers discard the request if preflight omits any of
// these.
func mcpCORSConfig() cors.Config {
	return cors.Config{
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Content-Type",
			"Authorization",
			"MCP-Protocol-Version",
			"Mcp-Method",
			"Mcp-Name",
		},
		// Accept any origin and reflect the requesting Origin back (never the
		// literal "*"), so cross-origin bearer credentials are allowed. This
		// mirrors the portal's default CORS behavior.
		AllowOriginFunc:  func(string) bool { return true },
		AllowCredentials: true,
	}
}

// protectedResourceHandler returns RFC 9728 protected-resource metadata for
// the MCP server, delegating to the OAuth provider service.
func (a *API) protectedResourceHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		meta, err := a.oauthSvc.ProtectedResourceMetadata(c.Request().Context(), a.resourceURL)
		if err != nil {
			// Surface a meaningful status (404 resource unknown, 503 provider
			// disabled) instead of a generic 500, and record the underlying
			// cause at error level so discovery failures are diagnosable.
			return writeErrAndLog(a.Logger(), c, "protected_resource_metadata", a.resourceURL, err)
		}
		a.Logger().Debug("serving protected resource metadata",
			zap.String("resource_url", a.resourceURL))
		return c.JSON(http.StatusOK, meta)
	}
}
