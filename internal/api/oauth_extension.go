package api

import (
	"crypto/ed25519"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/oauth"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/middleware"
	"go.lumeweb.com/portal-plugin-mcp/internal"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.uber.org/zap"
)

var _ core.APIExtension = (*OAuthExtension)(nil)

// OAuthExtension extends the dashboard API with the OAuth 2.1 authorization-
// server endpoints for MCP clients. The authorization, token, and registration
// endpoints are served under /api/auth/oauth/* on the dashboard subdomain, so
// resource owners authenticate with their portal credentials and MCP clients
// complete the OAuth authorization-code flow against the portal's own IdP.
type OAuthExtension struct {
	*core.BaseComponent
	oauthSvc core.OAuthProviderService
	authSvc  core.AuthService
	// baseURL is the dashboard API's public base URL. It is the issuer of the
	// authorization server and the prefix of every OAuth endpoint.
	baseURL string
	// publicKey is the portal's Ed25519 identity public key, exported as the
	// OpenID Connect JWKS so clients can verify portal-signed tokens. Captured
	// at startup from the core config.
	publicKey ed25519.PublicKey
	// logger logs OAuth authorization-server events at debug level. It is a
	// named child of the context logger, set during startup. A nil logger is a
	// no-op.
	logger *zap.Logger
}

// NewOAuthExtension creates a dashboard API extension serving the MCP OAuth
// endpoints.
func NewOAuthExtension() core.APIExtensionFactory {
	return func() (core.APIExtension, []core.ContextBuilderOption, error) {
		ext := &OAuthExtension{}

		return ext, core.ContextOptions(core.ContextWithStartupFunc(func(ctx core.Context) error {
			httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)

			// GetService fails fast (Fatal) when a required service is missing.
			ext.oauthSvc = core.GetService[core.OAuthProviderService](ctx, core.OAUTH_PROVIDER_SERVICE)
			ext.authSvc = core.GetService[core.AuthService](ctx, core.AUTH_SERVICE)

			ext.baseURL = httpSvc.APISubdomain(ext.TargetAPI(), true)
			if ext.baseURL == "" {
				ext.baseURL = ctx.Config().Config().Core.Domain
			}
			// The OIDC discovery document and JWKS advertise the portal's
			// Ed25519 identity key, the key portal JWTs are signed with.
			ext.publicKey = ctx.Config().Config().Core.Identity.PublicKey()
			ext.logger = ctx.Logger().Named("mcp.oauth")
			return nil
		})), nil
	}
}

// TargetAPI returns the dashboard API that this extension extends.
func (e *OAuthExtension) TargetAPI() string {
	return "dashboard"
}

// Configure mounts the OAuth authorization-server endpoints on the dashboard
// API. The metadata, token, and register endpoints are OAuth protocol
// endpoints called directly by MCP clients and are intentionally left without
// a portal access policy. The authorize endpoints are gated by the portal's
// JWT middleware so the resource owner must be signed in to approve a MCP
// client (see handleAuthorizeGET redirect to /app-login).
func (e *OAuthExtension) Configure(gRouter router.Router, accessSvc core.AccessService) error {
	subdomain := core.GetAPI(e.TargetAPI()).Subdomain()

	// GET allows empty auth so unauthenticated resource owners can be
	// redirected to /app-login; POST requires an authenticated user to
	// approve/reject.
	authorizeGETAuth := middleware.AuthMiddleware(e.Context(),
		middleware.WithAuthPurpose(jwt.PurposeLogin),
		middleware.WithAuthEmptyAllowed(true),
	)
	authorizePOSTAuth := middleware.AuthMiddleware(e.Context(),
		middleware.WithAuthPurpose(jwt.PurposeLogin),
	)

	// Shared OAuth query/header documentation for the authorize endpoints.
	authorizeQueryParams := []router.SwaggerOption{
		router.WithQueryParam("response_type", "Authorization flow response type; must be \"code\"", "code"),
		router.WithQueryParam("client_id", "The registered OAuth client identifier", "client_abc"),
		router.WithQueryParam("redirect_uri", "The client redirect URI", "http://127.0.0.1:51732/callback"),
		router.WithQueryParam("state", "Opaque state echoed back to the client", "xyz"),
		router.WithQueryParam("code_challenge", "PKCE code challenge (RFC 7636)", "abc"),
		router.WithQueryParam("code_challenge_method", "PKCE challenge method; must be \"S256\"", "S256"),
		router.WithQueryParam("resource", "The MCP server resource being requested (RFC 8707)", "https://mcp.example.com/mcp"),
		router.WithQueryParam("scope", "Requested scopes", "offline_access"),
	}

	metadataSwagger := router.WithSwagger(
		router.WithSummary("OAuth Authorization Server Metadata"),
		router.WithDescription("RFC 8414 authorization server metadata document used by MCP clients for endpoint discovery."),
		router.WithTags("MCP OAuth"),
		router.WithSuccessResponse(http.StatusOK, "Authorization server metadata", router.WithJSONContent(oauth.ASMetadata{})),
	)

	oidcSwagger := router.WithSwagger(
		router.WithSummary("OpenID Connect Discovery"),
		router.WithDescription("OpenID Connect Discovery 1.0 document describing the portal's OAuth issuer and JWKS."),
		router.WithTags("MCP OAuth"),
		router.WithSuccessResponse(http.StatusOK, "OpenID Connect discovery document", router.WithJSONContent(openIDConfig{})),
	)

	jwksSwagger := router.WithSwagger(
		router.WithSummary("JSON Web Key Set"),
		router.WithDescription("RFC 7517 JSON Web Key Set exposing the portal's Ed25519 identity public key."),
		router.WithTags("MCP OAuth"),
		router.WithSuccessResponse(http.StatusOK, "JSON Web Key Set", router.WithJSONContent(webKeySet{})),
	)

	authorizeGetSwagger := router.WithSwagger(append([]router.SwaggerOption{
		router.WithSummary("Authorize MCP Client"),
		router.WithDescription("Renders the OAuth consent page for an authenticated resource owner, or redirects unauthenticated users to the portal login. Submitting the page issues an authorization code."),
		router.WithTags("MCP OAuth"),
		router.WithSuccessResponse(http.StatusOK, "Consent page (text/html)"),
	}, authorizeQueryParams...)...)

	authorizePostSwagger := router.WithSwagger(append([]router.SwaggerOption{
		router.WithSummary("Approve MCP Client Authorization"),
		router.WithDescription("Issues an authorization code when the resource owner approves, returning the client redirect URI. Called by the consent page."),
		router.WithTags("MCP OAuth"),
		router.WithRequestBody(OAuthApproveRequest{}, "Approve or reject the request", true),
		router.WithSuccessResponse(http.StatusOK, "Final client redirect URI", router.WithJSONContent(OAuthRedirectResponse{})),
		router.WithErrorResponses(router.DefineSwaggerErrorResponses(
			router.DefineSwaggerErrorResponse(http.StatusBadRequest, "Invalid authorization request"),
		)),
	}, authorizeQueryParams...)...)

	tokenSwagger := router.WithSwagger(
		router.WithSummary("OAuth Token"),
		router.WithDescription("Exchanges an authorization code for tokens, or rotates a refresh token (RFC 6749 §5). Form-encoded body."),
		router.WithTags("MCP OAuth"),
		router.WithRequestBody(OAuthTokenRequest{}, "grant_type of authorization_code or refresh_token plus the relevant fields", true),
		router.WithSuccessResponse(http.StatusOK, "Token response", router.WithJSONContent(oauth.TokenResponse{})),
		router.WithErrorResponses(router.DefineSwaggerErrorResponses(
			router.DefineSwaggerErrorResponse(http.StatusBadRequest, "RFC 6749 §5.2 error response"),
		)),
	)

	registerSwagger := router.WithSwagger(
		router.WithSummary("Register MCP OAuth Client"),
		router.WithDescription("Registers a dynamic public OAuth client (RFC 7591 §3.1) and returns its client_id."),
		router.WithTags("MCP OAuth"),
		router.WithRequestBody(OAuthRegisterRequest{}, "Client registration metadata", true),
		router.WithSuccessResponse(http.StatusCreated, "Registered client", router.WithJSONContent(OAuthClientResponse{})),
		router.WithErrorResponses(router.DefineSwaggerErrorResponses(
			router.DefineSwaggerErrorResponse(http.StatusBadRequest, "Invalid client metadata"),
		)),
	)

	routes := router.DefineRoutes(
		// RFC 8414 authorization-server metadata. Served on the dashboard
		// subdomain because that is the OAuth issuer for the portal.
		router.NewRoute(http.MethodGet, "/.well-known/oauth-authorization-server",
			e.handleASMetadata,
			metadataSwagger,
			router.WithCors(discoveryCORSConfig()),
		),
		// CORS preflight for the authorization-server metadata endpoint.
		router.NewRoute(http.MethodOptions, "/.well-known/oauth-authorization-server",
			discoveryPreflight,
			metadataSwagger,
			router.WithCors(discoveryCORSConfig()),
		),
		// OpenID Connect Discovery document. Lets OIDC-discovery-using MCP
		// clients resolve the portal's authorization/token endpoints and the
		// JWKS that verifies its EdDSA-signed tokens.
		router.NewRoute(http.MethodGet, "/.well-known/openid-configuration",
			e.handleOpenIDConfig,
			oidcSwagger,
			router.WithCors(discoveryCORSConfig()),
		),
		// CORS preflight for the OpenID Connect discovery document.
		router.NewRoute(http.MethodOptions, "/.well-known/openid-configuration",
			discoveryPreflight,
			oidcSwagger,
			router.WithCors(discoveryCORSConfig()),
		),
		// RFC 7517 JSON Web Key Set exposing the portal's Ed25519 identity
		// public key, referenced by the OpenID Connect discovery jwks_uri.
		router.NewRoute(http.MethodGet, "/.well-known/jwks.json",
			e.handleJWKS,
			jwksSwagger,
			router.WithCors(discoveryCORSConfig()),
		),
		// CORS preflight for the JWKS endpoint.
		router.NewRoute(http.MethodOptions, "/.well-known/jwks.json",
			discoveryPreflight,
			jwksSwagger,
			router.WithCors(discoveryCORSConfig()),
		),
		// Authorization endpoint (RFC 6749 §4.1.1): GET renders the consent
		// page, POST issues the authorization code after the authenticated
		// resource owner approves.
		router.NewRoute(http.MethodGet, "/api/auth/oauth/authorize", e.handleAuthorizeGET,
			authorizeGetSwagger,
			router.WithMiddlewares(authorizeGETAuth),
			router.WithCors(),
		),
		router.NewRoute(http.MethodPost, "/api/auth/oauth/authorize", e.handleAuthorizePOST,
			authorizePostSwagger,
			router.WithMiddlewares(authorizePOSTAuth, e.verifySameOrigin()),
			router.WithCors(),
		),
		// Token endpoint (RFC 6749 §5): code exchange + refresh token grant.
		router.NewRoute(http.MethodPost, "/api/auth/oauth/token", e.handleToken,
			tokenSwagger,
			router.WithCors(),
		),
		// Dynamic client registration (RFC 7591 §3.1).
		router.NewRoute(http.MethodPost, "/api/auth/oauth/register", e.handleRegister,
			registerSwagger,
			router.WithCors(),
		),
	)

	return router.RegisterRoutes(gRouter, accessSvc, subdomain, routes)
}

// verifySameOrigin guards the authorize POST against CSRF. The consent page
// submits with same-origin fetch and credentials: "same-origin", so a genuine
// approval always carries an Origin matching the dashboard host. A cross-site
// request cannot set the Origin header to the victim's host, so rejecting a
// mismatched (or absent, for non-browser clients) origin blocks coerced
// approvals. GET is left open because it only renders the consent page.
func (e *OAuthExtension) verifySameOrigin() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			origin := c.Request().Header.Get("Origin")
			if origin != "" && !sameOrigin(e.baseURL, origin) {
				return echo.NewHTTPError(http.StatusForbidden, "cross-origin request rejected")
			}
			return next(c)
		}
	}
}

// sameOrigin reports whether origin matches the baseURL's host. The Origin
// header is always absolute (scheme://host); baseURL may or may not carry a
// scheme. Scheme is compared only when both are present so a scheme-less
// baseURL (common in tests) still matches.
func sameOrigin(baseURL, origin string) bool {
	o, err := url.Parse(origin)
	if err != nil || o.Host == "" {
		return false
	}
	b, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	if b.Host == "" {
		b, err = url.Parse("https://" + baseURL)
		if err != nil {
			return false
		}
	}
	// Hostname() strips any port, so an explicit ":443" still matches.
	if !strings.EqualFold(o.Hostname(), b.Hostname()) {
		return false
	}
	return o.Scheme == "" || b.Scheme == "" || o.Scheme == b.Scheme
}

// ID returns a stable identifier for this extension.
func (e *OAuthExtension) ID() string {
	return internal.PluginName + ".oauth_extension"
}

// logDebug emits a debug log entry if a logger is configured, else no-ops.
func (e *OAuthExtension) logDebug(msg string, fields ...zap.Field) {
	if e.logger == nil {
		return
	}
	e.logger.Debug(msg, fields...)
}
