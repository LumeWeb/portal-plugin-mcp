package api

import (
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/oauth"
	mcontext "go.lumeweb.com/portal-middleware/context"
	portalservice "go.lumeweb.com/portal/service"
	"go.uber.org/zap"
)

// consentPageData carries the data rendered into the OAuth consent page.
type consentPageData struct {
	ClientID string
	Resource string
	Scope    string
}

// layoutData is the shared layout wrapper for the embedded consent templates.
type layoutData struct {
	AriaLabelledBy  string
	AriaDescribedBy string
	MetaDescription string
	PageData        any
}

//go:embed consent_layout.html
var consentLayoutHTML string

//go:embed consent.html
var consentHTML string

var consentTemplate *template.Template

func init() {
	consentTemplate = template.Must(template.New("consent").
		Parse(consentLayoutHTML))
	template.Must(consentTemplate.New("page").Parse(consentHTML))
	template.Must(consentTemplate.Parse(`{{define "consent"}}{{template "layout" .}}{{end}}`))
}

// oauthReqFromValues builds an oauth.AuthorizeRequest from URL/form values.
func oauthReqFromValues(q url.Values) oauth.AuthorizeRequest {
	return oauth.AuthorizeRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Resource:            q.Get("resource"),
		Scope:               q.Get("scope"),
	}
}

// handleASMetadata serves the RFC 8414 authorization-server metadata document.
// The library builds endpoints at <issuer>/oauth/*, but this extension serves
// them under /api/auth/oauth/*, so the discoverable endpoint URLs are rewritten
// to the actual routes.
func (e *OAuthExtension) handleASMetadata(c echo.Context) error {
	meta, err := e.oauthSvc.Metadata(c.Request().Context())
	if err != nil {
		// When the OAuth provider is disabled (oauth.enabled=false) the
		// authorization server is never initialized, so there is no metadata
		// document to advertise. Mirror the MCP fail-closed behavior and
		// respond 404 rather than a misleading generic 500.
		if errors.Is(err, portalservice.ErrOAuthDisabled) {
			e.logDebug("authorization-server metadata unavailable: oauth provider disabled")
			return c.JSON(http.StatusNotFound, map[string]string{"error": "authorization_server_unavailable"})
		}
		e.logDebug("failed to build authorization-server metadata", zap.Error(err))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	e.logDebug("serving authorization-server metadata")
	base := strings.TrimRight(e.baseURL, "/")
	// Pin the issuer to the dashboard base URL (the origin actually serving
	// these endpoints) so the document is internally consistent: OIDC Core 1.0
	// requires issuer to match the endpoint origin. The portal's configured AS
	// issuer (oauth.issuer) can differ, but these routes are served from the
	// dashboard subdomain, not the configured issuer.
	meta.Issuer = base
	meta.AuthorizationEndpoint = base + "/api/auth/oauth/authorize"
	meta.TokenEndpoint = base + "/api/auth/oauth/token"
	meta.RegistrationEndpoint = base + "/api/auth/oauth/register"
	return c.JSON(http.StatusOK, meta)
}

// handleOpenIDConfig serves the OpenID Connect Discovery 1.0 document. It
// mirrors the RFC 8414 authorization-server metadata and adds the OpenID-
// specific fields and the JWKS location, so discovery-using MCP clients can
// resolve the endpoints and verification keys without special-casing the
// portal.
func (e *OAuthExtension) handleOpenIDConfig(c echo.Context) error {
	ctx := httputil.Context(c)

	// Mirror the authorization-server metadata availability: when the OAuth
	// provider is disabled there is no issuer to advertise, so report the
	// document as unavailable rather than leaking a misleading generic 500.
	if _, err := e.oauthSvc.Metadata(c.Request().Context()); err != nil {
		if errors.Is(err, portalservice.ErrOAuthDisabled) {
			e.logDebug("openid-configuration unavailable: oauth provider disabled")
			return ctx.Error(NewError(ErrAuthorizationServerUnavailable, err), http.StatusNotFound)
		}
		e.logDebug("failed to build openid-configuration", zap.Error(err))
		return ctx.Error(NewError(ErrOAuthServerError, err), http.StatusInternalServerError)
	}
	// Pin the issuer to the dashboard base URL where this document and its
	// endpoints are actually served. handleASMetadata also normalizes its
	// issuer to this base, so both discovery documents always agree.
	base := strings.TrimRight(e.baseURL, "/")
	return ctx.JSON(http.StatusOK, openIDConfig{
		Issuer:                base,
		AuthorizationEndpoint: base + "/api/auth/oauth/authorize",
		TokenEndpoint:         base + "/api/auth/oauth/token",
		RegistrationEndpoint:  base + "/api/auth/oauth/register",
		JwksURI:               base + "/.well-known/jwks.json",
		ResponseTypesSupported: []string{
			"code",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IdTokenSigningAlgValuesSupported: []string{
			"EdDSA",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"none",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
		ScopesSupported: []string{
			"offline_access",
		},
	})
}

// handleJWKS serves the RFC 7517 JSON Web Key Set for the portal's Ed25519
// identity key, referenced by the OpenID Connect discovery document.
//
// Note on key source: the portal's OAuth bearer tokens (go.lumeweb.com/oauth)
// are opaque, not JWT-signed, so this JWKS does not verify OAuth access tokens.
// It advertises the portal's Ed25519 identity key (Core.Identity), which is the
// key the portal signs its own JWTs with (EdDSA), so OIDC clients verifying
// portal-signed tokens can resolve it. The identity key is confirmed via
// config at startup; there is no JWKS method on the OAuth provider interface.
func (e *OAuthExtension) handleJWKS(c echo.Context) error {
	return c.JSON(http.StatusOK, ed25519KeySet(e.publicKey))
}

// handleAuthorizeGET renders the OAuth consent page for an authenticated
// resource owner. Unauthenticated users are redirected to the /app-login page
// so they can authenticate and return to approve/reject the request. This
// mirrors the portal-plugin-sia SSO consent pattern: portal JWT gate →
// /app-login (?app=&to=) → embedded consent page.
func (e *OAuthExtension) handleAuthorizeGET(c echo.Context) error {
	req := oauthReqFromValues(c.QueryParams())
	if err := e.oauthSvc.ValidateAuthorizeRequest(c.Request().Context(), req); err != nil {
		e.logDebug("authorize GET rejected",
			zap.String("client_id", req.ClientID),
			zap.String("resource", req.Resource),
			zap.Error(err))
		return unprocessable(c, err.Error())
	}

	if _, err := mcontext.GetUserID(c); err != nil {
		e.logDebug("unauthenticated resource owner redirected to login",
			zap.String("client_id", req.ClientID),
			zap.String("resource", req.Resource))
		return e.redirectToLogin(c, req.ClientID)
	}

	e.logDebug("rendering consent page",
		zap.String("client_id", req.ClientID),
		zap.String("resource", req.Resource),
		zap.String("scope", req.Scope))

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return consentTemplate.ExecuteTemplate(c.Response().Writer, "consent", layoutData{
		AriaLabelledBy:  "consent-heading",
		AriaDescribedBy: "consent-description",
		MetaDescription: "Authorize a MCP client to access your portal account",
		PageData: consentPageData{
			ClientID: req.ClientID,
			Resource: req.Resource,
			Scope:    req.Scope,
		},
	})
}

// handleAuthorizePOST issues an authorization code after the resource owner
// approves the request, binding the code to their authenticated user ID. It
// returns the final client redirect URI so the consent page JS can navigate
// the browser back to the client (RFC 6749 §4.1.2).
func (e *OAuthExtension) handleAuthorizePOST(c echo.Context) error {
	req := oauthReqFromValues(c.QueryParams())
	if err := e.oauthSvc.ValidateAuthorizeRequest(c.Request().Context(), req); err != nil {
		e.logDebug("authorize POST rejected",
			zap.String("client_id", req.ClientID),
			zap.String("resource", req.Resource),
			zap.Error(err))
		return unprocessable(c, err.Error())
	}

	var body OAuthApproveRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
		return unprocessable(c, "invalid request body")
	}

	userID, err := mcontext.GetUserID(c)
	if err != nil {
		return unprocessable(c, "authentication required")
	}

	if !body.Approve {
		e.logDebug("resource owner denied authorization",
			zap.String("client_id", req.ClientID),
			zap.String("resource", req.Resource),
			zap.Uint64("user_id", uint64(userID)))
		return c.JSON(http.StatusOK, OAuthRedirectResponse{
			RedirectURI: buildRedirectURI(req, url.Values{"error": {"access_denied"}}),
		})
	}

	code, err := e.oauthSvc.IssueAuthorizationCode(c.Request().Context(), req, userID)
	if err != nil {
		e.logDebug("failed to issue authorization code",
			zap.String("client_id", req.ClientID),
			zap.String("resource", req.Resource),
			zap.Uint64("user_id", uint64(userID)),
			zap.Error(err))
		return unprocessable(c, err.Error())
	}

	e.logDebug("authorization code issued",
		zap.String("client_id", req.ClientID),
		zap.String("resource", req.Resource),
		zap.Uint64("user_id", uint64(userID)))

	return c.JSON(http.StatusOK, OAuthRedirectResponse{
		RedirectURI: buildRedirectURI(req, url.Values{"code": {code}}),
	})
}

// buildRedirectURI appends the given params to the client redirect_uri,
// preserving any existing query parameters and including state if present.
func buildRedirectURI(req oauth.AuthorizeRequest, params url.Values) string {
	if req.State != "" {
		params.Set("state", req.State)
	}
	loc := req.RedirectURI
	if strings.Contains(loc, "?") {
		loc += "&" + params.Encode()
	} else {
		loc += "?" + params.Encode()
	}
	return loc
}

// redirectToLogin redirects an unauthenticated resource owner to the
// /app-login page, carrying a `to` parameter pointing back to the current
// authorize request so the login completes the OAuth flow. This mirrors the
// portal-plugin-sia SSO gate: portal JWT → <api>/app-login?app=&to=<authorize>.
func (e *OAuthExtension) redirectToLogin(c echo.Context, appName string) error {
	dest, err := url.Parse(e.baseURL)
	if err != nil {
		return unprocessable(c, "internal error")
	}
	dest.Path = "/app-login"
	query := url.Values{}
	query.Set("to", strings.TrimRight(e.baseURL, "/")+c.Request().URL.String())
	if appName != "" {
		query.Set("app", appName)
	}
	dest.RawQuery = query.Encode()
	return c.Redirect(http.StatusFound, dest.String())
}

// handleToken exchanges an authorization code or refresh token for tokens
// (RFC 6749 §5.1). Errors are returned per RFC 6749 §5.2.
func (e *OAuthExtension) handleToken(c echo.Context) error {
	if c.Request().Method != http.MethodPost {
		c.Response().Header().Set("Allow", http.MethodPost)
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "method not allowed")
	}
	r := c.Request()
	if err := r.ParseForm(); err != nil {
		return writeTokenError(c, oauth.NewInvalidRequestError("could not parse form"))
	}

	grantType := r.PostFormValue("grant_type")
	e.logDebug("token request", zap.String("grant_type", grantType))

	var resp *oauth.TokenResponse
	var err error
	switch grantType {
	case "authorization_code":
		resp, err = e.oauthSvc.ExchangeCode(r.Context(), oauth.TokenRequest{
			GrantType:    r.PostFormValue("grant_type"),
			Code:         r.PostFormValue("code"),
			ClientID:     r.PostFormValue("client_id"),
			RedirectURI:  r.PostFormValue("redirect_uri"),
			CodeVerifier: r.PostFormValue("code_verifier"),
			Resource:     r.PostFormValue("resource"),
		})
	case "refresh_token":
		resp, err = e.oauthSvc.RefreshToken(r.Context(), oauth.TokenRequest{
			GrantType:    r.PostFormValue("grant_type"),
			Resource:     r.PostFormValue("resource"),
			RefreshToken: r.PostFormValue("refresh_token"),
		})
	default:
		return writeTokenError(c, oauth.NewUnsupportedGrantTypeError("unsupported grant_type"))
	}
	if err != nil {
		e.logDebug("token request failed", zap.String("grant_type", grantType), zap.Error(err))
		return writeTokenError(c, err)
	}
	e.logDebug("token issued", zap.String("grant_type", grantType))
	return writeTokens(c, resp)
}

// handleRegister implements Dynamic Client Registration (RFC 7591 §3.1).
func (e *OAuthExtension) handleRegister(c echo.Context) error {
	if c.Request().Method != http.MethodPost {
		c.Response().Header().Set("Allow", http.MethodPost)
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "method not allowed")
	}
	var request OAuthRegisterRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&request); err != nil || len(request.RedirectURIs) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
	}
	for _, redirectURI := range request.RedirectURIs {
		if !oauth.AllowedClientRedirect(redirectURI) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
		}
	}
	if request.TokenEndpointAuthMethod != "" && request.TokenEndpointAuthMethod != "none" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
	}

	client, err := e.oauthSvc.RegisterClient(c.Request().Context(), oauth.ClientRegistration{
		ClientName:        request.ClientName,
		RedirectURIs:      request.RedirectURIs,
		GrantTypes:        request.GrantTypes,
		ResponseTypes:     request.ResponseTypes,
		TokenEndpointAuth: request.TokenEndpointAuthMethod,
	})
	if err != nil {
		// The MCP OAuth endpoints are unreachable when the provider is
		// disabled; report that as 503 rather than a misleading 400 and log
		// the underlying cause.
		if errors.Is(err, portalservice.ErrOAuthDisabled) {
			return writeErrAndLog(e.Logger(), c, "dynamic_client_registration", request.ClientName, err)
		}
		e.logDebug("client registration rejected",
			zap.String("client_name", request.ClientName),
			zap.Error(err))
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
	}
	e.logDebug("client registered",
		zap.String("client_id", client.ClientID),
		zap.String("client_name", client.ClientName))
	return c.JSON(http.StatusCreated, OAuthClientResponse{
		ClientID:                client.ClientID,
		ClientName:              client.ClientName,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		TokenEndpointAuthMethod: client.TokenEndpointAuth,
	})
}

// writeTokenError maps a library oauth error to an RFC 6749 §5.2 token endpoint
// error response. Non-oauth errors surface as server_error.
func writeTokenError(c echo.Context, err error) error {
	var oauthErr *oauth.OAuthError
	if errors.As(err, &oauthErr) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             oauthErr.Code,
			"error_description": oauthErr.Description,
		})
	}
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
}

// writeTokens writes the RFC 6749 §5.1 success response.
func writeTokens(c echo.Context, resp *oauth.TokenResponse) error {
	return c.JSON(http.StatusOK, map[string]any{
		"access_token":  resp.AccessToken,
		"token_type":    resp.TokenType,
		"expires_in":    resp.ExpiresIn,
		"refresh_token": resp.RefreshToken,
	})
}

// unprocessable writes a 400 JSON error body from an echo handler.
func unprocessable(c echo.Context, msg string) error {
	return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": msg})
}
