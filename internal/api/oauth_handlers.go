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
	"go.lumeweb.com/oauth"
	mcontext "go.lumeweb.com/portal-middleware/context"
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
func (e *OAuthExtension) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	meta, err := e.oauthSvc.Metadata(r.Context())
	if err != nil {
		writeServerError(w)
		return
	}
	base := strings.TrimRight(e.baseURL, "/")
	meta.AuthorizationEndpoint = base + "/api/auth/oauth/authorize"
	meta.TokenEndpoint = base + "/api/auth/oauth/token"
	meta.RegistrationEndpoint = base + "/api/auth/oauth/register"
	writeJSON(w, http.StatusOK, meta)
}

// handleAuthorizeGET renders the OAuth consent page for an authenticated
// resource owner. Unauthenticated users are redirected to the /app-login page
// so they can authenticate and return to approve/reject the request. This
// mirrors the portal-plugin-sia SSO consent pattern: portal JWT gate →
// /app-login (?app=&to=) → embedded consent page.
func (e *OAuthExtension) handleAuthorizeGET(c echo.Context) error {
	req := oauthReqFromValues(c.QueryParams())
	if err := e.oauthSvc.ValidateAuthorizeRequest(c.Request().Context(), req); err != nil {
		return unprocessable(c, err.Error())
	}

	if _, err := mcontext.GetUserID(c); err != nil {
		return e.redirectToLogin(c, req.ClientID)
	}

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
		return c.JSON(http.StatusOK, OAuthRedirectResponse{
			RedirectURI: buildRedirectURI(req, url.Values{"error": {"access_denied"}}),
		})
	}

	code, err := e.oauthSvc.IssueAuthorizationCode(c.Request().Context(), req, userID)
	if err != nil {
		return unprocessable(c, err.Error())
	}

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
func (e *OAuthExtension) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, oauth.NewInvalidRequestError("could not parse form"))
		return
	}

	var resp *oauth.TokenResponse
	var err error
	switch r.PostFormValue("grant_type") {
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
		writeTokenError(w, oauth.NewUnsupportedGrantTypeError("unsupported grant_type"))
		return
	}
	if err != nil {
		writeTokenError(w, err)
		return
	}
	writeTokens(w, resp)
}

// handleRegister implements Dynamic Client Registration (RFC 7591 §3.1).
func (e *OAuthExtension) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request OAuthRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	for _, redirectURI := range request.RedirectURIs {
		if !oauth.AllowedClientRedirect(redirectURI) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
			return
		}
	}
	if request.TokenEndpointAuthMethod != "" && request.TokenEndpointAuthMethod != "none" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}

	client, err := e.oauthSvc.RegisterClient(r.Context(), oauth.ClientRegistration{
		ClientName:        request.ClientName,
		RedirectURIs:      request.RedirectURIs,
		GrantTypes:        request.GrantTypes,
		ResponseTypes:     request.ResponseTypes,
		TokenEndpointAuth: request.TokenEndpointAuthMethod,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	writeJSON(w, http.StatusCreated, OAuthClientResponse{
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
func writeTokenError(w http.ResponseWriter, err error) {
	var oauthErr *oauth.OAuthError
	if errors.As(err, &oauthErr) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             oauthErr.Code,
			"error_description": oauthErr.Description,
		})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
}

// writeTokens writes the RFC 6749 §5.1 success response.
func writeTokens(w http.ResponseWriter, resp *oauth.TokenResponse) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  resp.AccessToken,
		"token_type":    resp.TokenType,
		"expires_in":    resp.ExpiresIn,
		"refresh_token": resp.RefreshToken,
	})
}

// unprocessable writes a 400 JSON error body from an echo handler.
func unprocessable(c echo.Context, msg string) error {
	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(c.Response()).Encode(map[string]string{"error": "invalid_request", "error_description": msg})
	return nil
}
