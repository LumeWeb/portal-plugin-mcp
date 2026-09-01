package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/oauth"
	coreTesting "go.lumeweb.com/portal/core/testing"
	portalservice "go.lumeweb.com/portal/service"
)

func TestOAuthMetadataRewritesEndpoints(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		oauthExt(ctx).EXPECT().Metadata(mock.Anything).Return(&oauth.ASMetadata{
			Issuer: "https://dashboard.example.com",
		}, nil)

		rec := request(t, ctx, http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		// The library builds endpoints at <issuer>/oauth/*; the extension must
		// rewrite them to the actually-served /api/auth/oauth/* routes.
		require.Contains(t, body, "/api/auth/oauth/authorize")
		require.Contains(t, body, "/api/auth/oauth/token")
		require.Contains(t, body, "/api/auth/oauth/register")
		require.NotContains(t, strings.TrimSuffix(body, "\n"), `"authorization_endpoint":"dashboard.example.com/oauth/authorize`)
	}, getOAuthExtensionTestOptions())
}

// TestOAuthMetadataDisabledProvider verifies that when the portal OAuth
// provider is disabled, the authorization-server metadata endpoint reports the
// AS as unavailable instead of leaking a generic 500 server_error.
func TestOAuthMetadataDisabledProvider(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		oauthExt(ctx).EXPECT().Metadata(mock.Anything).Return(nil, portalservice.ErrOAuthDisabled)

		rec := request(t, ctx, http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "authorization_server_unavailable")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthMetadataOPTIONSPreflightCORS(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// GET already returns CORS headers; the missing piece was the OPTIONS
		// preflight, which used to 405 because no OPTIONS route existed.
		req := ctx.NewAPIRequest(http.MethodOptions, "/.well-known/oauth-authorization-server", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		req.Header.Set("Access-Control-Request-Headers", "accept, mcp-protocol-version")
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Equal(t, "http://localhost:5173", rec.Header().Get("Access-Control-Allow-Origin"))
		require.Contains(t, strings.ToLower(rec.Header().Get("Access-Control-Allow-Methods")), "get")
		require.Contains(t, strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers")), "accept")
		require.Contains(t, strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers")), "mcp-protocol-version")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthOpenIDConfig(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Even when the configured AS issuer (oauth.issuer) diverges from the
		// dashboard subdomain, the OIDC document pins the issuer to the base
		// URL its endpoints are actually served from, so OIDC Core 1.0 strict
		// clients accept it.
		oauthExt(ctx).EXPECT().Metadata(mock.Anything).Return(&oauth.ASMetadata{
			Issuer: "https://auth.example.com",
		}, nil)

		rec := request(t, ctx, http.MethodGet, "/.well-known/openid-configuration", nil)
		require.Equal(t, http.StatusOK, rec.Code)

		var doc openIDConfig
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
		require.Equal(t, "dashboard.example.com", doc.Issuer)
		require.Equal(t, "dashboard.example.com/api/auth/oauth/authorize", doc.AuthorizationEndpoint)
		require.Equal(t, "dashboard.example.com/api/auth/oauth/token", doc.TokenEndpoint)
		require.Equal(t, "dashboard.example.com/api/auth/oauth/register", doc.RegistrationEndpoint)
		require.Equal(t, "dashboard.example.com/.well-known/jwks.json", doc.JwksURI)
		require.Contains(t, doc.ResponseTypesSupported, "code")
		require.Contains(t, doc.SubjectTypesSupported, "public")
		require.Contains(t, doc.IdTokenSigningAlgValuesSupported, "EdDSA")
		require.Contains(t, doc.CodeChallengeMethodsSupported, "S256")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthOpenIDConfigDisabledProvider(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		oauthExt(ctx).EXPECT().Metadata(mock.Anything).Return(nil, portalservice.ErrOAuthDisabled)

		rec := request(t, ctx, http.MethodGet, "/.well-known/openid-configuration", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "AuthorizationServerUnavailable")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthOpenIDConfigOPTIONSPreflightCORS(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		req := ctx.NewAPIRequest(http.MethodOptions, "/.well-known/openid-configuration", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Equal(t, "http://localhost:5173", rec.Header().Get("Access-Control-Allow-Origin"))
	}, getOAuthExtensionTestOptions())
}

func TestOAuthJWKS(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		rec := request(t, ctx, http.MethodGet, "/.well-known/jwks.json", nil)
		require.Equal(t, http.StatusOK, rec.Code)

		var ks webKeySet
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &ks))
		require.Len(t, ks.Keys, 1)
		k := ks.Keys[0]
		require.Equal(t, "OKP", k.Kty)
		require.Equal(t, "Ed25519", k.Crv)
		require.Equal(t, "EdDSA", k.Alg)
		require.Equal(t, "sig", k.Use)
		require.NotEmpty(t, k.X)
	}, getOAuthExtensionTestOptions())
}

func TestOAuthAuthorizeGET_UnauthenticatedRedirectsToAppLogin(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {"client_abc"},
			"redirect_uri":          {"http://127.0.0.1:12345/cb"},
			"state":                 {"xyz"},
			"code_challenge":        {"ch"},
			"code_challenge_method": {"S256"},
		}
		oauthExt(ctx).EXPECT().ValidateAuthorizeRequest(mock.Anything, mock.Anything).Return(nil)
		oauthExt(ctx).EXPECT().GetClientMetadata(mock.Anything, "client_abc").Return(&oauth.Client{
			ClientID: "client_abc", ClientName: "MCP Inspector",
		}, nil)

		rec := request(t, ctx, http.MethodGet, "/api/auth/oauth/authorize?"+q.Encode(), nil)
		require.Equal(t, http.StatusFound, rec.Code)
		loc := rec.Header().Get("Location")
		require.Contains(t, loc, "/app-login")
		require.Contains(t, loc, "to=")
		// The `app` query arg the login page renders must be the registered
		// client display name, never the raw client_id.
		require.Contains(t, loc, "app=MCP+Inspector")
		require.NotContains(t, loc, "app=client_abc")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthAuthorizeGET_UnauthenticatedLoginAppNameNeverIsClientIDURL(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// A client like mcpjam uses its client-metadata document URL as the
		// client_id. The /app-login `app` arg must carry the display name, not
		// that URL.
		clientURL := "https://www.mcpjam.com/.well-known/oauth/client-metadata.json"
		q := url.Values{"response_type": {"code"}, "client_id": {clientURL}}
		oauthExt(ctx).EXPECT().ValidateAuthorizeRequest(mock.Anything, mock.Anything).Return(nil)
		oauthExt(ctx).EXPECT().GetClientMetadata(mock.Anything, clientURL).Return(&oauth.Client{
			ClientID: clientURL, ClientName: "MCP Jam",
		}, nil)

		rec := request(t, ctx, http.MethodGet, "/api/auth/oauth/authorize?"+q.Encode(), nil)
		require.Equal(t, http.StatusFound, rec.Code)
		loc := rec.Header().Get("Location")
		require.Contains(t, loc, "/app-login")
		locURL, err := url.Parse(loc)
		require.NoError(t, err)
		// The `app` arg the login page renders must be the registered client
		// display name, never the client-metadata URL used as client_id. The
		// URL may still appear in the `to` param (the redirect back to the
		// authorize endpoint), so assert only on the app value.
		require.Equal(t, "MCP Jam", locURL.Query().Get("app"))
	}, getOAuthExtensionTestOptions())
}

func TestOAuthAuthorizeGET_AuthenticatedRendersConsent(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		token, _ := coreTesting.NewJWTHelper(ctx).CreateLoginToken(1)
		q := url.Values{"response_type": {"code"}, "client_id": {"client_abc"}}
		oauthExt(ctx).EXPECT().ValidateAuthorizeRequest(mock.Anything, mock.Anything).Return(nil)
		// No stored client metadata: the consent page falls back to a generic
		// heading and must not leak the opaque client_id.
		oauthExt(ctx).EXPECT().GetClientMetadata(mock.Anything, "client_abc").Return(nil, oauth.ErrClientNotFound)

		req := ctx.NewAPIRequest(http.MethodGet, "/api/auth/oauth/authorize?"+q.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
		require.Contains(t, rec.Body.String(), "An application wants to connect")
		require.NotContains(t, rec.Body.String(), "client_abc")
		require.Contains(t, rec.Body.String(), "Approve")
		require.NotContains(t, rec.Body.String(), "Publisher:")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthAuthorizeGET_ClientURIValidHTTPSurfaced(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		token, _ := coreTesting.NewJWTHelper(ctx).CreateLoginToken(1)
		q := url.Values{"response_type": {"code"}, "client_id": {"uri-client"}}
		oauthExt(ctx).EXPECT().ValidateAuthorizeRequest(mock.Anything, mock.Anything).Return(nil)
		// Only an absolute http(s) client_uri is rendered as a link.
		oauthExt(ctx).EXPECT().GetClientMetadata(mock.Anything, "uri-client").Return(&oauth.Client{
			ClientID:  "uri-client",
			ClientURI: "https://publisher.example/oauth-client.json",
		}, nil)

		req := ctx.NewAPIRequest(http.MethodGet, "/api/auth/oauth/authorize?"+q.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		require.Contains(t, body, "Publisher:")
		// The href keeps the full metadata URL; the link text is the domain.
		require.Contains(t, body, `href="https://publisher.example/oauth-client.json"`)
		require.Contains(t, body, ">publisher.example</a>")
		require.NotContains(t, body, ">https://publisher.example/oauth-client.json</a>")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthAuthorizeGET_RendersRegisteredClientName(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Authorize with a client whose name is returned from durable storage:
		// the consent page shows the display name, not the client_id.
		token, _ := coreTesting.NewJWTHelper(ctx).CreateLoginToken(1)
		q := url.Values{"response_type": {"code"}, "client_id": {"client_abc"}}
		oauthExt(ctx).EXPECT().ValidateAuthorizeRequest(mock.Anything, mock.Anything).Return(nil)
		oauthExt(ctx).EXPECT().GetClientMetadata(mock.Anything, "client_abc").Return(&oauth.Client{
			ClientID: "client_abc", ClientName: "MCP Inspector",
		}, nil)

		req := ctx.NewAPIRequest(http.MethodGet, "/api/auth/oauth/authorize?"+q.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Body.String(), "MCP Inspector wants to connect to your account")
		require.NotContains(t, rec.Body.String(), "client_abc")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthAuthorizePOST_CrossOriginRejected(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		token, _ := coreTesting.NewJWTHelper(ctx).CreateLoginToken(1)
		q := url.Values{"response_type": {"code"}, "client_id": {"client_abc"}}

		req := ctx.NewAPIRequest(http.MethodPost, "/api/auth/oauth/authorize?"+q.Encode(), mustMarshalJSON(t, OAuthApproveRequest{Approve: true}))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusForbidden, rec.Code)
		// No authorization code must be issued for a cross-origin approval.
		oauthExt(ctx).AssertNotCalled(t, "IssueAuthorizationCode", mock.Anything, mock.Anything, mock.Anything)
	}, getOAuthExtensionTestOptions())
}

func TestOAuthAuthorizePOST_SameOriginProceeds(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		token, _ := coreTesting.NewJWTHelper(ctx).CreateLoginToken(1)
		q := url.Values{"response_type": {"code"}, "client_id": {"client_abc"}}
		oauthExt(ctx).EXPECT().ValidateAuthorizeRequest(mock.Anything, mock.Anything).Return(nil)
		oauthExt(ctx).EXPECT().IssueAuthorizationCode(mock.Anything, mock.Anything, uint(1)).Return("code1", nil)

		req := ctx.NewAPIRequest(http.MethodPost, "/api/auth/oauth/authorize?"+q.Encode(), mustMarshalJSON(t, OAuthApproveRequest{Approve: true}))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Origin", "https://dashboard.example.com")
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Body.String(), "code1")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthRegisterClient(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		oauthExt(ctx).EXPECT().RegisterClient(mock.Anything, mock.Anything).Return(&oauth.Client{
			ClientID: "new-client", RedirectURIs: []string{"http://127.0.0.1:9999/cb"},
		}, nil)

		body := mustMarshalJSON(t, OAuthRegisterRequest{
			ClientName:    "test-client",
			RedirectURIs:  []string{"http://127.0.0.1:9999/cb"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
		})
		rec := request(t, ctx, http.MethodPost, "/api/auth/oauth/register", body)
		require.Equal(t, http.StatusCreated, rec.Code)
		require.Contains(t, rec.Body.String(), "new-client")
	}, getOAuthExtensionTestOptions())
}

func TestOAuthTokenExchange(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		oauthExt(ctx).EXPECT().ExchangeCode(mock.Anything, mock.Anything).Return(&oauth.TokenResponse{
			AccessToken: "at", RefreshToken: "rt", TokenType: "Bearer", ExpiresIn: 3600,
		}, nil)

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"code1"},
			"client_id":     {"client_abc"},
			"redirect_uri":  {"http://127.0.0.1:12345/cb"},
			"code_verifier": {"verifier"},
		}
		req := ctx.NewAPIRequest(http.MethodPost, "/api/auth/oauth/token", []byte(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		ctx.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Body.String(), `"access_token":"at"`)
	}, getOAuthExtensionTestOptions())
}

func mustMarshalJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
