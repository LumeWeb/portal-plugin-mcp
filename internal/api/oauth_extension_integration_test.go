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

		rec := request(t, ctx, http.MethodGet, "/api/auth/oauth/authorize?"+q.Encode(), nil)
		require.Equal(t, http.StatusFound, rec.Code)
		loc := rec.Header().Get("Location")
		require.Contains(t, loc, "/app-login")
		require.Contains(t, loc, "to=")
		require.Contains(t, loc, "app=client_abc")
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
