package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/oauth"
)

func TestOAuthReqFromValues(t *testing.T) {
	vals := url.Values{
		"response_type":         {"code"},
		"client_id":             {"client_abc"},
		"redirect_uri":          {"http://127.0.0.1:12345/cb"},
		"state":                 {"xyz"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"resource":              {"https://mcp.example.com/mcp"},
		"scope":                 {"offline_access"},
	}
	req := oauthReqFromValues(vals)
	if req.ResponseType != "code" || req.ClientID != "client_abc" ||
		req.CodeChallengeMethod != "S256" || req.Resource != "https://mcp.example.com/mcp" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestRenderConsentPage(t *testing.T) {
	w := httptest.NewRecorder()
	_ = consentTemplate.ExecuteTemplate(w, "consent", layoutData{
		AriaLabelledBy:  "consent-heading",
		AriaDescribedBy: "consent-description",
		PageData: consentPageData{
			ClientID:   "client_abc",
			ClientName: "MCP Inspector",
			Resource:   "https://mcp.example.com/mcp",
			Scope:      "offline_access",
		},
	})

	body := w.Body.String()
	for _, want := range []string{
		"Authorize — MCP Inspector",
		"MCP Inspector wants to connect to your account",
		"MCP client",
		"https://mcp.example.com/mcp",
		`data-action="approve"`,
		`data-action="reject"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("consent page missing %q", want)
		}
	}
	// The opaque client_id must never appear in user-facing copy.
	if strings.Contains(body, "client_abc") {
		t.Errorf("consent page must not render client_id, got %q", "client_abc")
	}
}

func TestRenderConsentPageFallback(t *testing.T) {
	w := httptest.NewRecorder()
	_ = consentTemplate.ExecuteTemplate(w, "consent", layoutData{
		AriaLabelledBy:  "consent-heading",
		AriaDescribedBy: "consent-description",
		PageData: consentPageData{
			ClientID: "client_abc",
			Resource: "https://mcp.example.com/mcp",
			Scope:    "offline_access",
		},
	})

	body := w.Body.String()
	for _, want := range []string{
		"An application wants to connect",
		"Authorize — Application",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("consent page fallback missing %q", want)
		}
	}
	// The opaque client_id must never appear in user-facing copy, even when
	// no display name is known.
	if strings.Contains(body, "client_abc") {
		t.Errorf("consent page fallback must not render client_id, got %q", "client_abc")
	}
}

func TestBuildRedirectURI(t *testing.T) {
	req := oauth.AuthorizeRequest{RedirectURI: "http://127.0.0.1:12345/cb", State: "xyz"}
	got := buildRedirectURI(req, url.Values{"code": {"code1"}})
	if got != "http://127.0.0.1:12345/cb?code=code1&state=xyz" {
		t.Fatalf("unexpected redirect URI: %s", got)
	}

	req = oauth.AuthorizeRequest{RedirectURI: "http://127.0.0.1:12345/cb?foo=1", State: "xyz"}
	got = buildRedirectURI(req, url.Values{"code": {"code1"}})
	if got != "http://127.0.0.1:12345/cb?foo=1&code=code1&state=xyz" {
		t.Fatalf("unexpected redirect URI with existing query: %s", got)
	}
}

func TestWriteTokens(t *testing.T) {
	c := newEchoContext()
	if err := writeTokens(c, &oauth.TokenResponse{
		AccessToken:  "tok",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "ref",
	}); err != nil {
		t.Fatalf("writeTokens returned error: %v", err)
	}
	if c.Response().Status != 200 {
		t.Fatalf("expected 200, got %d", c.Response().Status)
	}
	var body map[string]any
	if err := json.Unmarshal(c.Response().Writer.(*httptest.ResponseRecorder).Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["access_token"] != "tok" || body["token_type"] != "Bearer" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestWriteTokenError(t *testing.T) {
	c := newEchoContext()
	if err := writeTokenError(c, oauth.NewInvalidGrantError("expired code")); err != nil {
		t.Fatalf("writeTokenError returned error: %v", err)
	}
	if c.Response().Status != 400 {
		t.Fatalf("expected 400, got %d", c.Response().Status)
	}
	var body map[string]string
	if err := json.Unmarshal(c.Response().Writer.(*httptest.ResponseRecorder).Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("unexpected error code: %v", body)
	}
}

// newEchoContext returns an echo.Context bound to a fresh httptest recorder
// and a minimal request, so handlers can write JSON responses.
func newEchoContext() echo.Context {
	e := echo.New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	return e.NewContext(req, rec)
}
