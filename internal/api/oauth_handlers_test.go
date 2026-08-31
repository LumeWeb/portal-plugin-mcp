package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
			ClientID: "client_abc",
			Resource: "https://mcp.example.com/mcp",
			Scope:    "offline_access",
		},
	})

	body := w.Body.String()
	for _, want := range []string{
		"Authorize —",
		"client_abc",
		"MCP client",
		"https://mcp.example.com/mcp",
		`data-action="approve"`,
		`data-action="reject"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("consent page missing %q", want)
		}
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
	w := httptest.NewRecorder()
	writeTokens(w, &oauth.TokenResponse{
		AccessToken:  "tok",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "ref",
	})
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["access_token"] != "tok" || body["token_type"] != "Bearer" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestWriteTokenError(t *testing.T) {
	w := httptest.NewRecorder()
	writeTokenError(w, oauth.NewInvalidGrantError("expired code"))
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("unexpected error code: %v", body)
	}
}
