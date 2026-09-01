package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/cors"
)

// discoveryCORSConfig returns the CORS policy for the OAuth/OpenID discovery
// endpoints (RFC 8414 authorization-server metadata, RFC 9728 protected-
// resource metadata, JWKS, and OpenID Connect discovery). These documents are
// fetched anonymously by any client — including cross-origin browser MCP
// clients doing the OAuth authorization-code flow — without credentials, so
// every origin is allowed for the GET and OPTIONS methods. The middleware
// reflects the requesting Origin (never a literal "*") and answers the OPTIONS
// preflight for the explicit preflight routes below.
func discoveryCORSConfig() cors.Config {
	return cors.Config{
		AllowOrigins:   []string{"*"},
		AllowedMethods: []string{http.MethodGet, http.MethodOptions},
		AllowedHeaders: []string{"Accept", "MCP-Protocol-Version"},
	}
}

// discoveryPreflight is the handler for the explicit OPTIONS routes of the
// discovery endpoints. The CORS middleware answers a valid preflight itself
// (short-circuiting before this handler); this only runs as a fallback.
func discoveryPreflight(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}

// webKey is a single RFC 7517 JSON Web Key.
type webKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid,omitempty"`
	X   string `json:"x,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// webKeySet is an RFC 7517 JSON Web Key Set, served by the jwks_uri.
type webKeySet struct {
	Keys []webKey `json:"keys"`
}

// ed25519KeySet builds a JWK Set for the portal's Ed25519 identity key, which
// is what portal JWTs are signed with (EdDSA). The OpenID Connect discovery
// document points its jwks_uri here so an OIDC client can verify ID/session
// tokens signed by the portal.
func ed25519KeySet(pub ed25519.PublicKey) webKeySet {
	return webKeySet{Keys: []webKey{{
		Kty: "OKP",
		Crv: "Ed25519",
		// Encodes the raw 32-byte Ed25519 public key.
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Alg: "EdDSA",
		Use: "sig",
	}}}
}

// openIDConfig is the OpenID Connect Discovery 1.0 document advertised at
// /.well-known/openid-configuration. It mirrors the RFC 8414 authorization-
// server metadata served at /.well-known/oauth-authorization-server, with the
// OpenID-specific fields (jwks_uri, subject_types_supported,
// id_token_signing_alg_values_supported) that a discovery-using OIDC/MCP
// client expects. The portal issues EdDSA-signed tokens under its Ed25519
// identity key, so the document advertises EdDSA and points at the JWKS.
type openIDConfig struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
}
