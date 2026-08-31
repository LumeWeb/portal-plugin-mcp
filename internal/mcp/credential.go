package mcp

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"go.lumeweb.com/portal-middleware/auth/jwt"
)

// ErrNotAuthenticated is returned by CredentialResolver.TokenForRequest when
// there is no authenticated caller on the current request. The embedded
// pinner server treats it as "no per-request credential" and falls back to
// the bundle's config-token source.
var ErrNotAuthenticated = errors.New("mcp: no authenticated caller")

// apiTokenTTL is how long a minted Portal API JWT is valid. It is short-lived
// because the resolver is invoked per MCP request, so a fresh token is minted
// for every operation anyway.
const apiTokenTTL = 15 * time.Minute

// CredentialResolver implements the pinner mcpembed.CredentialResolver seam. It
// maps the OAuth-authenticated MCP caller onto a Portal API JWT (jwt.PurposeAPI)
// so the hosted pinner operations call the Portal API as that user.
//
// The OAuth middleware has already validated the caller and stamped the numeric
// user ID onto the request context (auth.TokenInfoFromContext, see Middleware).
// MCP access tokens are opaque and scoped to the mcp resource, so they cannot be
// replayed against the Portal API; a fresh, user-scoped API JWT is minted here.
type CredentialResolver struct {
	privateKey ed25519.PrivateKey
	domain     string
	ttl        time.Duration
}

// NewCredentialResolver builds a CredentialResolver that mints PurposeAPI JWTs
// for the portal domain, signed with the portal identity private key.
func NewCredentialResolver(privateKey ed25519.PrivateKey, domain string, ttl time.Duration) *CredentialResolver {
	if ttl <= 0 {
		ttl = apiTokenTTL
	}
	return &CredentialResolver{privateKey: privateKey, domain: domain, ttl: ttl}
}

// TokenForRequest returns a fresh Portal API JWT for the authenticated caller
// of the request, or ErrNotAuthenticated when the request is unauthenticated.
func (r *CredentialResolver) TokenForRequest(ctx context.Context) (string, error) {
	ti := auth.TokenInfoFromContext(ctx)
	if ti == nil || ti.UserID == "" {
		return "", ErrNotAuthenticated
	}
	return jwt.CreateToken(r.privateKey, r.domain, ti.UserID, jwt.PurposeAPI, r.ttl)
}
