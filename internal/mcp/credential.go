package mcp

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.uber.org/zap"
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
// maps the OAuth-authenticated MCP caller onto a Portal API JWT (jwt.PurposeLogin)
// so the hosted pinner operations call the Portal API as that user.
//
// The OAuth middleware has already validated the caller and stamped the numeric
// user ID onto the request context (auth.TokenInfoFromContext, see Middleware).
// MCP access tokens are opaque and scoped to the mcp resource, so they cannot be
// replayed against the Portal API; a fresh, user-scoped login JWT is minted here.
//
// The token is minted with PurposeLogin (not PurposeAPI). pinner's auth service
// decodes the JWT audience to decide how to use it: a PurposeAPI token is
// treated as an API-key credential and exchanged via POST /api/auth/key, but the
// token minted here was never registered as a stored API key, so that exchange
// fails with "unauthorized: invalid API key". A PurposeLogin token is used
// directly as the bearer credential for the Portal API.
type CredentialResolver struct {
	privateKey ed25519.PrivateKey
	domain     string
	ttl        time.Duration

	// logger logs per-request credential minting at debug level. It defaults to
	// nil (no-op) and can be replaced via WithLogger.
	logger *zap.Logger
}

// WithLogger sets the logger the resolver uses for credential-resolution debug
// events. A nil logger is a no-op.
func (r *CredentialResolver) WithLogger(l *zap.Logger) *CredentialResolver {
	r.logger = l
	return r
}

// NewCredentialResolver builds a CredentialResolver that mints PurposeLogin JWTs
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
		r.logDebug("no authenticated caller; falling back to config-token source")
		return "", ErrNotAuthenticated
	}
	r.logDebug("minted per-user Portal login JWT", zap.String("user_id", ti.UserID))
	return jwt.CreateToken(r.privateKey, r.domain, ti.UserID, jwt.PurposeLogin, r.ttl)
}

// logDebug emits a debug log entry if a logger is configured, else no-ops.
func (r *CredentialResolver) logDebug(msg string, fields ...zap.Field) {
	if r.logger == nil {
		return
	}
	r.logger.Debug(msg, fields...)
}
