package hosted

import (
	"go.lumeweb.com/pinner/mcp/hosted"
)

// CredentialResolver resolves the Portal API token for the authenticated
// principal of the current request. It is the seam that lets a hosted embed
// route the MCP OAuth backend to the Portal's own OAuth library/IdP (which has
// already validated the caller and established a user). It aliases the shared
// go.lumeweb.com/pinner/mcp/hosted contract.
type CredentialResolver = hosted.CredentialResolver

// IdentifiableCredentialResolver is an optional interface a CredentialResolver
// may implement to expose a STABLE identity for its underlying credential
// source. It aliases the shared contract from go.lumeweb.com/pinner/mcp/hosted;
// see the pinner documentation for the closure-equality proof semantics.
type IdentifiableCredentialResolver = hosted.IdentifiableCredentialResolver

// OAuthHandler protects the embedded MCP HTTP endpoint with OAuth. It is the
// surface-agnostic seam between the MCP implementation and an authorization
// server. In the Portal plugin it is implemented by internal/mcp.Middleware,
// which delegates to the Portal's OAuthProviderService (RFC 8414/9728). It
// aliases the shared contract from go.lumeweb.com/pinner/mcp/hosted.
type OAuthHandler = hosted.OAuthHandler

// NormalizeCredentialResolvers is the shared hosted-construction rule that
// reconciles the ONE effective per-request credential for an assembly so the
// HTTP boundary and catalog dispatch can never disagree about identity. It is
// re-exported from the pinner contract package for callers of this boundary.
var NormalizeCredentialResolvers = hosted.NormalizeCredentialResolvers
