package hosted

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.lumeweb.com/pinner/assembly"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// identityResolver is a comparable CredentialResolver fixture with a stable
// Identity, so resolver-normalization identity semantics can be pinned.
type identityResolver struct{ id string }

func (r identityResolver) TokenForRequest(ctx context.Context) (string, error) {
	return "token-" + r.id, nil
}
func (r identityResolver) ResolverIdentity() string { return r.id }

// oauthStub records whether it wrapped the downstream handler.
type oauthStub struct {
	wrapped *bool
}

func (o oauthStub) WrapHTTP(next http.Handler) http.Handler {
	if o.wrapped != nil {
		*o.wrapped = true
	}
	return next
}

func TestDomainScopeIsZero(t *testing.T) {
	assert.True(t, (DomainScope{}).IsZero(), "zero scope is empty")
	assert.False(t, DomainScopeHosted.IsZero(), "hosted scope is non-empty")

	// A partial surface maps flag per-field.
	partial := DomainScope{Account: true}
	assert.False(t, partial.IsZero())
	assert.True(t, partial.Account)
	assert.False(t, partial.Pins)

	// Hosted surface enables the full hosted set.
	assert.True(t, DomainScopeHosted.Account)
	assert.True(t, DomainScopeHosted.Pins)
	assert.True(t, DomainScopeHosted.Operations)
	assert.True(t, DomainScopeHosted.Upload)
}

func TestNewRequiresBuildServer(t *testing.T) {
	_, err := New(Options{DomainScope: DomainScopeHosted})
	require.Error(t, err, "New without BuildServer must fail fast, not return a hollow handler")
	assert.Contains(t, err.Error(), "BuildServer")
}

func TestNewDefaultsZeroScopeToHosted(t *testing.T) {
	var got DomainScope
	h, err := New(Options{
		BuildServer: func(cfg ServerConfig) (ServerBuildResult, error) {
			got = cfg.DomainScope
			return ServerBuildResult{Server: fakeServer()}, nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, DomainScopeHosted, got, "zero DomainScope defaults to the hosted surface")
}

func TestNewOAuthHandlerApplied(t *testing.T) {
	wrapped := false
	h, err := New(Options{
		DomainScope: DomainScopeHosted,
		BuildServer: func(cfg ServerConfig) (ServerBuildResult, error) {
			return ServerBuildResult{Server: fakeServer()}, nil
		},
		OAuthHandler: oauthStub{wrapped: &wrapped},
	})
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.True(t, wrapped, "OAuthHandler.WrapHTTP must be applied to the produced handler")

	// The produced handler must respond to a request without panicking.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
}

func TestNewBundleOnlyResolverDrivesHTTPBoundary(t *testing.T) {
	// The ONLY credential source is on the catalog-deps bundle. The reconciled
	// resolver must be threaded to BuildServer so both dispatch and the HTTP
	// credential middleware authenticate as that caller.
	bundleResolver := identityResolver{id: "bundle"}
	deps := &assembly.CatalogDepsBundle{CredentialResolver: bundleResolver}

	seenResolver := CredentialResolver(nil)
	h, err := New(Options{
		DomainScope: DomainScopeHosted,
		CatalogDeps: func() *assembly.CatalogDepsBundle { return deps },
		BuildServer: func(cfg ServerConfig) (ServerBuildResult, error) {
			seenResolver = cfg.CredentialResolver
			return ServerBuildResult{Server: fakeServer()}, nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, h)
	require.NotNil(t, seenResolver, "bundle resolver must be reconciled onto the construction config")
	assert.Equal(t, identityResolver{id: "bundle"}, seenResolver)
}

func TestNewConflictingResolversFailClosed(t *testing.T) {
	explicit := identityResolver{id: "explicit"}
	bundleResolver := identityResolver{id: "bundle"} // disagrees with explicit
	deps := &assembly.CatalogDepsBundle{CredentialResolver: bundleResolver}

	_, err := New(Options{
		DomainScope:        DomainScopeHosted,
		CatalogDeps:        func() *assembly.CatalogDepsBundle { return deps },
		CredentialResolver: explicit,
	})
	require.Error(t, err, "two observe-but-disagreeing resolvers must fail construction closed")
	assert.Contains(t, err.Error(), "conflicting credential resolvers")
}

func TestNewSameResolverAccepted(t *testing.T) {
	res := identityResolver{id: "same"}
	deps := &assembly.CatalogDepsBundle{CredentialResolver: res}

	h, err := New(Options{
		DomainScope:        DomainScopeHosted,
		CatalogDeps:        func() *assembly.CatalogDepsBundle { return deps },
		CredentialResolver: res,
		BuildServer: func(cfg ServerConfig) (ServerBuildResult, error) {
			return ServerBuildResult{Server: fakeServer()}, nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, h)
}

func TestNewNoTransferReturnsStreamableDirectly(t *testing.T) {
	h, err := New(Options{
		DomainScope: DomainScopeHosted,
		BuildServer: func(cfg ServerConfig) (ServerBuildResult, error) {
			return ServerBuildResult{Server: fakeServer()}, nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, h)
	// /mcp must be served (a request is routed/answered, not panicking).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	require.NotEqual(t, http.StatusNotFound, rec.Code, "/mcp must reach the streamable handler")
}
