package hosted

import (
	"testing"

	"go.lumeweb.com/canimcp"
	pinnermcp "go.lumeweb.com/pinner/mcp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHostedWebListingPolicyConsumesSharedSelector verifies the hosted
// construction root resolves the SHARED tool-listing policy for its web
// audience: every hosted web host (Claude Web, Grok Web, ChatGPT/OpenAI Web)
// selects flat through the shared pinner/mcp.PolicyForHost selector, and the
// hosted root therefore declares the same flat strategy — never a drifted
// copy of the host→strategy decision.
func TestHostedWebListingPolicyConsumesSharedSelector(t *testing.T) {
	p := hostedWebListingPolicy()
	require.NoError(t, p.Validate(), "hosted web policy must be a valid shared listing policy")
	assert.Equal(t, pinnermcp.ListingFlat, p.Strategy, "hosted web assembly must declare flat tools/list")

	// The shared selector maps every hosted web host to the same flat strategy,
	// so the single resolved hosted policy is consistent with each web audience.
	flat := []struct {
		host      canimcp.HostType
		transport canimcp.TransportKind
	}{
		{canimcp.HostClaude, canimcp.TransportHTTP},
		{canimcp.HostGrok, canimcp.TransportHTTP},
		{canimcp.HostChatGPT, canimcp.TransportHTTP},
		{canimcp.HostOpenAI, canimcp.TransportOpenAI},
	}
	for _, tc := range flat {
		assert.Equalf(t, pinnermcp.ListingFlat, pinnermcp.PolicyForHost(tc.host, tc.transport).Strategy,
			"shared selector must flag %s/%s flat", tc.host, tc.transport)
	}
}

// TestBuildHostedServerResolvesSharedFlatListing drives the REAL BuildServer
// seam and asserts the assembled server's resolved listing policy is the
// shared flat policy for the hosted web audience — the same value the hosted
// wire registration (which lists every compiled op directly) materializes.
func TestBuildHostedServerResolvesSharedFlatListing(t *testing.T) {
	depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
	require.NoError(t, err, "NewCatalogDeps must build the bundle")

	res, err := BuildHostedServer(ServerConfig{
		DomainScope: DomainScopeHosted,
		CatalogDeps: depsFactory,
	})
	require.NoError(t, err, "BuildHostedServer must assemble a server")
	require.NotNil(t, res.Server)
	assert.Equal(t, pinnermcp.ListingFlat, res.Listing.Strategy, "hosted default must resolve the shared flat policy")
}

// TestBuildHostedServerHonorsExplicitListing verifies an embedding host can
// override the shared flat default with an explicit progressive policy, and
// that the override is what the assembly resolves (never overridden back).
func TestBuildHostedServerHonorsExplicitListing(t *testing.T) {
	depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
	require.NoError(t, err)

	progressive := pinnermcp.DefaultPolicy() // shared progressive default
	res, err := BuildHostedServer(ServerConfig{
		DomainScope: DomainScopeHosted,
		CatalogDeps: depsFactory,
		Listing:     &progressive,
	})
	require.NoError(t, err)
	assert.Equal(t, pinnermcp.ListingProgressive, res.Listing.Strategy,
		"an explicit policy override must win over the hosted flat default")
}

// TestNewThreadsListingToBuildServer verifies Options.Listing is threaded
// through the construction boundary into the BuildServer seam, so an embedding
// host can supply the shared policy it resolved for its audience.
func TestNewThreadsListingToBuildServer(t *testing.T) {
	var got *pinnermcp.ListingPolicy
	progressive := pinnermcp.DefaultPolicy()
	h, err := New(Options{
		DomainScope: DomainScopeHosted,
		Listing:     &progressive,
		BuildServer: func(cfg ServerConfig) (ServerBuildResult, error) {
			got = cfg.Listing
			return ServerBuildResult{Server: fakeServer()}, nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, h)
	require.NotNil(t, got, "Options.Listing must reach the BuildServer seam")
	assert.Equal(t, pinnermcp.ListingProgressive, got.Strategy)
}
