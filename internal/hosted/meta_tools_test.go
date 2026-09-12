package hosted

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	pinnermcp "go.lumeweb.com/pinner/mcp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// metaToolNames are the five progressive-discovery meta-tools the hosted
// server must register whenever the resolved listing policy serves them.
var metaToolNames = []string{
	metaToolSearch,
	metaToolDescribe,
	metaToolInvokeRead,
	metaToolInvokeWrite,
	metaToolInvokeDestructive,
}

// hostedTestBuild assembles a REAL hosted server through the BuildServer seam
// with the given explicit listing policy (nil = resolved hosted default). It
// returns the build result plus a connected in-memory MCP client session for
// wire-level tools/list assertions.
func hostedTestBuild(t *testing.T, listing *pinnermcp.ListingPolicy) (ServerBuildResult, *mcp.ClientSession) {
	t.Helper()
	depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
	require.NoError(t, err, "NewCatalogDeps must build the bundle")

	res, err := BuildHostedServer(ServerConfig{
		DomainScope: DomainScopeHosted,
		CatalogDeps: depsFactory,
		Listing:     listing,
	})
	require.NoError(t, err, "BuildHostedServer must assemble a server")
	require.NotNil(t, res.Server, "BuildHostedServer must return an assembled server")

	cs := connectOfficialClient(t, res.Server)
	return res, cs
}

// connectOfficialClient wires an in-memory client session to the SDK server
// so tests observe the actual wire tools/list surface.
func connectOfficialClient(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// listedToolNames pages the full tools/list surface of the connected session.
func listedToolNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err, "tools/list must resolve against the hosted server")
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

// assembledPresentDirectNames re-assembles the SAME presentation
// BuildHostedServer projects (same scope/hosted flag/listing), returning the
// direct-only plus direct-visible tool names that tools/list must carry.
func assembledPresentDirectNames(t *testing.T, listing pinnermcp.ListingPolicy) map[string]bool {
	t.Helper()
	depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
	require.NoError(t, err)
	bundle := depsFactory()
	transferDeps, _, err := buildHostedTransfer(ServerConfig{
		DomainScope: DomainScopeHosted,
		CatalogDeps: depsFactory,
	}, bundle)
	require.NoError(t, err)

	present, err := pinnermcp.Assemble(pinnermcp.Config{
		DomainScope: toAssemblyScope(DomainScopeHosted),
		Hosted:      true,
		Deps:        bundle,
		Transfer:    transferDeps,
		Listing:     &listing,
	})
	require.NoError(t, err)

	names := map[string]bool{}
	for _, d := range present.Direct {
		names[d.Name] = true
	}
	for _, tool := range present.Tools {
		if tool.DirectVisible {
			names[tool.Name] = true
		}
	}
	return names
}

// TestHostedDefaultFlatRetainsMetaTools pins the default hosted surface: the
// resolved policy is the shared flat web policy, whose safe default KEEPS
// the progressive-disclosure meta-tools on tools/list alongside the full flat
// direct surface. IncludeMetaOnFlat explicitly false is the only opt-out.
func TestHostedDefaultFlatRetainsMetaTools(t *testing.T) {
	res, cs := hostedTestBuild(t, nil)

	assert.Equal(t, pinnermcp.ListingFlat, res.Listing.Strategy,
		"hosted default must resolve the shared flat policy")
	assert.True(t, res.Listing.ResolveIncludeMetaOnFlat(),
		"the hosted default must KEEP the meta tools on the flat surface")

	names := listedToolNames(t, cs)
	for _, name := range metaToolNames {
		assert.Truef(t, names[name], "default flat surface must retain meta tool %q (got %v)", name, names)
	}
	// The flat direct surface is untouched: direct-only tools and the
	// agent-safe compiled ops remain materialized.
	for _, name := range []string{"agent_guide", "capabilities", "upload_file", "download_file", "pins_list"} {
		assert.Truef(t, names[name], "default flat surface must keep direct tool %q (got %v)", name, names)
	}
}

// TestHostedExplicitProgressiveRetainsMetaTools pins the explicit progressive
// policy: the meta-tools are always served, the direct surface is the
// DirectVisible set (nothing else is materialized directly), and the
// discovery loop actually resolves a search against the indexed surface.
func TestHostedExplicitProgressiveRetainsMetaTools(t *testing.T) {
	progressive := pinnermcp.DefaultPolicy()
	res, cs := hostedTestBuild(t, &progressive)

	assert.Equal(t, pinnermcp.ListingProgressive, res.Listing.Strategy)

	names := listedToolNames(t, cs)

	// The meta-tools are always present under progressive.
	for _, name := range metaToolNames {
		assert.Truef(t, names[name], "progressive surface must register meta tool %q (got %v)", name, names)
	}
	// Direct-only tools stay materialized.
	for _, name := range []string{"agent_guide", "capabilities"} {
		assert.Truef(t, names[name], "progressive surface must keep direct tool %q (got %v)", name, names)
	}

	// tools/list carries EXACTLY the direct set plus the meta-tools: no
	// non-direct compiled op is materialized directly under progressive.
	allowed := assembledPresentDirectNames(t, progressive)
	for _, name := range metaToolNames {
		allowed[name] = true
	}
	for name := range names {
		assert.Truef(t, allowed[name],
			"progressive tools/list must not materialize %q directly (not DirectVisible/direct/meta)", name)
	}

	// The discovery loop works end to end: search_tools("pin") finds the
	// compiled pins ops through the meta surface.
	call, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      metaToolSearch,
		Arguments: map[string]any{"query": "pins"},
	})
	require.NoError(t, err)
	require.False(t, call.IsError, "search_tools must resolve successfully")
	require.NotEmpty(t, call.Content, "search_tools must return content")
	text, ok := call.Content[0].(*mcp.TextContent)
	require.True(t, ok, "search_tools must return text content")
	var found searchResult
	require.NoError(t, json.Unmarshal([]byte(text.Text), &found), "search_tools result must be the search envelope")
	assert.Positive(t, found.Total, "searching 'pins' must surface the pins tools")
	assert.NotEmpty(t, found.Tools, "search_tools must return matching tool summaries")
}

// TestHostedExplicitFlatWithoutMetaOmitsMetaTools pins the explicit opt-out:
// a flat policy with IncludeMetaOnFlat: false is the one case that hides the
// progressive-discovery meta-tools from tools/list, while the full flat
// direct surface stays materialized.
func TestHostedExplicitFlatWithoutMetaOmitsMetaTools(t *testing.T) {
	explicitOff := false
	flatNoMeta := pinnermcp.ListingPolicy{
		Strategy:          pinnermcp.ListingFlat,
		IncludeMetaOnFlat: &explicitOff,
	}
	res, cs := hostedTestBuild(t, &flatNoMeta)

	assert.Equal(t, pinnermcp.ListingFlat, res.Listing.Strategy)
	// The one and only opt-out is the EXPLICIT false switch: an unset (nil)
	// switch under flat must retain the meta tools, never omit them.
	assert.True(t, servesMetaTools(pinnermcp.ListingPolicy{Strategy: pinnermcp.ListingFlat}),
		"flat with an UNSET IncludeMetaOnFlat must retain the meta tools")
	require.NotNil(t, res.Listing.IncludeMetaOnFlat,
		"the explicit opt-out policy must carry the non-nil IncludeMetaOnFlat switch")
	assert.False(t, *res.Listing.IncludeMetaOnFlat,
		"the explicit opt-out must resolve to false, not the unset default")

	names := listedToolNames(t, cs)
	for _, name := range metaToolNames {
		assert.Falsef(t, names[name],
			"flat with IncludeMetaOnFlat=false must omit meta tool %q from tools/list", name)
	}
	// The full flat direct surface remains materialized.
	for _, name := range []string{"agent_guide", "capabilities", "upload_file", "download_file", "pins_list"} {
		assert.Truef(t, names[name], "explicit flat surface must keep direct tool %q (got %v)", name, names)
	}
}

// TestHostedSearchTotalReportsPreCapCount pins the truthful-total contract:
// when a limit truncates search results (or the onboarding listing), Total
// must report the pre-cap match count so a capped response still signals that
// additional matches were truncated rather than silently capping discovery at
// exactly the requested limit.
func TestHostedSearchTotalReportsPreCapCount(t *testing.T) {
	progressive := pinnermcp.DefaultPolicy()
	_, cs := hostedTestBuild(t, &progressive)

	callSearch := func(args map[string]any) searchResult {
		t.Helper()
		call, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      metaToolSearch,
			Arguments: args,
		})
		require.NoError(t, err)
		require.False(t, call.IsError, "search_tools must resolve successfully")
		require.NotEmpty(t, call.Content, "search_tools must return content")
		text, ok := call.Content[0].(*mcp.TextContent)
		require.True(t, ok, "search_tools must return text content")
		var res searchResult
		require.NoError(t, json.Unmarshal([]byte(text.Text), &res), "must decode the search envelope")
		return res
	}

	// No limit: every match is returned and Total equals the returned count.
	unbounded := callSearch(map[string]any{"query": "pins"})
	require.Positive(t, unbounded.Total, "searching 'pins' must match tools")
	assert.Equal(t, len(unbounded.Tools), unbounded.Total,
		"without a limit Total must equal the returned tool count")

	// limit=1 truncates, but Total must still report the pre-cap count.
	capped := callSearch(map[string]any{"query": "pins", "limit": 1})
	require.Len(t, capped.Tools, 1, "limit=1 must cap the returned tools")
	assert.Equal(t, unbounded.Total, capped.Total,
		"Total must stay at the pre-cap match count when results are truncated")
	assert.Greater(t, capped.Total, len(capped.Tools),
		"truncation must be visible: Total must exceed the returned tool count")

	// Onboarding (empty query) honors the limit while keeping the pre-cap total.
	onboardCapped := callSearch(map[string]any{"limit": 1})
	require.Len(t, onboardCapped.Tools, 1, "onboarding must honor the limit contract")
	assert.Greater(t, onboardCapped.Total, len(onboardCapped.Tools),
		"onboarding Total must report the pre-cap count, not the capped length")
}
