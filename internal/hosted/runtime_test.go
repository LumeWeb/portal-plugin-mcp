package hosted

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/mcpplane/sdk"
	pinnermcp "go.lumeweb.com/pinner/mcp"
)

// TestBuildHostedServerAssemblesRealServer drives the REAL BuildServer seam
// (BuildHostedServer) through the construction boundary, using a CfgMgr-only
// catalog-deps bundle — the same shape api.go wires. It proves the runtime
// assembles a genuine SDK server from the public pinner mcp.Assemble contract
// and serves /mcp.
func TestBuildHostedServerAssemblesRealServer(t *testing.T) {
	depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
	require.NoError(t, err, "NewCatalogDeps must build the CfgMgr-only bundle")

	h, err := New(Options{
		DomainScope: DomainScopeHosted,
		CatalogDeps: depsFactory,
		BuildServer: BuildHostedServer,
	})
	require.NoError(t, err, "hosted.New with the real BuildServer must assemble a server")
	require.NotNil(t, h)

	// /mcp must be served by the assembled SDK server (a request is routed and
	// answered, never a 404 miss).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.NotEqual(t, http.StatusNotFound, rec.Code, "/mcp must reach the assembled streamable handler")
}

// TestBuildHostedServerRequiresBundle guards the BuildServer seam: without a
// catalog-deps bundle the runtime must fail loudly, never return a hollow
// server.
func TestBuildHostedServerRequiresBundle(t *testing.T) {
	_, err := BuildHostedServer(ServerConfig{DomainScope: DomainScopeHosted})
	require.Error(t, err, "BuildHostedServer without a bundle must fail fast")
	assert.Contains(t, err.Error(), "catalog deps")
}

// TestBuildHostedServerRegistersPromptAndResourceSurface locks hosted MCP
// parity with the local stdio composition: the assembled server must register
// the surface-gated prompts, resources, and resource templates projected by
// the public pinner mcp.Assemble contract, not just tools. It drives the real
// BuildServer seam over an in-memory MCP session and lists the prompt/resource
// surface through the official SDK client.
func TestBuildHostedServerRegistersPromptAndResourceSurface(t *testing.T) {
	depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
	require.NoError(t, err, "NewCatalogDeps must build the bundle")

	res, err := BuildHostedServer(ServerConfig{
		DomainScope: DomainScopeHosted,
		CatalogDeps: depsFactory,
	})
	require.NoError(t, err, "BuildHostedServer must assemble a server")
	require.NotNil(t, res.Server, "BuildHostedServer must return a server")

	ctx := context.Background()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	_, err = res.Server.Connect(ctx, serverTransport, nil)
	require.NoError(t, err, "server must connect over the in-memory transport")

	client := mcp.NewClient(&mcp.Implementation{Name: "pinner-test", Version: "v1"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err, "client must connect")
	defer cs.Close()

	prompts, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{})
	require.NoError(t, err, "prompts/list must succeed")
	assert.NotEmpty(t, prompts.Prompts, "hosted server must expose surface-gated prompts")

	resources, err := cs.ListResources(ctx, &mcp.ListResourcesParams{})
	require.NoError(t, err, "resources/list must succeed")
	assert.NotEmpty(t, resources.Resources, "hosted server must expose pinner:// resources")

	templates, err := cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{})
	require.NoError(t, err, "resources/templates/list must succeed")
	assert.NotEmpty(t, templates.ResourceTemplates, "hosted server must expose resource templates")
}

// TestBuildHostedServerDevToolsSurface locks the dev-tools opt-in: the
// read-only dev_* introspection tools must be absent from the production
// surface and present on tools/list only when the construction declares
// DevTools.
func TestBuildHostedServerDevToolsSurface(t *testing.T) {
	ctx := context.Background()
	connect := func(t *testing.T, devTools bool) map[string]bool {
		t.Helper()
		depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
		require.NoError(t, err, "NewCatalogDeps must build the bundle")

		res, err := BuildHostedServer(ServerConfig{
			DomainScope: DomainScopeHosted,
			CatalogDeps: depsFactory,
			DevTools:    devTools,
		})
		require.NoError(t, err, "BuildHostedServer must assemble a server")

		clientTransport, serverTransport := mcp.NewInMemoryTransports()
		_, err = res.Server.Connect(ctx, serverTransport, nil)
		require.NoError(t, err, "server must connect over the in-memory transport")

		client := mcp.NewClient(&mcp.Implementation{Name: "pinner-devtools-test", Version: "v1"}, nil)
		cs, err := client.Connect(ctx, clientTransport, nil)
		require.NoError(t, err, "client must connect")
		defer cs.Close()

		tools, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
		require.NoError(t, err, "tools/list must succeed")
		names := map[string]bool{}
		for _, tool := range tools.Tools {
			names[tool.Name] = true
		}
		return names
	}

	production := connect(t, false)
	assert.False(t, production["dev_host_env"])
	assert.False(t, production["dev_profile"])
	assert.False(t, production["dev_request"])

	dev := connect(t, true)
	assert.True(t, dev["dev_host_env"], "dev tools on: dev_host_env on tools/list")
	assert.True(t, dev["dev_profile"], "dev tools on: dev_profile on tools/list")
	assert.True(t, dev["dev_request"], "dev tools on: dev_request on tools/list")
}

// connectInMemory drives an assembled SDK server through an in-memory MCP
// session: it connects the server transport and a named SDK client, returning
// the client session for tools/list calls. Sessions close with the test.
func connectInMemory(t *testing.T, srv *sdk.Server, client *mcp.Client) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	_, err := srv.Connect(ctx, serverTransport, nil)
	require.NoError(t, err, "server must connect over the in-memory transport")
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err, "client must connect")
	t.Cleanup(func() { cs.Close() })
	return cs
}

// TestBuildHostedServerMetaToolsSurface locks the progressive-discovery meta
// tools as the shared pinner/mcp presentation surface: the five upstream
// meta-tool descriptors register on tools/list whenever the RESOLVED listing
// policy serves them (the hosted flat web policy keeps meta-on-flat by
// default), and disappear when the policy opts out with
// IncludeMetaOnFlat=false — while the direct surface itself stays wired.
func TestBuildHostedServerMetaToolsSurface(t *testing.T) {
	connect := func(t *testing.T, listing *pinnermcp.ListingPolicy) map[string]bool {
		t.Helper()

		depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
		require.NoError(t, err, "NewCatalogDeps must build the bundle")

		res, err := BuildHostedServer(ServerConfig{
			DomainScope: DomainScopeHosted,
			CatalogDeps: depsFactory,
			Listing:     listing,
		})
		require.NoError(t, err, "BuildHostedServer must assemble a server")

		client := mcp.NewClient(&mcp.Implementation{Name: "pinner-meta-test", Version: "v1"}, nil)
		clientSession := connectInMemory(t, res.Server, client)

		tools, err := clientSession.ListTools(context.Background(), &mcp.ListToolsParams{})
		require.NoError(t, err, "tools/list must succeed")
		names := map[string]bool{}
		for _, tool := range tools.Tools {
			names[tool.Name] = true
		}
		return names
	}

	optOutFlat := pinnermcp.ListingPolicy{
		Strategy:          pinnermcp.ListingFlat,
		IncludeMetaOnFlat: &[]bool{false}[0],
	}
	noMeta := connect(t, &optOutFlat)
	for _, name := range pinnermcp.MetaToolNames() {
		assert.False(t, noMeta[name], "meta-on-flat opt-out: %s must be absent from tools/list", name)
	}
	assert.True(t, noMeta["agent_guide"], "opt-out still serves the direct surface")

	withMeta := connect(t, nil)
	for _, name := range pinnermcp.MetaToolNames() {
		assert.True(t, withMeta[name], "resolved policy serves meta tools: %s on tools/list", name)
	}
}
