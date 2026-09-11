package hosted

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/pinner/assembly"
	"go.lumeweb.com/pinner/mcp"
)

// hostedTestBundle builds the same CfgMgr-only catalog-deps bundle the real
// api.go wiring uses, for driving the transfer wiring and the assembly beyond
// the harness bundle.
func hostedTestBundle(t *testing.T) func() *assembly.CatalogDepsBundle {
	t.Helper()
	depsFactory, err := NewCatalogDeps("https://pinner.xyz", true, BuildCatalogDeps)
	require.NoError(t, err, "NewCatalogDeps must build the CfgMgr-only bundle")
	return depsFactory
}

// TestHostedBuildServerWiresByteRoutes pins the byte-route blocker: the plugin
// owns concrete uploads/download services (in internal/hosted), and once wired
// into BuildHostedServer the returned ServerBuildResult carries real
// /upload and /download coordinators instead of nil. That is what lets
// hosted.New mount the presigned PUT and filedrop GET routes.
func TestHostedBuildServerWiresByteRoutes(t *testing.T) {
	depsFactory := hostedTestBundle(t)
	res, err := BuildHostedServer(ServerConfig{
		DomainScope: DomainScopeHosted,
		CatalogDeps: depsFactory,
		BaseURL:     "https://pinner.xyz/mcp",
	})
	require.NoError(t, err, "BuildHostedServer must assemble with transfer wiring")
	require.NotNil(t, res.Server, "an assembled SDK server is required")
	require.NotNil(t, res.Transfer.Upload, "the presigned upload PUT coordinator must be wired")
	require.NotNil(t, res.Transfer.Download, "the filedrop GET coordinator must be wired")
}

// TestHostedByteRouteSurfaceRegistersDirectTools asserts that the assembled
// direct surface (agent guide, capabilities, and the wired upload/download
// transfer tools) is present once TransferDeps is threaded into mcp.Assemble.
// This is the listing/progressive-discovery parity the hosted surface needs:
// tools/list must expose the transfer tools the byte routes back, plus the
// guide and capabilities helpers.
func TestHostedByteRouteSurfaceRegistersDirectTools(t *testing.T) {
	depsFactory := hostedTestBundle(t)
	bundle := depsFactory()

	transferDeps, coordinators, err := buildHostedTransfer(ServerConfig{
		DomainScope: DomainScopeHosted,
		CatalogDeps: depsFactory,
		BaseURL:     "https://pinner.xyz/mcp",
	}, bundle)
	require.NoError(t, err)
	require.NotNil(t, coordinators.Upload)
	require.NotNil(t, coordinators.Download)

	presentation, err := mcp.Assemble(mcp.Config{
		DomainScope: toAssemblyScope(DomainScopeHosted),
		Hosted:      true,
		Deps:        bundle,
		Transfer:    transferDeps,
	})
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, d := range presentation.Direct {
		names[d.Name] = true
	}
	for _, want := range []string{"agent_guide", "capabilities", "upload_file", "download_file"} {
		assert.True(t, names[want], "direct surface must include %q (got %v)", want, names)
	}
}
