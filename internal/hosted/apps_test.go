package hosted

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/canimcp"
	"go.lumeweb.com/mcpplane/model"
	"go.lumeweb.com/pinner/mcp"
	"go.lumeweb.com/pinner/mcp/appswire"
)

// TestHostedAppRowsSelection pins the deployable view set on a hosted embed:
// the transaction-capable hosted rows — pin creator (backed by the hosted
// pinning provider), account and pin list (dependency-free), and the upload /
// download managers (backed by the hosted presigned-upload and filedrop
// coordinators). The OOB rows (sso / password / email) and the Sia vault rows
// must never surface, because the advertised FeatMCPApps capability follows
// this set.
func TestHostedAppRowsSelection(t *testing.T) {
	rows := hostedAppRows()
	launchers := make([]string, 0, len(rows))
	for _, r := range rows {
		launchers = append(launchers, r.Launcher)
	}
	// Registration order is the shared table's load-direction order, which is
	// stable and authoritative (pin creator, account, pin list, upload
	// manager, download manager).
	require.Equal(t, []string{
		appswire.LauncherPinCreator,
		appswire.LauncherAccount,
		appswire.LauncherPinList,
		appswire.LauncherUploadManager,
		appswire.LauncherDownloadManager,
	}, launchers, "hosted surface must install exactly the five wired app views")

	// None of the capability-masked rows may appear.
	excluded := []string{
		appswire.LauncherSSOSignin,
		appswire.LauncherAccountPassword,
		appswire.LauncherAccountEmail,
		appswire.LauncherVaultCreate,
		appswire.LauncherVaultRestore,
		appswire.LauncherVaultBrowser,
		appswire.LauncherVaultManager,
		appswire.LauncherVaultDownloadMgr,
	}
	for _, name := range excluded {
		assert.NotContains(t, launchers, name, "view %q must not install on the hosted surface", name)
	}
}

// TestHostedLauncherNames returns the open_* launcher names that feed
// Config.InstalledApps — the vocabulary the assembly validates against the
// shared table's launcher names.
func TestHostedLauncherNames(t *testing.T) {
	launchers := hostedLauncherNames(hostedAppRows())
	require.Equal(t, []string{
		appswire.LauncherPinCreator,
		appswire.LauncherAccount,
		appswire.LauncherPinList,
		appswire.LauncherUploadManager,
		appswire.LauncherDownloadManager,
	}, launchers)

	screens := hostedScreens(hostedAppRows())
	require.Equal(t, []string{
		"pin_creator", "account", "pin_list", "upload_manager", "download_manager",
	}, screens)
}

// TestHostedProfileFeatMCPAppsFollowsInventory pins that the hosted profile
// only declares the MCP Apps capability when app views are actually wired, so
// the capability signal and the registered inventory cannot drift in either
// direction.
func TestHostedProfileFeatMCPAppsFollowsInventory(t *testing.T) {
	withApps := hostedProfile(hostedAppRows())
	require.True(t, withApps.Hosted, "hosted profile must mark the deployment hosted")
	assert.Equal(t, canimcp.TransportHTTP, withApps.Transport)
	require.True(t, withApps.Features.Has(mcp.FeatMCPApps),
		"a hosted assembly with installed views must advertise FeatMCPApps")

	withoutApps := hostedProfile(nil)
	require.False(t, withoutApps.Features.Has(mcp.FeatMCPApps),
		"an apps-less hosted assembly must NOT advertise FeatMCPApps")
}

// TestLauncherCatalogGet verifies the app-install attach catalog returns the
// per-app launcher entry carrying the view's ui:// resourceUri, so an app
// view can attach to its launcher.
func TestLauncherCatalogGet(t *testing.T) {
	cat := newLauncherCatalog(hostedAppRows(), nil)
	entry, ok := cat.Get(appswire.LauncherPinList)
	require.True(t, ok, "pin list launcher must be present for its view to attach")
	require.NotNil(t, entry.Meta)
	require.NotNil(t, entry.Meta["ui"], "launcher entry must carry the ui meta so the host renders the view")

	_, ok = cat.Get(appswire.LauncherVaultCreate)
	require.False(t, ok, "a view not wired on hosted must have no launcher entry")
}

// TestOpenAppDescriptor resolves installed views by both launcher name and
// bare screen name, rejects unknown views, and reports the installed
// inventory.
func TestOpenAppDescriptor(t *testing.T) {
	rows := hostedAppRows()
	desc := openAppDescriptor(rows)
	assert.Equal(t, "open_app", desc.Name)
	assert.Contains(t, desc.Description, "pin_creator, account, pin_list, upload_manager, download_manager")

	byLauncher, err := openAppRun(rows, hostedScreens(rows), openAppInput{App: appswire.LauncherPinList})
	require.NoError(t, err)
	require.False(t, byLauncher.IsError)
	sc := byLauncher.StructuredContent.(map[string]any)
	assert.Equal(t, appswire.LauncherPinList, sc["app"])
	assert.Equal(t, "ui://pins/list.html", sc["view"])

	byScreen, err := openAppRun(rows, hostedScreens(rows), openAppInput{App: "account"})
	require.NoError(t, err)
	assert.Equal(t, "ui://auth/status.html", byScreen.StructuredContent.(map[string]any)["view"])

	unknown, err := openAppRun(rows, hostedScreens(rows), openAppInput{App: "vault_create"})
	require.NoError(t, err)
	require.True(t, unknown.IsError)
	assert.Contains(t, unknown.Text, "unknown app")

	avail, _ := json.Marshal(byLauncher.StructuredContent.(map[string]any)["available"])
	assert.Contains(t, string(avail), `pin_list`, "open_app must enumerate the installed inventory")
	assert.Contains(t, string(avail), `account`)
	assert.NotContains(t, string(avail), `vault`)
}

// fakePinProvider is a stub pinStatusProvider for descriptor tests.
type fakePinProvider struct {
	statusFor func(cid string) string
}

func (f fakePinProvider) PinStatus(_ context.Context, cid string) (string, error) {
	return f.statusFor(cid), nil
}

// TestPinStatusDescriptorHandler verifies the pin creator's app-only poll
// helper surfaces the provider's status and rejects a missing CID.
func TestPinStatusDescriptorHandler(t *testing.T) {
	desc := pinStatusDescriptor(fakePinProvider{statusFor: func(cid string) string { return "pinned" }})
	require.Equal(t, "pin_status", desc.Name)

	res, err := desc.Handler(context.Background(), model.ToolRequest{
		Arguments: map[string]any{"cid": "bafyabc"},
	})
	require.NoError(t, err)
	require.False(t, res.IsError)
	assert.Equal(t, "pinned", res.StructuredContent.(map[string]any)["status"])

	missing, err := desc.Handler(context.Background(), model.ToolRequest{Arguments: map[string]any{}})
	require.NoError(t, err)
	require.True(t, missing.IsError)
	assert.Contains(t, missing.Text, "cid is required")
}

// TestUploadManagerRequiresPresignedCoordinator pins the fail-closed seal on
// the upload manager view: it is advertised (selection includes it) but must
// fail the assembly loudly when the presigned upload coordinator it binds is
// missing — never silently drop the view and drift the inventory.
func TestUploadManagerRequiresPresignedCoordinator(t *testing.T) {
	var rows []appswire.ViewSpec
	for _, r := range hostedAppRows() {
		if r.Launcher == appswire.LauncherUploadManager {
			rows = append(rows, r)
		}
	}
	require.Len(t, rows, 1, "upload manager must be selected on the hosted surface")

	installed, err := installHostedApps(nil, rows, "", nil, nil, nil)
	require.Error(t, err, "a nil presigned coordinator must fail the assembly")
	assert.Nil(t, installed)
	assert.Contains(t, err.Error(), "presigned upload coordinator")
}

// TestDownloadManagerRequiresFiledropCoordinator pins the fail-closed seal on
// the download manager view, mirroring the upload manager: it is advertised
// (selection includes it) but must fail the assembly loudly when the filedrop
// download coordinator it renders against is missing — never silently drop the
// view and drift the advertised inventory from the wired transfer backend.
func TestDownloadManagerRequiresFiledropCoordinator(t *testing.T) {
	var rows []appswire.ViewSpec
	for _, r := range hostedAppRows() {
		if r.Launcher == appswire.LauncherDownloadManager {
			rows = append(rows, r)
		}
	}
	require.Len(t, rows, 1, "download manager must be selected on the hosted surface")

	installed, err := installHostedApps(nil, rows, "", nil, nil, nil)
	require.Error(t, err, "a nil filedrop coordinator must fail the assembly")
	assert.Nil(t, installed)
	assert.Contains(t, err.Error(), "filedrop download coordinator")
}

// TestHostedVerifyInstalledOrderInsensitive checks hostedVerifyInstalled (the
// set-based check backing verifyApps and the post-install assertion) accepts
// the configured inventory in any order — the mcp.Assemble / appswire.Install
// may report launchers in a different order than the table load-order, so an
// order-sensitive comparison would spuriously fail the build.
func TestHostedVerifyInstalledOrderInsensitive(t *testing.T) {
	rows := hostedAppRows()
	launchers := hostedLauncherNames(rows)
	require.NotEmpty(t, launchers, "hosted surface must select some rows")

	// Reversed order must still satisfy the inventory check.
	reversed := make([]string, len(launchers))
	copy(reversed, launchers)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	assert.NoError(t, hostedVerifyInstalled(reversed, rows))

	// An extra launcher must fail (over-install).
	extra := append(append([]string{}, launchers...), "open_extra_view")
	assert.Error(t, hostedVerifyInstalled(extra, rows))

	// A missing launcher must fail (under-install).
	missing := launchers[:len(launchers)-1]
	assert.Error(t, hostedVerifyInstalled(missing, rows))
}

// TestHostedVerifyInstalledRejectsDuplicateUnderInstall checks a duplicate in
// `installed` with a matching length cannot silently drop a wired row: rows
// ["a","b"] vs installed ["a","a"] satisfies only the length check, so the
// wired row "b" must still be flagged as missing to keep the drift invariant
// bidirectional.
func TestHostedVerifyInstalledRejectsDuplicateUnderInstall(t *testing.T) {
	rows := hostedAppRows()
	require.GreaterOrEqual(t, len(rows), 2, "need at least two rows to exercise a duplicate")

	launchers := hostedLauncherNames(rows)
	dupe := append([]string{launchers[0], launchers[0]}, launchers[2:]...)
	require.Len(t, dupe, len(launchers), "duplicate must preserve total length")
	assert.Error(t, hostedVerifyInstalled(dupe, rows), "duplicate under-install must fail even when lengths match")
}
