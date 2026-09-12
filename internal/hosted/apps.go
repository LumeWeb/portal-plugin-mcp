package hosted

// This file wires pinner's shared MCP App table (go.lumeweb.com/pinner/mcp/appswire)
// onto a hosted (Portal-embedded) server, following pinner-cli #695. The
// hosted profile advertises FeatMCPApps only when hosted-selectable views
// install; open_app is the single directly-listed launcher; the installed
// inventory feeds the agent-guide prose.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/samber/lo"
	"go.lumeweb.com/canimcp"
	"go.lumeweb.com/mcpforge"
	mcpapps "go.lumeweb.com/mcpplane/apps"
	"go.lumeweb.com/mcpplane/credctx"
	"go.lumeweb.com/mcpplane/model"
	"go.lumeweb.com/mcpplane/sdk"
	"go.lumeweb.com/mcpplane/transfer"
	"go.lumeweb.com/pinner/canvas"
	"go.lumeweb.com/pinner/canvasassets"
	"go.lumeweb.com/pinner/catalogops"
	"go.lumeweb.com/pinner/core/config"
	"go.lumeweb.com/pinner/core/pinning"
	"go.lumeweb.com/pinner/mcp"
	"go.lumeweb.com/pinner/mcp/appswire"
	"go.lumeweb.com/pinner/mcp/hosted"
)

// hostedAppRows returns the app-view rows this hosted embed installs: the
// shared table's CapHosted rows whose dependencies this deployment wires.
// Hosted wires no out-of-band coordinators (CapOOB sign-in/password/email) and
// no Sia vault (CapVault), so the mask excludes those rows.
func hostedAppRows() []appswire.ViewSpec {
	return appswire.Selectable(appswire.CapHosted, hostedViewAvailable)
}

// hostedViewAvailable reports whether this deployment supplies a row's
// dependencies. It is opt-in and fails closed: a CapHosted row installs only
// when wired here, so a row whose dependencies are missing is neither
// advertised nor installed. Keep it in lockstep with what installHostedApps
// installs, so the advertised capability and the registered inventory cannot
// drift.
func hostedViewAvailable(v appswire.ViewSpec) bool {
	switch v.Launcher {
	case appswire.LauncherAccount, appswire.LauncherPinList, appswire.LauncherPinCreator,
		appswire.LauncherUploadManager, appswire.LauncherDownloadManager:
		// The account and pin list screens are dependency-free, attaching to
		// headless tools the hosted scope always registers; the pin creator
		// screen is backed by the hosted pinning provider (its pin_status
		// poll helper is wired by installHostedApps); the upload and download
		// manager screens are backed by the hosted presigned-upload and
		// filedrop-download coordinators built in buildHostedTransfer.
		return true
	default:
		// The Sia vault rows and the OOB-coordinator rows both carry
		// dependencies not wired here; a future hosting that wires one flips
		// it on explicitly so it is advertised AND installed together.
		return false
	}
}

// hostedLauncherNames returns rows' open_* launcher names, the
// Config.InstalledApps vocabulary. The assembly validates these against the
// table's launcher names (SpecForLauncher), not screen names.
func hostedLauncherNames(rows []appswire.ViewSpec) []string {
	return lo.Map(rows, func(r appswire.ViewSpec, _ int) string { return r.Launcher })
}

// hostedScreens returns rows' screen names, the inventory the consolidated
// open_app launcher enumerates in prose and results (e.g. "account", "pin_list").
func hostedScreens(rows []appswire.ViewSpec) []string {
	return lo.Map(rows, func(r appswire.ViewSpec, _ int) string { return r.Screen() })
}

// hostedProfile is the platform profile a hosted assembly resolves its
// feature-gated presentation against. Hosted has no detected per-host profile,
// so without an explicit one it would fall back to the bare HTTP transport
// profile, which carries no FeatMCPApps even when views are about to install.
// FeatMCPApps therefore follows the installed inventory, not the transport.
func hostedProfile(rows []appswire.ViewSpec) mcp.HostProfile {
	features := mcpforge.FeatureSet{
		mcp.FeatSourceMint:   true,
		mcp.FeatSinkLocal:    true,
		mcp.FeatSinkDrop:     true,
		mcp.FeatRemoteAccess: true,
	}
	if len(rows) > 0 {
		features[mcp.FeatMCPApps] = true
	}
	return mcp.HostProfile{
		Features:  features,
		Transport: canimcp.TransportHTTP,
		Host:      canimcp.HostGeneric,
		Hosted:    true,
	}
}

// launcherCatalog is the narrow AppCatalog the install attaches views
// through. Views attach only to their own open_* launcher, so the catalog
// needs just those entries for RegisterAppView's attach-target validation and
// _meta.ui stamping.
type launcherCatalog struct {
	entries map[string]*model.ToolEntry
}

func newLauncherCatalog(rows []appswire.ViewSpec, hp *transfer.Upload) *launcherCatalog {
	c := &launcherCatalog{entries: map[string]*model.ToolEntry{}}
	for _, row := range rows {
		desc, err := row.NewLauncherDescriptorFor()
		if err != nil {
			// Rows here are all standard; a marshal failure is a programming
			// error.
			panic("hosted: build launcher descriptor for " + row.Launcher + ": " + err.Error())
		}
		c.entries[row.Launcher] = model.ToolEntryFromDescriptor(desc)
	}
	// The upload manager row is composition-owned (CustomDescriptor): its
	// launcher carries the presigned-PUT input schema and coordinator, so use
	// the shared seam's descriptor rather than the generic no-arg launcher.
	if hp != nil {
		desc, err := appswire.UploadManagerDescriptor(hp)
		if err != nil {
			panic("hosted: build upload manager launcher descriptor: " + err.Error())
		}
		c.entries[appswire.LauncherUploadManager] = model.ToolEntryFromDescriptor(desc)
	}
	return c
}

// Get implements mcpapps.AppCatalog.
func (c *launcherCatalog) Get(name string) (*model.ToolEntry, bool) {
	e, ok := c.entries[name]
	return e, ok
}

// rowForView returns the table row rendering the given canvas view, so the
// app document can use the row's resource title.
func rowForView(rows []appswire.ViewSpec, view canvas.View) (appswire.ViewSpec, bool) {
	for _, r := range rows {
		if r.View == view {
			return r, true
		}
	}
	return appswire.ViewSpec{}, false
}

// pinStatusProvider is the read the "Create a Pin" view needs: a pin's status
// so the app can poll until it settles.
type pinStatusProvider interface {
	// PinStatus returns the current status of the pinned CID.
	PinStatus(ctx context.Context, cid string) (string, error)
}

// hostedPinProvider adapts the hosted PinningService (pinner core/pinning) to
// pinStatusProvider. It builds the service per call from the request's hosted
// credential (credctx), falling back to the config token when no credential is
// present.
type hostedPinProvider struct {
	buildSvc func(ctx context.Context) (pinning.PinningService, error)
}

// newHostedPinProvider builds the pin creator's poll provider from the
// catalog PinsDeps: each call pins a PinningService to the request credential
// (credctx), else the config token, matching the PinsDeps factories.
func newHostedPinProvider(pins catalogops.PinsDeps, cfgMgr config.Manager, secure bool) *hostedPinProvider {
	return &hostedPinProvider{
		buildSvc: func(ctx context.Context) (pinning.PinningService, error) {
			if tok := credctx.From(ctx); tok != "" {
				return pins.NewAuthenticated(cfgMgr, secure, tok), nil
			}
			return pins.ServiceFactory(cfgMgr, secure), nil
		},
	}
}

// PinStatus implements pinStatusProvider.
func (p *hostedPinProvider) PinStatus(ctx context.Context, cid string) (string, error) {
	svc, err := p.buildSvc(ctx)
	if err != nil {
		return "", err
	}
	status, err := svc.Status(ctx, cid, false)
	if err != nil {
		return "", err
	}
	return status.Status, nil
}

// pinStatusDescriptor builds the app-only pin status helper for the "Create a
// Pin" view. It is visible to the app only (never the model) and shares the
// pin create view; the app calls it via callServerTool to poll until terminal.
func pinStatusDescriptor(provider pinStatusProvider) model.ToolDescriptor {
	return model.ToolDescriptor{
		Name:        "pin_status",
		Title:       "Get pin status",
		Description: "Poll the current status of a pinned CID. App-only helper for the Create a Pin view.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"cid":{"type":"string","description":"The IPFS CID being pinned."}},"required":["cid"]}`),
		Meta: map[string]any{
			"openai/toolInvocation": map[string]any{
				"invoking": "Checking pin status…",
				"invoked":  "Pin status checked",
			},
		},
		ReadOnly: true, // pure status poll: reads pin state, mutates nothing and is safe to retry
		Handler: func(ctx context.Context, req model.ToolRequest) (model.ToolResult, error) {
			cid, _ := req.Arguments["cid"].(string)
			if cid == "" {
				return model.ToolResult{IsError: true, Text: "cid is required"}, nil
			}
			status, err := provider.PinStatus(ctx, cid)
			if err != nil {
				return model.ToolResult{IsError: true, Text: err.Error()}, nil
			}
			return model.ToolResult{
				Text:              status + ": " + cid,
				StructuredContent: map[string]any{"status": status, "cid": cid},
			}, nil
		},
	}
}

// installHostedApps installs rows' app views on srv, returning the launcher
// names that installed. Views render through the shared canvasassets seam; a
// per-server app registry records the ui:// resources and tool→view
// associations.
//
// pins backs the "Create a Pin" view's pin_status poll helper, hp backs the
// upload manager's custom launcher/helpers/connect-domains via the appswire
// upload-manager seam, and dl is the filedrop coordinator for the download
// view.
func installHostedApps(srv *sdk.Server, rows []appswire.ViewSpec, baseURL string, pins pinStatusProvider, hp *transfer.Upload, dl *transfer.Download) ([]string, error) {
	registry := mcpapps.NewAppRegistry()
	if baseURL != "" {
		// Attribute every ui:// view to the externally reachable origin so the
		// rendered app meta resolves against the real deployment. The resolver
		// domain must be the bare origin (the exact-origin check rejects
		// pathed domains), while BaseURL itself may carry the resource path
		// for coordinator presign URL minting.
		registry.SetViewDomainResolver(func() string { return hosted.HTTPSOriginOf(baseURL) })
	}

	render := func(view canvas.View) string {
		if row, ok := rowForView(rows, view); ok {
			return canvasassets.RenderAppDoc(view, row.ResourceTitle)
		}
		return canvasassets.RenderAppDoc(view, string(view))
	}

	installers := appswire.Installers{}
	var helpers map[string][]model.ToolDescriptor
	if pins != nil {
		helpers = map[string][]model.ToolDescriptor{
			appswire.LauncherPinCreator: {pinStatusDescriptor(pins)},
		}
	}
	for _, row := range rows {
		switch row.Launcher {
		case appswire.LauncherUploadManager:
			if hp == nil {
				// Advertised here, so a nil coordinator is a wiring bug.
				return nil, fmt.Errorf("hosted MCP server: upload manager view requires the presigned upload coordinator")
			}
			installers[row.Launcher] = appswire.UploadManagerInstaller(hp)
			continue
		case appswire.LauncherPinCreator:
			if pins == nil {
				// Advertised here, so a nil provider would leave the view
				// without its pin_status poll helper.
				return nil, fmt.Errorf("hosted MCP server: pin creator view requires the pinned pinning provider")
			}
		case appswire.LauncherDownloadManager:
			// The download row isn't a CustomDescriptor, so the shared
			// ViewInstaller registers it; only its backend coord needs a nil
			// guard, matching the upload row.
			if dl == nil {
				return nil, fmt.Errorf("hosted MCP server: download manager view requires the filedrop download coordinator")
			}
		}
		installers[row.Launcher] = row.ViewInstaller()
	}

	installed, err := appswire.Install(srv, newLauncherCatalog(rows, hp), rows, installers, appswire.InstallOptions{
		Registry: registry,
		Render:   render,
		Helpers:  helpers,
	})
	if err != nil {
		return nil, fmt.Errorf("hosted MCP server: install app views: %w", err)
	}
	return installed, nil
}

// appInstallMu serializes the scoped app-install registration. The SDK
// tool-registrar seam is process-global; even with capture/restore, two
// overlapping installs would interleave set/restore, so the whole install
// holds one lock.
var appInstallMu sync.Mutex

// installHostedAppsSerialized installs the hosted app views under a process
// lock, scoping the app-only helper registration (via the SDK tool-registrar
// seam) to this build's deps. It captures the prior adapter with
// sdk.GetToolRegistrar, installs a scoped one for installHostedApps, and
// restores it afterwards, so a concurrent build or another component's
// registrar is preserved.
func installHostedAppsSerialized(srv *sdk.Server, deps sdk.HandlerDeps, rows []appswire.ViewSpec, baseURL string, pins pinStatusProvider, hp *transfer.Upload, dl *transfer.Download) ([]string, error) {
	appInstallMu.Lock()
	defer appInstallMu.Unlock()

	prev := sdk.GetToolRegistrar()
	sdk.SetToolRegistrar(func(s *sdk.Server, desc model.ToolDescriptor, handler model.ToolHandler) error {
		desc.Handler = handler
		return sdk.RegisterTool(s, deps, desc)
	})
	defer sdk.SetToolRegistrar(prev)

	return installHostedApps(srv, rows, baseURL, pins, hp, dl)
}

// hostedVerifyInstalled checks the installed launcher set equals the wired
// rows bidirectionally, so the advertised inventory (InstalledApps) and the
// wire surface can't drift: an over- or under-install fails the build. The
// length check alone is not enough — a duplicate in `installed` (e.g. ["a","a"]
// for rows ["a","b"]) would satisfy it while silently dropping row "b", so
// every wired row must also appear in the installed set.
func hostedVerifyInstalled(installed []string, rows []appswire.ViewSpec) error {
	if len(installed) != len(rows) {
		return fmt.Errorf("hosted MCP server: installed %d app views, wired %d", len(installed), len(rows))
	}
	installedSet := make(map[string]struct{}, len(installed))
	for _, name := range installed {
		installedSet[name] = struct{}{}
	}
	for _, r := range rows {
		if _, ok := installedSet[r.Launcher]; !ok {
			return fmt.Errorf("hosted MCP server: wired app view %q was not installed", r.Launcher)
		}
	}
	return nil
}

// resolveOpenApp resolves an app request (an open_* launcher name or its bare
// screen name) to the launcher name and ui:// resource URI of an installed
// view, or returns false.
func resolveOpenApp(rows []appswire.ViewSpec, requested string) (string, string, bool) {
	req := strings.TrimSpace(strings.ToLower(requested))
	if req == "" {
		return "", "", false
	}
	for _, r := range rows {
		if r.Launcher == req || r.Screen() == req {
			return r.Launcher, r.URI, true
		}
	}
	return "", "", false
}

// openAppInputSchema is the argument schema of the consolidated open_app tool.
const openAppInputSchema = `{"type":"object","properties":{"app":{"type":"string","description":"Which app view to open (e.g. pin_list, account)."}},"required":["app"]}`

// openAppDescriptor builds the consolidated open_app launcher, the single
// directly-listed app launcher on the hosted surface (per pinner-cli #695).
// Its handler resolves an app request to an installed view's ui:// URI.
func openAppDescriptor(rows []appswire.ViewSpec) model.ToolDescriptor {
	screens := hostedScreens(rows)
	description := "Open one of Pinner's interactive app views by name (" + strings.Join(screens, ", ") +
		"). The host renders the returned ui:// view as an iframe. Prefer headless " +
		"primitives (pins_list, auth_status, upload_file, download_file) for autonomous workflows."
	return model.ToolDescriptor{
		Name:        "open_app",
		Title:       "Open an app",
		Description: description,
		Category:    model.CategoryCore,
		InputSchema: json.RawMessage(openAppInputSchema),
		Handler: func(ctx context.Context, request model.ToolRequest) (model.ToolResult, error) {
			in := openAppInput{App: ""}
			if v, ok := request.Arguments["app"].(string); ok {
				in.App = v
			}
			return openAppRun(rows, screens, in)
		},
	}
}

// openAppInput is the argument shape of the consolidated open_app tool.
type openAppInput struct {
	App string
}

// openAppRun executes the open_app handler.
func openAppRun(rows []appswire.ViewSpec, screens []string, in openAppInput) (model.ToolResult, error) {
	name, view, ok := resolveOpenApp(rows, in.App)
	if !ok {
		return model.ToolResult{
			IsError: true,
			Text:    fmt.Sprintf("unknown app %q; available apps: %s", in.App, strings.Join(screens, ", ")),
		}, nil
	}
	sc := map[string]any{"app": name, "view": view, "available": screens}
	raw, _ := json.Marshal(sc)
	return model.ToolResult{StructuredContent: sc, Text: string(raw)}, nil
}
