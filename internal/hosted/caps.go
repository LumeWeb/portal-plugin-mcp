package hosted

import (
	"encoding/json"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"go.lumeweb.com/canimcp"
	"go.lumeweb.com/mcpplane/apps"
	"go.lumeweb.com/mcpplane/model"
	"go.lumeweb.com/mcpplane/sdk"
)

// The hosted HTTP path builds the per-request cap view every tool reads:
// profile detection over the public caniuse-style canimcp registry plus, under
// dev tools, the raw wire snapshot the dev_* introspection tools expose.

// hostedDetectorRegistry is the shared canimcp detector set. Detect resolves
// static profiles and wire-signal overlays without mutating registry state,
// so a single registry is safe for concurrent requests.
var hostedDetectorRegistry = canimcp.NewRegistry()

// requestCapsFunc returns the HandlerDeps.RequestCaps builder for this embed.
// The hosted server always resolves a platform profile over HTTP wire signals
// (remote, hosted audience); when devTools is on it additionally captures the
// raw client capability + initialize wire snapshots that dev_host_env
// introspects. The go-sdk call-tool request types are converted to the
// SDK-neutral model layer here so no tool handler ever sees the protocol SDK.
func requestCapsFunc(devTools bool) func(req *sdk.CallToolRequest) *model.RequestCaps {
	return func(req *sdk.CallToolRequest) *model.RequestCaps {
		rc := &model.RequestCaps{ProtocolVersion: req.ProtocolVersion()}

		var headers http.Header
		var tokenInfo *canimcp.TokenInfo
		if extra := req.GetExtra(); extra != nil {
			headers = extra.Header
			if extra.TokenInfo != nil {
				tokenInfo = canimcpTokenInfo(extra.TokenInfo)
			}
		}

		var clientInfo *canimcp.ClientInfo
		if ci := req.ClientInfo(); ci != nil {
			clientInfo = &canimcp.ClientInfo{
				Name:        ci.Name,
				Version:     ci.Version,
				Title:       ci.Title,
				Description: ci.Description,
			}
		}

		if cc := req.ClientCapabilities(); cc != nil {
			rc.UI = apps.GetClientUICapability(cc.Extensions)
		}

		// Hosted embeds are always remote HTTP servers behind a proxy: neither
		// co-located stdio nor the OpenAI tunnel wire applies.
		profile := hostedDetectorRegistry.Detect(canimcp.Evidence{
			ClientInfo:      clientInfo,
			ProtocolVersion: req.ProtocolVersion(),
			UserAgent:       headers.Get("User-Agent"),
			Headers:         headers,
			TokenInfo:       tokenInfo,
		})

		// Safety net: a client advertising MCP Apps support on the wire but
		// without a matching static profile entry still must resolve the
		// mcp-apps-ui feature for tools that branch on it at call time.
		if rc.UI != nil && rc.UI.SupportsApps() && !profile.Has(canimcp.FeatMCPApps) {
			profile = profile.CloneFeatures()
			profile.Features[canimcp.FeatMCPApps] = true
		}

		shared := sharedProfile(profile)
		shared.Hosted = true
		rc.Profile = &shared

		if devTools {
			if cc := req.ClientCapabilities(); cc != nil {
				rc.Capabilities = toJSONMap(cc)
			}
			if s := req.Session; s != nil {
				if ip := s.InitializeParams(); ip != nil {
					rc.InitializeParams = toJSONMap(ip)
				}
			}
		}

		return rc
	}
}

// sharedProfile adapts a canimcp profile to the SDK-neutral model.Profile. The
// vocabularies are byte-identical string sets; only the named types differ.
func sharedProfile(p canimcp.Profile) model.Profile {
	clientInfo := (*model.ClientInfo)(nil)
	if p.ClientInfo != nil {
		clientInfo = &model.ClientInfo{
			Name:        p.ClientInfo.Name,
			Version:     p.ClientInfo.Version,
			Title:       p.ClientInfo.Title,
			Description: p.ClientInfo.Description,
		}
	}
	tokenInfo := (*model.TokenInfo)(nil)
	if p.TokenInfo != nil {
		tokenInfo = &model.TokenInfo{
			Scopes:     p.TokenInfo.Scopes,
			Expiration: p.TokenInfo.Expiration,
			UserID:     p.TokenInfo.UserID,
			Extra:      p.TokenInfo.Extra,
		}
	}
	features := make(model.FeatureSet, len(p.Features))
	for f, ok := range p.Features {
		features[model.Feature(f)] = ok
	}
	return model.Profile{
		HostType:    model.HostType(p.HostType),
		Transport:   model.TransportKind(p.Transport),
		AuthMethod:  model.AuthMethod(p.AuthMethod),
		Remote:      p.Remote,
		Features:    features,
		ClientInfo:  clientInfo,
		ProtocolVer: p.ProtocolVer,
		UserAgent:   p.UserAgent,
		Headers:     p.Headers,
		TokenInfo:   tokenInfo,
	}
}

// canimcpTokenInfo converts the go-sdk bearer token info into the canimcp
// evidence shape so the detector can overlay wire auth onto the profile.
func canimcpTokenInfo(ti *auth.TokenInfo) *canimcp.TokenInfo {
	return &canimcp.TokenInfo{
		Scopes:     ti.Scopes,
		Expiration: ti.Expiration,
		UserID:     ti.UserID,
		Extra:      ti.Extra,
	}
}

// toJSONMap converts a go-sdk-typed value into a plain JSON map so the
// SDK-neutral model layer carries it without importing the protocol SDK.
// Returns nil when marshaling fails (defensive; the SDK structs serialize).
func toJSONMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}
