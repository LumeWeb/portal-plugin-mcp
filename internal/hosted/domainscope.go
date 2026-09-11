// Package hosted is the Portal plugin's construction boundary and HTTP
// transport for a hosted (Portal-embedded) Pinner MCP server. It assembles the
// /mcp streamable-HTTP handler, applies the OAuth gate, resolves the one
// effective per-request credential, and mounts the IPFS byte routes, reusing
// the SDK-independent contracts published by go.lumeweb.com/pinner/mcp/hosted
// and go.lumeweb.com/pinner/assembly. Resolver normalization, OAuth wrapping,
// localhost protection, and mux mounting all live in this package.
package hosted

// DomainScope declares which operation domains/tool families the hosted
// server exposes. The zero value means "nothing enabled" — callers opt in
// explicitly (typically via DomainScopeHosted). The Sia vault and portal-admin
// domains are intentionally not represented: a hosted embed never exposes
// them.
type DomainScope struct {
	// Account enables account, subscription, auth, and API-key operations.
	Account bool
	// Pins enables the IPFS pinning operations.
	Pins bool
	// Websites enables IPFS website publishing operations.
	Websites bool
	// DNS enables the DNS zone/record operations.
	DNS bool
	// IPNS enables the IPNS key/publish operations.
	IPNS bool
	// ENS enables the ENS/onchain pointing operations.
	ENS bool
	// Operations enables the operations-status operations.
	Operations bool
	// Upload enables the IPFS upload/download tool family.
	Upload bool
}

// DomainScopeHosted is the standard hosted surface: account/subscription plus
// the full IPFS/websites/DNS/IPNS/ENS/operations set (no vault, no admin).
var DomainScopeHosted = DomainScope{
	Account:    true,
	Pins:       true,
	Websites:   true,
	DNS:        true,
	IPNS:       true,
	ENS:        true,
	Operations: true,
	Upload:     true,
}

// IsZero reports whether the surface has every flag disabled (the empty
// value). hosted.New treats a zero DomainScope as DomainScopeHosted.
func (s DomainScope) IsZero() bool {
	return s == (DomainScope{})
}
