package api

import (
	"net/url"

	"go.lumeweb.com/portal/core"
)

// BuildAbsoluteURL constructs an absolute URL using the HTTP service's
// APISubdomain helper, mirroring the portal-plugin-billing URL helper.
// The API subdomain resolves scheme-less (e.g. "mcp.example.com"); this
// prepends the scheme derived from the secure flag so the OAuth resource URL
// and issuer are always canonical. Falls back to the provided relative path
// when the HTTP service is unavailable or the subdomain cannot be resolved.
func BuildAbsoluteURL(http core.HTTPService, subdomainID, relativePath string, secure bool) string {
	if http == nil {
		return relativePath
	}

	base := http.APISubdomain(subdomainID, false)
	if base == "" {
		return relativePath
	}

	scheme := "http"
	if secure {
		scheme = "https"
	}

	// Split path from query so query parameters are not re-encoded.
	rel, err := url.Parse(relativePath)
	if err != nil {
		return relativePath
	}

	u := &url.URL{
		Scheme:   scheme,
		Host:     base,
		Path:     rel.Path,
		RawQuery: rel.RawQuery,
	}
	return u.String()
}
