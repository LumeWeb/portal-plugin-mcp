package api

import (
	"net/http"

	"go.lumeweb.com/portal/core"
)

const (
	// Namespace is the error namespace for the MCP plugin.
	Namespace = "mcp"
)

// Error types for the MCP plugin's OAuth/OpenID discovery endpoints, registered
// in the mcp namespace so responses are produced by the framework error system
// (core.Error) rather than ad-hoc JSON maps. The OAuth protocol endpoints
// (token, register, authorize) still emit OAuth-spec error codes directly,
// which automated MCP clients parse; these discovery errors are for the
// OAuth/OpenID metadata documents the plugin itself serves.
const (
	// ErrAuthorizationServerUnavailable is returned when the OAuth provider is
	// disabled and no authorization-server metadata can be advertised (404).
	ErrAuthorizationServerUnavailable core.ErrorType = "ErrAuthorizationServerUnavailable"
	// ErrOAuthServerError is returned for any unexpected failure while building
	// an OAuth/OpenID discovery document (500).
	ErrOAuthServerError core.ErrorType = "ErrOAuthServerError"
)

func init() {
	core.MustRegisterNamespace(Namespace)
	core.MustRegisterDefaultErrorMessages(Namespace, map[core.ErrorType]core.ErrorDefinition{
		ErrAuthorizationServerUnavailable: {
			Message: "Authorization server unavailable",
		},
		ErrOAuthServerError: {
			Message: "OAuth server error",
		},
	})
	core.MustRegisterErrorCodes(Namespace, map[core.ErrorType]int{
		ErrAuthorizationServerUnavailable: http.StatusNotFound,
		ErrOAuthServerError:               http.StatusInternalServerError,
	})
}

// NewError creates a core.Error in the mcp namespace, mirroring the
// portal-plugin-billing error helper so discovery handlers surface failures
// through the framework error system.
func NewError(key core.ErrorType, err error, args ...any) *core.Error {
	return core.NewError(Namespace, key, err, args...)
}
