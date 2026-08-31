package api

import (
	"errors"
	"net/http"

	"go.lumeweb.com/portal/core"
	portalservice "go.lumeweb.com/portal/service"
	"go.uber.org/zap"
)

// serverErrorCode is the RFC 6749 §5.2 error code returned for any internal
// OAuth/MCP failure. Internal error strings are never sent to clients.
const serverErrorCode = "server_error"

// oauthServerError maps an internal OAuth/MCP failure to a client-safe error
// code and HTTP status. Known portal errors become meaningful statuses so an
// unconfigured/disabled provider (503) can be told apart from an unknown
// protected resource (404) and a generic internal failure (500).
func oauthServerError(err error) (code string, status int) {
	switch {
	case errors.Is(err, portalservice.ErrOAuthDisabled):
		return serverErrorCode, http.StatusServiceUnavailable
	case errors.Is(err, portalservice.ErrResourceNotRegistered):
		return serverErrorCode, http.StatusNotFound
	default:
		return serverErrorCode, http.StatusInternalServerError
	}
}

// writeErrAndLog logs the underlying failure and writes the mapped
// oauthServerError response. The full error and the caller-supplied detail
// (public context such as the resource URL) are logged for operability but
// never echoed to the client.
func writeErrAndLog(logger *core.Logger, w http.ResponseWriter, op, detail string, err error) {
	code, status := oauthServerError(err)
	if logger != nil {
		logger.Error("oauth: "+op+" failed",
			zap.Error(err),
			zap.String("detail", detail),
			zap.Int("http_status", status),
		)
	}
	writeJSON(w, status, map[string]string{"error": code})
}
