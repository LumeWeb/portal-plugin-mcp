package api

import (
	"encoding/json"
	"net/http"
)

// healthzHandler is the unauthenticated liveness probe used by orchestrators.
// It is deliberately outside the OAuth guards.
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// writeJSON writes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeServerError writes a generic RFC 6749 §5.2 server_error response. Used
// for internal failures on OAuth/MCP protocol endpoints so internal error
// strings are never leaked to clients.
func writeServerError(w http.ResponseWriter) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
}
