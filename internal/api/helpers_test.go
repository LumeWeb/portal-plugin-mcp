package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, 201, map[string]string{"x": "y"})

	require.Equal(t, 201, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "y", body["x"])
}

func TestWriteServerError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeServerError(rec)

	require.Equal(t, 500, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "server_error", body["error"])
}
