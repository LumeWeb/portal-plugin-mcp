package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestJSONRawRoundTrips ensures a JSON-escaped value remains decodable as the
// original string when placed back inside a JSON string literal.
func TestJSONRawRoundTrips(t *testing.T) {
	tainted := `</script><script>alert(1)</script>"&`
	raw := jsonRaw(tainted)
	// Escaping must neutralize HTML-special bytes so a hostile config value can't
	// close the surrounding <script> tag.
	require.NotContains(t, raw, "</script>")
	require.NotContains(t, raw, "<")
	require.NotContains(t, raw, "&")

	var back string
	require.NoError(t, json.Unmarshal([]byte(`"`+raw+`"`), &back))
	require.Equal(t, tainted, back)
}

// TestJSONRawPlainKeepsNormalValues ensures ordinary values pass through
// unchanged so the assembled document reads naturally.
func TestJSONRawPlainKeepsNormalValues(t *testing.T) {
	require.Equal(t, "Pinner", jsonRaw("Pinner"))
	require.Equal(t, "mcp.example.com", jsonRaw("mcp.example.com"))
}
