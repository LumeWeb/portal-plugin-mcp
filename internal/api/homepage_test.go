package api

import (
	"bytes"
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

// TestWizardTemplateRendersNotice ensures the wizard payload stays valid JSON
// with the access-notice panel populated: the client-side wizard renders this
// data with Handlebars, and an empty or malformed notice would silently hide
// the panel (home.html skips rendering when notice is absent) or break the
// JSON.parse that gates the whole wizard.
func TestWizardTemplateRendersNotice(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, wizardTemplate.Execute(&buf, wizardData{
		PortalName:  "Pinner",
		ResourceURL: "https://mcp.example.com/mcp",
		AllowDomain: "mcp.example.com",
	}))

	var data struct {
		Notice struct {
			Title string `json:"title"`
			Items []struct {
				Label string `json:"label"`
				Text  string `json:"text"`
			} `json:"items"`
		} `json:"notice"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &data))

	require.Equal(t, "Before you connect", data.Notice.Title)
	require.Len(t, data.Notice.Items, 3)
	for _, item := range data.Notice.Items {
		require.NotEmpty(t, item.Label)
		require.NotEmpty(t, item.Text)
	}
	// Config-derived values must appear in the rendered copy.
	require.Contains(t, data.Notice.Items[0].Text, "Pinner")
	require.Contains(t, data.Notice.Items[2].Text, "official Pinner server")
}
