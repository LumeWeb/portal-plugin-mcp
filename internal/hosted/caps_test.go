package hosted

import (
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/mcpplane/model"
	"go.lumeweb.com/mcpplane/sdk"
)

// callToolReqWithMeta builds a minimal go-sdk call-tool request carrying
// per-request meta and HTTP wire extras, mirroring how the streamable
// transport materializes a remoted call.
func callToolReqWithMeta(t *testing.T, meta map[string]any, extra *mcp.RequestExtra) *sdk.CallToolRequest {
	t.Helper()
	return &sdk.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Meta: mcp.Meta(meta)},
		Extra:  extra,
	}
}

// TestRequestCapsResolvesHostedHTTPProfile locks the hosted per-request
// capability view: profile detection over the canimcp registry must resolve
// the remote HTTP generic profile for an unidentified client, stamped with the
// hosted deployment flag.
func TestRequestCapsResolvesHostedHTTPProfile(t *testing.T) {
	build := requestCapsFunc(false)

	meta := map[string]any{
		"io.modelcontextprotocol/protocolVersion": "2025-06-18",
		"io.modelcontextprotocol/clientInfo": map[string]any{
			"name": "unittest-host", "version": "v1",
		},
	}
	req := callToolReqWithMeta(t, meta, &mcp.RequestExtra{
		Header: http.Header{"User-Agent": []string{"unittest-agent/1.0"}},
	})

	rc := build(req)
	require.NotNil(t, rc, "request caps must resolve")
	assert.Equal(t, "2025-06-18", rc.ProtocolVersion)
	require.NotNil(t, rc.Profile, "profile must resolve")
	assert.Equal(t, model.TransportHTTP, rc.Profile.Transport, "hosted embeds resolve the HTTP transport")
	assert.True(t, rc.Profile.Hosted, "profile must carry the hosted deployment flag")
	assert.True(t, rc.Profile.Remote, "hosted embeds are always remote")
	assert.Equal(t, "unittest-agent/1.0", rc.Profile.UserAgent, "wire User-Agent must overlay the profile")
	require.NotNil(t, rc.Profile.ClientInfo)
	assert.Equal(t, "unittest-host", rc.Profile.ClientInfo.Name)
	assert.Empty(t, rc.Capabilities, "the raw wire snapshot must stay absent with dev tools off")
}

// TestRequestCapsDevSnapshot locks the dev-tools wire snapshot: the raw client
// capabilities and initialize params are captured only when dev tools are on.
func TestRequestCapsDevSnapshot(t *testing.T) {
	meta := map[string]any{
		"io.modelcontextprotocol/clientCapabilities": map[string]any{
			"roots": map[string]any{"listChanged": true},
		},
	}

	off := requestCapsFunc(false)(callToolReqWithMeta(t, meta, nil))
	assert.Nil(t, off.Capabilities, "dev tools off: no capabilities snapshot")

	on := requestCapsFunc(true)(callToolReqWithMeta(t, meta, nil))
	assert.NotNil(t, on.Capabilities, "dev tools on: capabilities snapshot captured")
	assert.Contains(t, on.Capabilities, "roots")
}
