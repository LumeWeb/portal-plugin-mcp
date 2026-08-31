package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.lumeweb.com/portal/core/testing/mocks"
)

func TestBuildAbsoluteURL_WithHTTPService_Secure(t *testing.T) {
	mockHTTP := mocks.NewMockHTTPService(t)
	mockHTTP.EXPECT().APISubdomain("mcp", false).Return("mcp.example.com")

	result := BuildAbsoluteURL(mockHTTP, "mcp", "/mcp", true)
	assert.Equal(t, "https://mcp.example.com/mcp", result)
}

func TestBuildAbsoluteURL_WithHTTPService_Insecure(t *testing.T) {
	mockHTTP := mocks.NewMockHTTPService(t)
	mockHTTP.EXPECT().APISubdomain("mcp", false).Return("mcp.example.com")

	result := BuildAbsoluteURL(mockHTTP, "mcp", "/mcp", false)
	assert.Equal(t, "http://mcp.example.com/mcp", result)
}

func TestBuildAbsoluteURL_NilHTTPService(t *testing.T) {
	result := BuildAbsoluteURL(nil, "mcp", "/mcp", true)
	assert.Equal(t, "/mcp", result)
}

func TestBuildAbsoluteURL_EmptySubdomain(t *testing.T) {
	mockHTTP := mocks.NewMockHTTPService(t)
	mockHTTP.EXPECT().APISubdomain("mcp", false).Return("")

	result := BuildAbsoluteURL(mockHTTP, "mcp", "/mcp", true)
	assert.Equal(t, "/mcp", result)
}

func TestBuildAbsoluteURL_KeepsRelativeEmptyPath(t *testing.T) {
	mockHTTP := mocks.NewMockHTTPService(t)
	mockHTTP.EXPECT().APISubdomain("mcp", false).Return("mcp.example.com")

	result := BuildAbsoluteURL(mockHTTP, "mcp", "", true)
	assert.Equal(t, "https://mcp.example.com", result)
}
