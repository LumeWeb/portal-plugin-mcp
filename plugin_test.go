package mcp

import (
	"slices"
	"testing"
)

func TestGetPluginInfo(t *testing.T) {
	info := GetPluginInfo()
	if info.ID != "mcp" {
		t.Fatalf("expected plugin ID mcp, got %q", info.ID)
	}
	if info.API == nil {
		t.Fatal("expected API factory")
	}
	if info.APIExtensions == nil {
		t.Fatal("expected APIExtensions factory")
	}
	if !slices.Contains(info.Depends, "dashboard") {
		t.Fatalf("expected depends on dashboard, got %v", info.Depends)
	}
}

func TestGetPluginInfoAPIExtensions(t *testing.T) {
	info := GetPluginInfo()
	extensions, err := info.APIExtensions(nil)
	if err != nil {
		t.Fatalf("unexpected error building extensions: %v", err)
	}
	if len(extensions) != 1 {
		t.Fatalf("expected 1 API extension, got %d", len(extensions))
	}
}
