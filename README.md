# portal-plugin-mcp

API-only plugin for the LumeWeb Portal that exposes Model Context Protocol endpoints.

## Status

Scaffold. The plugin registers a single API (`mcp`) with a health endpoint. Endpoints and behaviors will be added as requirements are defined.

## Development

This is a Go plugin for the [LumeWeb Portal](https://github.com/LumeWeb/portal). It depends on `go.lumeweb.com/portal@develop`.

```bash
go build ./...
go test ./...
```
