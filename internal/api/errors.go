package api

import "go.lumeweb.com/portal/core"

const (
	Namespace = "mcp"
)

func init() {
	core.MustRegisterNamespace(Namespace)
	core.MustRegisterDefaultErrorMessages(Namespace, map[core.ErrorType]core.ErrorDefinition{})
}
