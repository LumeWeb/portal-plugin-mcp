package hosted

// This file is the dispatch bridge between the operation catalog (the
// compiler-backed source of truth for the tool surface, assembled via
// go.lumeweb.com/pinner/mcp.Assemble) and a real mcpplane SDK server.
//
// Each compiled operation is surfaced as an SDK tool whose handler dispatches
// through opmesh.Catalog.Invoke so the Interaction, Visibility, Safety, and
// required-arg gates hold. The per-request credential is threaded through the
// reserved auth-token override (opmesh.ReservedAuthTokenKey) so a hosted
// server authenticates every request as the calling user rather than sharing a
// config credential.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.lumeweb.com/mcpplane/model"
	"go.lumeweb.com/opmesh"
)

// catalogToolHandler returns the model.ToolHandler that dispatches one
// compiled catalog operation through its owning Catalog.Invoke gate.
//
// The credential is preferred from the request context first: the HTTP
// credential middleware (credentialMiddleware in httptransport.go) resolves it
// once per request, so the handler does not re-resolve per tool. On paths with
// no middleware it falls back to resolving now via resolver.
//
// FAIL CLOSED on the hosted path: when a per-request resolver is configured, a
// resolver error or a blank resolved token returns a structured
// credential_entry needs_human hand-off and the operation is NEVER dispatched,
// so an unrecognized caller can never execute under the deployment's own
// shared credential.
func catalogToolHandler(cat opmesh.Catalog, name string, resolver CredentialResolver) model.ToolHandler {
	return func(ctx context.Context, req model.ToolRequest) (model.ToolResult, error) {
		tok := credentialFromContext(ctx)
		if tok == "" && resolver != nil {
			t, err := resolver.TokenForRequest(ctx)
			if err != nil || t == "" {
				return model.NeedsHumanResult(model.NeedsHuman{
					Reason: model.ReasonCredentialEntry,
					Detail: name + " requires an authenticated request, but no Portal credential could be resolved for the current identity. Re-authenticate the MCP session; no operation was executed under default credentials.",
				}), nil
			}
			tok = t
			ctx = withCredential(ctx, tok)
		}
		args := req.Arguments
		if tok != "" {
			if args == nil {
				args = map[string]any{}
			}
			args[opmesh.ReservedAuthTokenKey] = tok
		}
		return dispatchCatalogOp(ctx, cat, opmesh.ActorModel, name, args, name)
	}
}

// dispatchCatalogOp dispatches one catalog operation on the model-actor MCP
// surface, mapping the catalog gate's refusals onto the SDK-neutral model
// result shapes.
func dispatchCatalogOp(ctx context.Context, cat opmesh.Catalog, actor opmesh.Actor, name string, args map[string]any, resumeTool string) (model.ToolResult, error) {
	// AgentRequired args are enforced here, at the MCP dispatch layer, not in
	// Catalog.Invoke / NormalizeOperationInput (shared seams the CLI and other
	// non-MCP callers use; AgentRequired must never leak into a non-MCP
	// invocation).
	if op, ok := cat.Get(name); ok {
		if m := firstMissingDispatchRequiredArg(op, args); m != "" {
			return model.ToolResult{IsError: true, Text: fmt.Sprintf("missing required argument %q", m)}, nil
		}
	}

	result, err := cat.Invoke(ctx, name, args, actor)
	if err != nil {
		// A destructive op invoked by a model needs explicit human
		// confirmation. Surface it as a confirm hand-off, not an error.
		if errors.Is(err, opmesh.ErrConfirmRequired) {
			return model.NeedsHumanResult(model.NeedsHuman{
				Reason:     model.ReasonConfirmation,
				ResumeTool: resumeTool,
				Detail:     name + " is destructive and requires explicit human confirmation",
			}), nil
		}
		// An InteractiveOnly/NeedsHandoff op refused for a non-human actor is
		// a hand-off to the human, not a failure.
		if errors.Is(err, opmesh.ErrHumanRequired) {
			return model.NeedsHumanResult(model.NeedsHuman{
				Reason:     model.ReasonInteractiveOnly,
				ResumeTool: resumeTool,
				Detail:     name + " requires a human to complete; resume with " + resumeTool,
			}), nil
		}
		return model.ToolResult{IsError: true, Text: cleanMessage(err)}, nil
	}

	return resultToToolResult(result), nil
}

// firstMissingDispatchRequiredArg reports the name of the first declared
// MCP-dispatch-required arg that the input does not satisfy, or "" when every
// such arg is satisfied. Replicates the module's ValidateMCPRequired
// semantics: an arg is required here when AgentRequired or Required with no
// Default; it counts as missing when absent, present-but-null, or
// present-but-empty.
func firstMissingDispatchRequiredArg(op opmesh.Operation, input map[string]any) string {
	for _, a := range op.Args() {
		if !a.AgentRequired && !isRequiredArg(a) {
			continue
		}
		raw, present := lookupAgentArgInput(a, input)
		if !present || raw == nil || isAgentArgEmpty(a, raw) {
			return a.Name
		}
	}
	return ""
}

// lookupAgentArgInput resolves an operation arg against a raw input map,
// matching both the declared (kebab) name and its camelCase alias, so a model
// sending either spelling satisfies the arg.
func lookupAgentArgInput(a opmesh.OperationArg, input map[string]any) (any, bool) {
	if raw, ok := input[a.Name]; ok {
		return raw, true
	}
	if alias := camelCase(a.Name); alias != a.Name {
		if raw, ok := input[alias]; ok {
			return raw, true
		}
	}
	return nil, false
}

// isAgentArgEmpty classifies a present argument value as "empty" for
// required-arg purposes: an empty string, an empty string slice, or an empty
// raw-JSON string. Typed scalars have no meaningful empty value.
func isAgentArgEmpty(a opmesh.OperationArg, raw any) bool {
	switch a.Type {
	case opmesh.ArgTypeStringSlice:
		if s, ok := raw.([]string); ok {
			return len(s) == 0
		}
		if s, ok := raw.([]any); ok {
			return len(s) == 0
		}
		return false
	case opmesh.ArgTypeString, opmesh.ArgTypeFlexibleID, opmesh.ArgTypeRawJSON:
		s, ok := raw.(string)
		return ok && s == ""
	default:
		return false
	}
}

// isRequiredArg mirrors the shared predicate used by Invoke and every schema
// builder: an arg is only mandatory when Required AND has no declared default.
func isRequiredArg(a opmesh.OperationArg) bool {
	return a.Required && a.Default == ""
}

// camelCase converts a kebab-case name to camelCase (e.g. "device-name" ->
// "deviceName"), so a model sending the camelCase spelling satisfies the arg.
func camelCase(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	upper := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '-' {
			upper = true
			continue
		}
		if upper {
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			upper = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// resultToToolResult converts the typed (any) result returned by the catalog
// gate into an SDK-neutral ToolResult. Every successful result is wrapped in
// the single canonical envelope {"status":"ok","value":<result>}, regardless of
// whether the result is an object, array, or scalar.
func resultToToolResult(result any) model.ToolResult {
	switch v := result.(type) {
	case model.ToolResult:
		return v
	case *model.ToolResult:
		if v != nil {
			return *v
		}
		return model.ToolResult{Text: `{"status":"ok"}`, StructuredContent: map[string]any{"status": model.StatusOk}}
	}
	b, err := json.Marshal(result)
	if err != nil {
		return model.ToolResult{IsError: true, Text: "unable to serialize catalog result"}
	}
	if string(b) == "null" {
		sc := map[string]any{"status": model.StatusOk}
		jb, _ := json.Marshal(sc)
		return model.ToolResult{Text: string(jb), StructuredContent: sc}
	}
	var value any
	if json.Valid(b) {
		value = json.RawMessage(b)
	}
	sc := map[string]any{"status": model.StatusOk, "value": value}
	jb, _ := json.Marshal(sc)
	return model.ToolResult{Text: string(jb), StructuredContent: sc}
}

// cleanMessage returns a single-line, non-empty error message for surfacing as
// ToolResult.Text, guarding against an empty string.
func cleanMessage(err error) string {
	if err == nil {
		return "operation failed"
	}
	return strings.TrimSpace(err.Error())
}
