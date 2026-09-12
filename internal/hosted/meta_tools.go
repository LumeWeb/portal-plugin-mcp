package hosted

// This file ports the progressive-disclosure meta-tools (search_tools,
// describe_tool, and the typed invoke dispatchers invoke_read_tool /
// invoke_write_tool / invoke_destructive_tool) onto the compiled hosted
// surface, adapting the reference behavior from the self-hosted CLI assembly's
// internal/mcp/sdk_official.go + catalog.go in pinner-cli.
//
// The discovery index here is NOT a hand-built ToolCatalog: it is derived from
// the assembled presentation (go.lumeweb.com/pinner/mcp.Assemble) — the
// compiled catalog surface (dispatched through the owning opmesh.Catalog via
// the same dispatchCatalogOp gate all hosted ops use) plus the direct-only
// tools (agent_guide, capabilities, the wired transfer tools), which keep
// their baked-in handlers.
//
// Registration is controlled ONLY by the resolved shared pinner/mcp
// ListingPolicy (servesMetaTools): progressive always serves the meta-tools;
// flat serves them unless IncludeMetaOnFlat is explicitly false. The
// deployment mode (Hosted) never gates registration.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"go.lumeweb.com/mcpplane/model"
	"go.lumeweb.com/mcpplane/sdk"
	"go.lumeweb.com/mcpplane/toolargs"
	"go.lumeweb.com/opmesh"
	"go.lumeweb.com/pinner/mcp"
)

// The meta-tool wire names. These are the five tools an agent sees on
// tools/list under a progressive listing (and, on flat, alongside the direct
// set when the policy keeps meta-on-flat).
const (
	metaToolSearch            = "search_tools"
	metaToolDescribe          = "describe_tool"
	metaToolInvokeRead        = "invoke_read_tool"
	metaToolInvokeWrite       = "invoke_write_tool"
	metaToolInvokeDestructive = "invoke_destructive_tool"
)

// servesMetaTools reports whether the RESOLVED listing policy keeps the
// progressive-disclosure meta-tools on tools/list: always under progressive,
// and under flat unless the policy explicitly opts out with a non-nil
// IncludeMetaOnFlat pointing to false. The decision reads ONLY the resolved
// shared pinner/mcp ListingPolicy value — never the hosted deployment mode.
// This is the shared predicate for the meta registration gate, mirroring
// pinner-cli's ToolCatalog.servesMetaTools (progressive always; flat omitted
// only on the explicit opt-out).
func servesMetaTools(listing mcp.ListingPolicy) bool {
	return listing.Strategy != mcp.ListingFlat || listing.ResolveIncludeMetaOnFlat()
}

// toolSummary is the lightweight representation returned by search_tools. It
// deliberately omits the input schema so discovery stays cheap. It mirrors
// pinner-cli's ToolSummary wire shape.
type toolSummary struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Category    model.ToolCategory `json:"category,omitempty"`
	ReadOnly    bool               `json:"readOnlyHint,omitempty"`
	Destructive bool               `json:"destructiveHint,omitempty"`
}

// toolDetail is the full representation returned by describe_tool. It mirrors
// pinner-cli's ToolDetail wire shape: hints always serialize, and InvokeTool
// names the typed dispatcher that executes the tool.
type toolDetail struct {
	Name        string             `json:"name"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description"`
	Category    model.ToolCategory `json:"category,omitempty"`
	ReadOnly    bool               `json:"readOnlyHint"`
	Destructive bool               `json:"destructiveHint"`
	InvokeTool  string             `json:"invokeTool,omitempty"`
	InputSchema json.RawMessage    `json:"inputSchema"`
}

// searchResult is the wire envelope for the keyword-search path of
// search_tools.
type searchResult struct {
	Tools []toolSummary `json:"tools"`
	Total int           `json:"total"`
}

// onboardingResult is the wire envelope for the onboarding path (empty/help
// query, no category).
type onboardingResult struct {
	Tools []toolSummary `json:"tools"`
	Total int           `json:"total"`
	Hint  string        `json:"hint,omitempty"`
}

// searchToolsInput is the typed argument shape for search_tools.
type searchToolsInput struct {
	Query    string `json:"query,omitempty"`
	Category string `json:"category,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// describeToolInput is the typed argument shape for describe_tool.
type describeToolInput struct {
	Name string `json:"name"`
}

// invokeToolInput is the typed argument shape for the typed invoke
// dispatchers.
type invokeToolInput struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// invokeClass identifies the safety class a typed invoke dispatcher admits.
// The typed split keeps every meta-tool's wire annotations truthful: each
// dispatcher refuses out-of-class tools (see pinner-cli's classifyEntry).
type invokeClass int

const (
	invokeClassRead invokeClass = iota
	invokeClassWrite
	invokeClassDestructive
)

// dispatcher names the typed invoke tool for this class.
func (c invokeClass) dispatcher() string {
	switch c {
	case invokeClassRead:
		return metaToolInvokeRead
	case invokeClassDestructive:
		return metaToolInvokeDestructive
	default:
		return metaToolInvokeWrite
	}
}

// classNoun names a safety class in human-readable error text.
func classNoun(c invokeClass) string {
	switch c {
	case invokeClassRead:
		return "read-only"
	case invokeClassDestructive:
		return "destructive"
	default:
		return "mutating"
	}
}

// classifyDescriptor maps a descriptor's platform hints onto the typed-invoke
// safety class (the same classifier pinner-cli uses on ToolEntry): a
// readOnly entry that still declares open-world interaction is conservatively
// reachable only through the write dispatcher.
func classifyDescriptor(d model.ToolDescriptor) invokeClass {
	switch {
	case d.Destructive:
		return invokeClassDestructive
	case d.ReadOnly && !d.OpenWorldHint:
		return invokeClassRead
	default:
		return invokeClassWrite
	}
}

// metaSurface is the discovery index behind the hosted meta-tools: the
// compiled catalog surface (metadata only — dispatch goes through the owning
// opmesh.Catalog) plus the direct-only tools (baked-in handlers). It is
// immutable once built by newMetaSurface.
type metaSurface struct {
	// catalog entries dispatch through the opmesh catalog gate.
	catalog []model.ToolDescriptor
	// direct entries (agent_guide, capabilities, wired transfer tools) carry
	// baked-in handlers and are invoked directly.
	direct []model.ToolDescriptor
	cat    opmesh.Catalog
	// resolver threads the per-request Portal credential into catalog
	// dispatch (the same seam every hosted catalog tool uses).
	resolver CredentialResolver
}

// newMetaSurface indexes the assembled presentation for progressive
// discovery: every model-visible compiled op AND every direct-only tool is
// discoverable, exactly like the CLI assembly's catalog indexes both surfaces.
func newMetaSurface(present *mcp.Server, resolver CredentialResolver) *metaSurface {
	return &metaSurface{
		catalog:  present.Tools,
		direct:   present.Direct,
		cat:      present.Catalog(),
		resolver: resolver,
	}
}

// lookup resolves a tool by name across both indexed surfaces along with
// whether it is a direct-only (baked-handler) tool.
func (s *metaSurface) lookup(name string) (model.ToolDescriptor, bool, bool) {
	for _, d := range s.catalog {
		if d.Name == name {
			return d, true, false
		}
	}
	for _, d := range s.direct {
		if d.Name == name {
			return d, true, true
		}
	}
	return model.ToolDescriptor{}, false, false
}

// entries returns every indexed descriptor.
func (s *metaSurface) entries() []model.ToolDescriptor {
	out := make([]model.ToolDescriptor, 0, len(s.catalog)+len(s.direct))
	out = append(out, s.catalog...)
	out = append(out, s.direct...)
	return out
}

// hiddenFromSearch reports whether an entry must not appear in agent
// discovery. Admin and wizard-category tools are gated from general search,
// but an explicit category browse may request either category. Human-only and
// needs-handoff catalog ops remain hidden because an agent cannot execute them
// directly through discovery.
func (s *metaSurface) hiddenFromSearch(d model.ToolDescriptor, category string) bool {
	if d.Category == model.CategoryAdmin && category != string(model.CategoryAdmin) {
		return true
	}
	if d.Category == model.CategoryWizard && category != string(model.CategoryWizard) {
		return true
	}
	if op, ok := s.cat.Get(d.Name); ok {
		return op.Interaction() == opmesh.InteractionHumanOnly || op.Interaction() == opmesh.InteractionNeedsHandoff
	}
	return false
}

// summaryOf projects a descriptor onto the cheap discovery shape.
func summaryOf(d model.ToolDescriptor) toolSummary {
	return toolSummary{
		Name:        d.Name,
		Description: d.Description,
		Category:    d.Category,
		ReadOnly:    d.ReadOnly,
		Destructive: d.Destructive,
	}
}

// isOnboardingQuery reports whether a query selects the onboarding listing
// (empty or the literal "help" keyword), matching the CLI assembly's routing
// predicate.
func isOnboardingQuery(query string) bool {
	return query == "" || query == "help"
}

// onboard returns the onboarding "start here" listing: the direct-visible
// surface (the agent guide, capabilities, and the wired transfer tools),
// which is exactly the bounded set a fresh agent gets before any search. It
// is the hosted analog of the CLI onboarding set.
func (s *metaSurface) onboard() onboardingResult {
	var tools []toolSummary
	seen := map[string]bool{}
	for _, d := range s.entries() {
		if seen[d.Name] || !d.DirectVisible || s.hiddenFromSearch(d, "") {
			continue
		}
		seen[d.Name] = true
		tools = append(tools, summaryOf(d))
	}
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Category != tools[j].Category {
			return tools[i].Category < tools[j].Category
		}
		return tools[i].Name < tools[j].Name
	})
	return onboardingResult{
		Tools: tools,
		Total: len(tools),
		Hint:  "These are the primary start-here tools (agent-guide orientation, capabilities, and the wired file-transfer surface). Call agent_guide for the full ordered flows, or search with a keyword (optionally filtered by category) to discover the full hosted tool surface.",
	}
}

// search returns tools matching a non-empty keyword query, porting the CLI
// assembly's layered ranking (measured by matchRank) over the indexed
// surface. An empty query with an explicit category browses that whole
// category. limit caps the results (<=0 means no cap).
func (s *metaSurface) search(query, category string, limit int) []toolSummary {
	query = strings.ToLower(strings.TrimSpace(query))

	type ranked struct {
		summary toolSummary
		rank    int
	}
	var results []ranked
	for _, d := range s.entries() {
		if s.hiddenFromSearch(d, category) {
			continue
		}
		if category != "" && string(d.Category) != category {
			continue
		}
		rank := matchRank(query, strings.ToLower(d.Name), strings.ToLower(d.Description))
		if rank >= 0 {
			results = append(results, ranked{summary: summaryOf(d), rank: rank})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].rank != results[j].rank {
			return results[i].rank < results[j].rank
		}
		if results[i].summary.Category != results[j].summary.Category {
			return results[i].summary.Category < results[j].summary.Category
		}
		return results[i].summary.Name < results[j].summary.Name
	})
	summaries := make([]toolSummary, 0, len(results))
	for _, r := range results {
		summaries = append(summaries, r.summary)
	}
	if limit > 0 && len(summaries) > limit {
		summaries = summaries[:limit]
	}
	return summaries
}

// suggest returns up to max tool names close to the given (unknown) name, so
// describe_tool and the invoke dispatchers can answer "did you mean ...?".
func (s *metaSurface) suggest(name string, max int) []string {
	target := strings.ToLower(name)
	type scored struct {
		dist int
		name string
	}
	var all []scored
	for _, d := range s.entries() {
		if s.hiddenFromSearch(d, "") {
			continue
		}
		all = append(all, scored{dist: levenshtein(strings.ToLower(d.Name), target), name: d.Name})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].dist != all[j].dist {
			return all[i].dist < all[j].dist
		}
		return all[i].name < all[j].name
	})
	var out []string
	for _, s := range all {
		if max > 0 && len(out) >= max {
			break
		}
		out = append(out, s.name)
	}
	return out
}

// describe returns the full detail (including input schema) for one tool.
// Admin-category tools refuse describe behind the same gate as search.
func (s *metaSurface) describe(name string) (*toolDetail, error) {
	d, ok, _ := s.lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	if d.Category == model.CategoryAdmin {
		return nil, fmt.Errorf("admin tool %s is not available through describe_tool; use search_tools with category=admin to discover admin tools", name)
	}
	return &toolDetail{
		Name:        d.Name,
		Title:       d.Title,
		Description: d.Description,
		Category:    d.Category,
		ReadOnly:    d.ReadOnly,
		Destructive: d.Destructive,
		InvokeTool:  classifyDescriptor(d).dispatcher(),
		InputSchema: d.InputSchema,
	}, nil
}

// invoke dispatches a meta-tool invocation. The typed dispatcher has already
// enforced its safety class; catalog ops go through the SAME hosted dispatch
// seam as every direct catalog tool (credential threading + dispatchCatalogOp
// gates), while direct-only tools call their baked-in handlers.
func (s *metaSurface) invoke(ctx context.Context, name string, args map[string]any) (model.ToolResult, error) {
	d, ok, isDirect := s.lookup(name)
	if !ok {
		return model.ToolResult{}, fmt.Errorf("unknown tool: %s", name)
	}
	if d.Category == model.CategoryAdmin {
		return model.ToolResult{IsError: true, Text: fmt.Sprintf("admin tool %s is not available through the invoke dispatchers; use search_tools with category=admin to discover admin tools", name)}, nil
	}
	if args == nil {
		args = map[string]any{}
	}
	if isDirect {
		if d.Handler == nil {
			return model.ToolResult{IsError: true, Text: "tool is not executable"}, nil
		}
		return d.Handler(ctx, model.ToolRequest{Name: name, Arguments: args})
	}
	return catalogToolHandler(s.cat, name, s.resolver)(ctx, model.ToolRequest{Name: name, Arguments: args})
}

// metaSchema is a tiny SDK-neutral input schema builder for the static
// meta-tools (ported from pinner-cli).
type metaSchema struct {
	props map[string]any
}

func (s *metaSchema) property(name string, schema map[string]any) {
	if s.props == nil {
		s.props = make(map[string]any)
	}
	s.props[name] = schema
}

func (s *metaSchema) raw() json.RawMessage {
	obj := map[string]any{"type": "object", "properties": s.props}
	if s.props == nil {
		obj["properties"] = map[string]any{}
	}
	out, _ := json.Marshal(obj)
	return out
}

// registerHostedMetaTools registers the five progressive-disclosure
// meta-tools on the hosted SDK server from the assembled presentation. Call
// only when the resolved listing policy serves them (servesMetaTools); the
// catalog-operated dispatchers route through dispatchCatalogOp.
func registerHostedMetaTools(srv *sdk.Server, present *mcp.Server, resolver CredentialResolver) error {
	if srv == nil {
		return fmt.Errorf("hosted MCP server: nil SDK server for meta-tool registration")
	}
	if present == nil {
		return fmt.Errorf("hosted MCP server: nil presentation for meta-tool registration")
	}
	ms := newMetaSurface(present, resolver)
	// Defensive: the meta-tool names are reserved. A compiled op carrying one
	// would, if registered directly, collide with (or shadow) the dispatcher
	// on tools/list — fail loudly instead.
	for _, name := range []string{metaToolSearch, metaToolDescribe, metaToolInvokeRead, metaToolInvokeWrite, metaToolInvokeDestructive} {
		if _, ok, _ := ms.lookup(name); ok {
			return fmt.Errorf("hosted MCP server: compiled surface declares meta-tool name %q", name)
		}
	}
	if err := registerMetaSearchTools(srv, ms); err != nil {
		return err
	}
	if err := registerMetaDescribeTool(srv, ms); err != nil {
		return err
	}
	return registerMetaInvokeTools(srv, ms)
}

// registerMetaSearchTools registers search_tools, the discovery workflow
// entry point. The description documents the search -> describe -> invoke
// loop so a model discovers without any out-of-band knowledge.
func registerMetaSearchTools(srv *sdk.Server, ms *metaSurface) error {
	schema := &metaSchema{}
	schema.property("query", map[string]any{
		"type":        "string",
		"description": "A single keyword to search for in tool names (and, as a whole word only, descriptions). Name matches rank above description matches, so e.g. 'auth' finds the auth_* tools, not every tool whose description happens to contain a word starting with auth. Leave empty (or use 'help') for an onboarding listing of just the primary start-here tools, with a hint pointing at agent_guide and category browsing.",
	})
	schema.property("category", map[string]any{
		"type":        "string",
		"description": "Filter by category: 'core' (user commands incl. pins/websites/dns), 'account' (auth, api keys), 'names' (IPNS/ENS), 'operations', or 'storage'. Leave empty to search all categories.",
	})
	schema.property("limit", map[string]any{
		"type":        "integer",
		"description": "Optional maximum number of results to return. Leave unset for no limit.",
	})

	discoveryNote := "Search the internal tool catalog by a single keyword. No boolean (AND/OR) syntax: pass one keyword at a time (e.g. 'pin', not 'pin OR upload'). Name matches are ranked exact, then starts-with, contains, then within-segment subsequence (a fuzzy abbreviation within a single word of the name), then whole-word description matches; tools that never match are omitted. Use the 'category' filter to narrow scope and 'limit' to cap results. Leave query empty or use 'help' for an onboarding listing of just the primary start-here tools, which also carries agent_guide for the full flows and a hint pointing at category browsing for a specific domain. Workflow: after discovering a tool here, call describe_tool(name) for its input schema; the describe response carries an invokeTool field naming the typed dispatcher that executes it (invoke_read_tool for read-only tools, invoke_write_tool for mutating tools, invoke_destructive_tool for destructive tools — each dispatcher refuses out-of-class tools, so route by the named one). Capability, agent-guide, and file-transfer tools are exposed directly on the tool surface AND indexed here, so they are discoverable by name."

	desc := model.ToolDescriptor{
		Name:          metaToolSearch,
		Title:         "Search tool catalog",
		Description:   discoveryNote,
		OpenWorldHint: false,
		InputSchema:   schema.raw(),
	}
	desc.Handler = model.ToolHandler(func(_ context.Context, request model.ToolRequest) (model.ToolResult, error) {
		in, err := toolargs.DecodeToolArgs[searchToolsInput](request)
		if err != nil {
			return model.ToolResult{}, err
		}
		var data []byte
		if isOnboardingQuery(strings.ToLower(strings.TrimSpace(in.Query))) && in.Category == "" {
			res := ms.onboard()
			// Honor the documented limit contract on the onboarding path too.
			if in.Limit > 0 && len(res.Tools) > in.Limit {
				res.Tools = res.Tools[:in.Limit]
				res.Total = len(res.Tools)
			}
			data, err = json.Marshal(res)
		} else {
			tools := ms.search(in.Query, in.Category, in.Limit)
			data, err = json.Marshal(searchResult{Tools: tools, Total: len(tools)})
		}
		if err != nil {
			return model.ToolResult{}, err
		}
		return model.ToolResult{Text: string(data)}, nil
	})
	return sdk.RegisterTool(srv, sdk.HandlerDeps{}, desc)
}

// registerMetaDescribeTool registers describe_tool: full input schema for a
// single tool by name, with "did you mean ...?" recovery for unknown names.
func registerMetaDescribeTool(srv *sdk.Server, ms *metaSurface) error {
	schema := &metaSchema{}
	schema.property("name", map[string]any{
		"type":        "string",
		"description": "Tool name from search_tools result",
	})

	desc := model.ToolDescriptor{
		Name:          metaToolDescribe,
		Title:         "Describe a catalog tool",
		Description:   "Get the full input schema for a single tool by name. Use the tool name returned by search_tools. The inputSchema field contains the JSON Schema that the tool's arguments conform to.",
		OpenWorldHint: false,
		InputSchema:   schema.raw(),
	}
	desc.Handler = model.ToolHandler(func(_ context.Context, request model.ToolRequest) (model.ToolResult, error) {
		in, err := toolargs.DecodeToolArgs[describeToolInput](request)
		if err != nil {
			return model.ToolResult{IsError: true, Text: err.Error()}, nil
		}
		if in.Name == "" {
			return model.ToolResult{IsError: true, Text: "name is required"}, nil
		}
		detail, err := ms.describe(in.Name)
		if err != nil {
			resp := map[string]any{
				"error":   err.Error(),
				"suggest": ms.suggest(in.Name, 3),
			}
			out, _ := json.Marshal(resp)
			return model.ToolResult{IsError: true, Text: string(out)}, nil
		}
		data, err := json.Marshal(detail)
		if err != nil {
			return model.ToolResult{}, err
		}
		return model.ToolResult{Text: string(data)}, nil
	})
	return sdk.RegisterTool(srv, sdk.HandlerDeps{}, desc)
}

// registerMetaInvokeTools registers the three typed invoke dispatchers. Each
// executes only tools of its own safety class and refuses the rest with a
// pointer to the right dispatcher, keeping the wire annotations truthful.
func registerMetaInvokeTools(srv *sdk.Server, ms *metaSurface) error {
	specs := []struct {
		name        string
		title       string
		description string
		class       invokeClass
		readOnly    bool
		destructive bool
		openWorld   bool
	}{
		{
			name:        metaToolInvokeRead,
			title:       "Invoke a read-only catalog tool",
			description: "Execute a read-only catalog tool by name with the given arguments. This is the third step of the discovery workflow: search_tools(name) to find a tool, describe_tool(name) for its input schema (the describe response names the dispatcher to invoke), then invoke_read_tool(name, arguments) for any tool whose describe response names invoke_read_tool — read-only tools with readOnlyHint=true and no open-world interaction. The dispatcher refuses non-read-only tools; use invoke_write_tool or invoke_destructive_tool for those. The arguments object is validated against the tool's inputSchema returned by describe_tool.",
			class:       invokeClassRead,
			readOnly:    true,
		},
		{
			name:        metaToolInvokeWrite,
			title:       "Invoke a mutating catalog tool",
			description: "Execute a state-mutating (but not destructive, and generally not read-only) catalog tool by name with the given arguments. This is the third step of the discovery workflow: search_tools(name) to find a tool, describe_tool(name) for its input schema (the describe response names the dispatcher to invoke), then invoke_write_tool(name, arguments) for any tool whose describe response names invoke_write_tool — every tool that is neither read-only (invoke_read_tool) nor destructive (invoke_destructive_tool). The dispatcher refuses read-only and destructive tools; use invoke_read_tool or invoke_destructive_tool for those. The arguments object is validated against the tool's inputSchema returned by describe_tool.",
			class:       invokeClassWrite,
			openWorld:   true,
		},
		{
			name:        metaToolInvokeDestructive,
			title:       "Invoke a destructive catalog tool",
			description: "Execute a destructive (irreversible / deletion) catalog tool by name with the given arguments. This is the third step of the discovery workflow: search_tools(name) to find a tool, describe_tool(name) for its input schema (the describe response names the dispatcher to invoke), then invoke_destructive_tool(name, arguments) for any tool whose describe response names invoke_destructive_tool — tools whose hints carry destructiveHint=true. Destructive operations additionally require human confirmation (the server returns a needs_human hand-off before running). The dispatcher refuses non-destructive tools; use invoke_read_tool or invoke_write_tool for those. The arguments object is validated against the tool's inputSchema returned by describe_tool.",
			class:       invokeClassDestructive,
			destructive: true,
			openWorld:   true,
		},
	}

	for _, spec := range specs {
		spec := spec
		schema := &metaSchema{}
		schema.property("name", map[string]any{
			"type":        "string",
			"description": "Tool name from search_tools result",
		})
		schema.property("arguments", map[string]any{
			"type":        "object",
			"description": "Arguments object matching the tool's inputSchema. Use describe_tool to see the schema.",
		})

		desc := model.ToolDescriptor{
			Name:          spec.name,
			Title:         spec.title,
			Description:   spec.description,
			ReadOnly:      spec.readOnly,
			Destructive:   spec.destructive,
			OpenWorldHint: spec.openWorld,
			InputSchema:   schema.raw(),
		}
		desc.Handler = model.ToolHandler(func(ctx context.Context, request model.ToolRequest) (model.ToolResult, error) {
			in, err := toolargs.DecodeToolArgs[invokeToolInput](request)
			if err != nil {
				return model.ToolResult{IsError: true, Text: err.Error()}, nil
			}
			if in.Name == "" {
				return model.ToolResult{IsError: true, Text: "name is required"}, nil
			}
			entry, ok, _ := ms.lookup(in.Name)
			if !ok {
				// Unknown tool: offer nearest names so the agent can recover
				// without a separate search round-trip.
				suggestions := ms.suggest(in.Name, 3)
				resp := map[string]any{
					"error":   fmt.Sprintf("unknown tool: %s", in.Name),
					"suggest": suggestions,
				}
				if len(suggestions) > 0 {
					resp["message"] = "unknown tool. did you mean one of these?"
				}
				out, _ := json.Marshal(resp)
				return model.ToolResult{IsError: true, Text: string(out)}, nil
			}
			// Safety-class gate: each dispatcher admits one class only, so the
			// annotations' claimed capability boundary holds at dispatch time.
			if got := classifyDescriptor(entry); got != spec.class {
				return model.ToolResult{IsError: true, Text: fmt.Sprintf("tool %s is a %s operation; call %s(name, arguments) instead", in.Name, classNoun(got), got.dispatcher())}, nil
			}
			return ms.invoke(ctx, in.Name, in.Arguments)
		})
		if err := sdk.RegisterTool(srv, sdk.HandlerDeps{}, desc); err != nil {
			return err
		}
	}
	return nil
}

// --- Keyword matching helpers, ported from pinner-cli's catalog.go so the
// hosted discovery behaves identically to the self-hosted surface. ---

// matchRank returns -1 if the query does not match the tool at any level.
// Otherwise it returns a lower-is-better rank:
//
//	0 = exact name match
//	1 = name starts with query
//	2 = name contains query
//	3 = name is a subsequence match of query within a single name segment
//	4 = description contains query as a whole token
func matchRank(query, name, desc string) int {
	if name == query {
		return 0
	}
	if strings.HasPrefix(name, query) {
		return 1
	}
	if strings.Contains(name, query) {
		return 2
	}
	if matchSegmentSubsequence(query, name) {
		return 3
	}
	if descContainsToken(desc, query) {
		return 4
	}
	return -1
}

// descContainsToken reports whether query appears in desc as a complete
// word/phrase, bounded on both sides by a non-alphanumeric boundary (or
// start/end of string). It is case-insensitive on both sides: "auth" does not
// match within "authenticated".
func descContainsToken(desc, query string) bool {
	if query == "" {
		return false
	}
	lowerDesc := strings.ToLower(desc)
	lowerQuery := strings.ToLower(query)
	start := 0
	for {
		idx := strings.Index(lowerDesc[start:], lowerQuery)
		if idx < 0 {
			return false
		}
		abs := start + idx
		beforeOK := abs == 0 || !isAlphaNum(rune(lowerDesc[abs-1]))
		after := abs + len(lowerQuery)
		afterOK := after >= len(lowerDesc) || !isAlphaNum(rune(lowerDesc[after]))
		if beforeOK && afterOK {
			return true
		}
		start = abs + 1
	}
}

// isAlphaNum reports whether r is an ASCII letter or digit (token body char).
func isAlphaNum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
}

// matchSegmentSubsequence reports whether src is a subsequence of any single
// underscore- or hyphen-delimited segment of name. Fuzzy subsequence matching
// is scoped to one segment so a query cannot match by scattering letters
// across unrelated segments, while within-segment abbreviations still match
// ("pload" matches "upload").
func matchSegmentSubsequence(src, name string) bool {
	src = strings.ToLower(strings.TrimSpace(src))
	if src == "" {
		return false
	}
	for _, seg := range segmentize(name) {
		if isSubsequence(src, seg) {
			return true
		}
	}
	return false
}

// segmentize splits a tool name into its underscore- and hyphen-delimited
// words (e.g. "vault_cache_rebuild" -> ["vault", "cache", "rebuild"]).
func segmentize(name string) []string {
	return strings.FieldsFunc(name, func(r rune) bool {
		return r == '_' || r == '-'
	})
}

// isSubsequence checks whether every character in src appears in target in
// the same order, but not necessarily contiguously.
func isSubsequence(src, target string) bool {
	if len(src) == 0 {
		return true
	}
	if len(src) > len(target) {
		return false
	}
	i := 0
	for _, c := range target {
		if byte(src[i]) == byte(c) {
			i++
			if i == len(src) {
				return true
			}
		}
	}
	return false
}

// levenshtein returns the edit distance between two strings (case-sensitive;
// callers pass lowercased inputs). A compact, dependency-free implementation
// matching the CLI assembly's suggestion ranking.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
