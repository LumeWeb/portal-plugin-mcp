package api

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"html/template"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

//go:embed home.html
var homeHTML string

//go:embed home.json
var homeJSON string

//go:embed wizard_templates.html
var wizardTemplatesHTML string

var (
	homepageTemplate *template.Template
	wizardTemplate   *template.Template
)

func init() {
	// The landing page and the OAuth consent page share the same layout/theme
	// (layout.html, CSS defined once); each page only supplies its
	// page-title/page-content blocks.
	homepageTemplate = template.Must(template.New("home").
		Parse(layoutHTML))
	template.Must(homepageTemplate.New("page").Parse(homeHTML))
	template.Must(homepageTemplate.Parse(`{{define "home"}}{{template "layout" .}}{{end}}`))

	// The wizard copy in home.json is itself a template. Config-derived values
	// are bound with {{jval .Field}} actions, executed into the JSON document
	// at request time. jval JSON-escapes and HTML-neutralizes every value, so
	// the assembled payload stays valid JSON and cannot break out of the
	// surrounding <script> tag.
	wizardTemplate = template.Must(template.New("home.json").
		Funcs(template.FuncMap{"jval": jsonRaw}).
		Parse(homeJSON))
}

// homepageData carries the values rendered into the MCP subdomain landing page.
type homepageData struct {
	PortalName string
	// WizardJSON is the fully rendered wizard configuration (see wizardTemplate),
	// injected into the page.
	WizardJSON template.JS
	// WizardTemplates is the Handlebars template tags (wizard_templates.html),
	// injected as trusted raw HTML so the page's own Go template never parses
	// the Handlebars {{ }} actions inside them.
	WizardTemplates template.HTML
}

// wizardData carries the config-derived values available to the home.json
// template.
type wizardData struct {
	PortalName  string
	ResourceURL string
	AllowDomain string
}

// jsonRaw escapes s for embedding inside an existing JSON string literal and
// additionally escapes the HTML-special bytes <, > and & so a hostile config
// value cannot break out of the surrounding <script> tag. Placeholders render
// inside string contexts, so no surrounding quotes are added (they are already
// part of home.json); this keeps the assembled document valid JSON.
func jsonRaw(s string) string {
	b, _ := json.Marshal(s)
	inner := string(b[1 : len(b)-1])
	r := strings.NewReplacer(
		"&", `\u0026`,
		"<", `\u003c`,
		">", `\u003e`,
	)
	return r.Replace(inner)
}

// mcpDomain returns the bare host of the MCP subdomain (e.g. "mcp.example.com"),
// used where clients ask for the domain to allowlist.
func (a *API) mcpDomain() string {
	u, err := url.Parse(a.baseURL)
	if err == nil && u.Host != "" {
		return u.Host
	}
	// baseURL may be a bare host (Core.Domain fallback) with no scheme to
	// parse; honor it rather than substituting the display name.
	return a.baseURL
}

// homepageHandler returns the MCP subdomain landing page: a server-rendered
// (no SPA) setup wizard that walks users through connecting an MCP client to
// the resource path. Copy lives in home.json so it stays editable without
// touching Go code; config-derived values are interpolated via the template.
func (a *API) homepageHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		res := c.Response()
		res.Header().Set("Content-Type", "text/html; charset=utf-8")
		res.Header().Set("Cache-Control", "no-cache")

		var buf bytes.Buffer
		if err := wizardTemplate.Execute(&buf, wizardData{
			PortalName:  a.portalName,
			ResourceURL: a.resourceURL,
			AllowDomain: a.mcpDomain(),
		}); err != nil {
			return err
		}

		data := layoutData{
			MetaDescription: a.portalName + " MCP server setup",
			PageData: homepageData{
				PortalName:      a.portalName,
				WizardJSON:      template.JS(buf.String()),
				WizardTemplates: template.HTML(wizardTemplatesHTML),
			},
		}
		return homepageTemplate.ExecuteTemplate(res.Writer, "home", data)
	}
}
