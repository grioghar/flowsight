package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/grioghar/flowsight/internal/core"
	_ "github.com/grioghar/flowsight/internal/modules"
)

// OpDoc describes an operation from OpenAPI spec
type OpDoc struct {
	Path     string
	Method   string
	Summary  string
	Module   string
	Params   []ParamDoc
	ReqBody  map[string]any
	RespBody map[string]any
}

type ParamDoc struct {
	Name        string
	Type        string
	Required    bool
	Description string
	Example     any
}

func main() {
	// Create a temp directory for the store
	tempDir := "/tmp/flowsight-apidoc"
	os.MkdirAll(tempDir, 0700)
	defer os.RemoveAll(tempDir)

	// Use a no-op logger to suppress module loading messages
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 100}))
	c, err := core.New("0.9.8r000000000000", "", tempDir, nil, logger)
	if err != nil {
		log.Fatalf("failed to create core: %v", err)
	}

	// Load modules
	c.LoadModules()

	// Generate OpenAPI spec
	spec := c.API.OpenAPI()

	// Output header
	fmt.Print(`# API reference

FlowSight is driven entirely through a JSON HTTP API; the UI uses nothing else. On OPNsense the GUI page proxies it at ` + "`" + `/flowsight.php?api=<path>` + "`" + ` with the session's CSRF token; on other systems it listens at ` + "`" + `http://127.0.0.1:8080` + "`" + ` by default.

## API Explorer

An interactive OpenAPI explorer is built into FlowSight at the **API** page under Administration. It provides:
- Grouped operations by area (Monitor, Inventory, Protect, Administration)
- Parameter and request body templates
- Live request/response with timing
- Copy as curl for easy CLI testing

Download the full OpenAPI 3.0 specification at ` + "`" + `GET /api/openapi.json` + "`" + ` for use with Swagger UI, Insomnia, Postman, or other tools.

## Conventions

- Every write (POST) needs the header ` + "`" + `X-Requested-With: Flowsight` + "`" + `. From anything that is not the OPNsense GUI or loopback, also send the API token in ` + "`" + `X-Flowsight-Token` + "`" + ` (or sign in once at ` + "`" + `POST /api/login` + "`" + ` with ` + "`" + `{"token": …}` + "`" + ` to get a session cookie).
- Responses are JSON objects. Errors are ` + "`" + `{"error": "message"}` + "`" + ` with a matching status: 400 invalid input, 402 the feature needs a higher license tier or the license has expired (` + "`" + `locked` + "`" + ` or ` + "`" + `expired` + "`" + ` is set, with ` + "`" + `feature` + "`" + ` and ` + "`" + `required` + "`" + `), 403 forbidden (missing header, read-only instance, locked key), 404 unknown route, 500 a backend failed.
- Time windows take ` + "`" + `hours` + "`" + ` (default 24). Lists take ` + "`" + `limit` + "`" + `.
- The machine-readable description is at ` + "`" + `GET /api/openapi.json` + "`" + `.
- Every write is recorded in the audit log (` + "`" + `GET /api/system/audit` + "`" + `) with the user and client address.

## Routes

`)

	// Parse operations by module
	paths := spec["paths"].(map[string]map[string]any)
	modules := make(map[string][]OpDoc)

	pathKeys := make([]string, 0, len(paths))
	for p := range paths {
		pathKeys = append(pathKeys, p)
	}
	sort.Strings(pathKeys)

	for _, path := range pathKeys {
		methods := paths[path]
		methodKeys := make([]string, 0, len(methods))
		for m := range methods {
			methodKeys = append(methodKeys, m)
		}
		sort.Strings(methodKeys)

		for _, method := range methodKeys {
			opRaw := methods[method].(map[string]any)
			op := OpDoc{
				Path:   path,
				Method: strings.ToUpper(method),
			}

			if s, ok := opRaw["summary"]; ok {
				op.Summary = s.(string)
			}

			// Extract module from path /api/{module}/...
			parts := strings.Split(path, "/")
			if len(parts) > 2 {
				op.Module = parts[2]
			}

			// Extract parameters
			if params, ok := opRaw["parameters"].([]map[string]any); ok {
				for _, p := range params {
					pd := ParamDoc{
						Name: p["name"].(string),
					}
					if d, ok := p["description"]; ok {
						pd.Description = d.(string)
					}
					if r, ok := p["required"].(bool); ok {
						pd.Required = r
					}
					if s, ok := p["schema"].(map[string]any); ok {
						if t, ok := s["type"]; ok {
							pd.Type = t.(string)
						}
						if ex, ok := s["example"]; ok {
							pd.Example = ex
						}
					}
					op.Params = append(op.Params, pd)
				}
			}

			// Extract request body
			if rb, ok := opRaw["requestBody"].(map[string]any); ok {
				if content, ok := rb["content"].(map[string]any); ok {
					if ajson, ok := content["application/json"].(map[string]any); ok {
						if schema, ok := ajson["schema"]; ok {
							op.ReqBody = schema.(map[string]any)
						}
					}
				}
			}

			// Extract response
			if resp, ok := opRaw["responses"].(map[string]any); ok {
				if resp200, ok := resp["200"].(map[string]any); ok {
					if content, ok := resp200["content"].(map[string]any); ok {
						if ajson, ok := content["application/json"].(map[string]any); ok {
							if schema, ok := ajson["schema"]; ok {
								op.RespBody = schema.(map[string]any)
							}
						}
					}
				}
			}

			modules[op.Module] = append(modules[op.Module], op)
		}
	}

	// Output by module
	moduleNames := make([]string, 0, len(modules))
	for m := range modules {
		moduleNames = append(moduleNames, m)
	}
	sort.Strings(moduleNames)

	for _, modName := range moduleNames {
		ops := modules[modName]
		fmt.Printf("### %s\n\n", modName)

		// Group by summary patterns (e.g., "List", "Create", "Get", "Update", "Delete")
		groups := make(map[string][]OpDoc)
		for _, op := range ops {
			group := ""
			if strings.Contains(op.Summary, "List") || strings.Contains(op.Summary, "Get all") {
				group = "**List operations**"
			} else if strings.Contains(op.Summary, "Create") {
				group = "**Create operations**"
			} else if strings.Contains(op.Summary, "Update") {
				group = "**Update operations**"
			} else if strings.Contains(op.Summary, "Delete") {
				group = "**Delete operations**"
			} else {
				group = "**Other operations**"
			}
			groups[group] = append(groups[group], op)
		}

		// Output by group
		groupNames := []string{"**List operations**", "**Create operations**", "**Update operations**", "**Delete operations**", "**Other operations**"}
		for _, gn := range groupNames {
			if len(groups[gn]) == 0 {
				continue
			}
			fmt.Printf("%s\n", gn)
			fmt.Printf("| Method | Path | What | Parameters |\n")
			fmt.Printf("|---|---|---|---|\n")
			for _, op := range groups[gn] {
				params := ""
				for _, p := range op.Params {
					if params != "" {
						params += ", "
					}
					params += p.Name
				}
				if params == "" {
					params = "none"
				}
				fmt.Printf("| %s | `%s` | %s | %s |\n",
					op.Method, op.Path, op.Summary, params)
			}
			fmt.Printf("\n")
		}
	}

	fmt.Print(`## Authentication

The API accepts authentication in three ways:

1. **Token header**: Send ` + "`" + `X-Flowsight-Token: your-api-token` + "`" + ` with every request.
2. **Bearer token**: Send ` + "`" + `Authorization: Bearer your-api-token` + "`" + ` with every request.
3. **Session cookie**: POST ` + "`" + `{"token": "your-api-token"}` + "`" + ` to ` + "`" + `/api/login` + "`" + ` to receive an ` + "`" + `fs_session` + "`" + ` cookie.

Loopback clients (127.0.0.1, ::1) without a token configured are trusted.

## Common parameters

Many endpoints accept query parameters to control scope and pagination:
- ` + "`" + `hours` + "`" + `: Time window in hours (default varies by endpoint; max 9600 hours).
- ` + "`" + `minutes` + "`" + `: Time window in minutes (alternative to hours).
- ` + "`" + `limit` + "`" + `: Maximum number of records to return (default 100; max 10000).
- ` + "`" + `offset` + "`" + `: Pagination offset for large result sets.

## Response format

All responses are JSON. Successful requests return the requested data. Errors return:

` + "```json" + `
{"error": "error message"}
` + "```" + `

Status codes:
- ` + "`" + `200` + "`" + ` OK
- ` + "`" + `400` + "`" + ` Bad request (invalid input or missing required field)
- ` + "`" + `402` + "`" + ` License tier or feature required, or license expired
- ` + "`" + `403` + "`" + ` Forbidden (insufficient permissions, read-only instance, or missing header)
- ` + "`" + `404` + "`" + ` Not found
- ` + "`" + `500` + "`" + ` Internal server error

`)
}
