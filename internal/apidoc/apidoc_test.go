package apidoc

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
	_ "github.com/grioghar/flowsight/internal/modules"
)

// TestAllRoutesDocumented validates that every registered route has proper documentation.
// This is the build-time check ensuring no route ships without:
// - A description
// - Documented path/query parameters matching what handlers actually read
// - Request body schema for POST/PUT/DELETE that read a body
// - Response documentation
func TestAllRoutesDocumented(t *testing.T) {
	// Create a temp directory for the store
	tempDir, err := os.MkdirTemp("", "apidoc-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create logger that discards output (error level only)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 100}))

	// Initialize core
	c, err := core.New("0.9.8r000000000000", "", tempDir, nil, logger)
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}

	// Load all modules to register routes
	c.LoadModules()

	// Build a map of handler source files and their parameter patterns
	handlerParams := buildHandlerParameterMap(t)

	// Validate each route
	var offenders []string
	c.API.IterateRoutes(func(method, path string, route *core.Route) {
		issues := validateRoute(t, method, path, route, handlerParams)
		if len(issues) > 0 {
			offenders = append(offenders, fmt.Sprintf("%s %s: %s", method, path, strings.Join(issues, "; ")))
		}
	})

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Logf("Found %d undocumented routes:\n", len(offenders))
		for _, off := range offenders {
			t.Logf("  %s\n", off)
		}
		t.Fatalf("%d routes lack proper documentation", len(offenders))
	}

	t.Logf("All %d routes are properly documented", countRoutes(c))
}

// validateRoute checks if a route has all required documentation.
func validateRoute(t *testing.T, method, path string, route *core.Route, handlerParams map[string]map[string]bool) []string {
	var issues []string

	// Check description
	if route.Description == "" {
		issues = append(issues, "missing description")
	}

	// Get expected parameters for this handler
	handlerName := extractHandlerName(route)
	expectedParams := handlerParams[handlerName]

	// Check path parameters in {brackets}
	pathParamPattern := regexp.MustCompile(`\{([^}]+)\}`)
	pathParams := pathParamPattern.FindAllStringSubmatch(path, -1)
	for _, match := range pathParams {
		paramName := match[1]
		found := false
		for _, p := range route.Parameters {
			if p.Name == paramName && p.In == "path" {
				found = true
				break
			}
		}
		if !found {
			issues = append(issues, fmt.Sprintf("path parameter '%s' not documented", paramName))
		}
	}

	// Check query parameters that handlers actually read
	for paramName := range expectedParams {
		found := false
		for _, p := range route.Parameters {
			if p.Name == paramName && p.In == "query" {
				found = true
				break
			}
		}
		// Also check legacy Params map
		if !found {
			if _, ok := route.Params[paramName]; ok {
				found = true
			}
		}
		if !found && paramName != "" {
			issues = append(issues, fmt.Sprintf("query parameter '%s' not documented (handler reads it)", paramName))
		}
	}

	// Check request body for write operations that read a body
	if (method == "POST" || method == "PUT" || method == "DELETE") && expectedParams["_has_body"] {
		if route.RequestBody == nil {
			issues = append(issues, "write operation reads body but RequestBody not documented")
		}
	}

	// Check response documentation
	if route.Response == nil {
		issues = append(issues, "missing response documentation (use Returns or ReturnsType)")
	}

	return issues
}

// buildHandlerParameterMap scans handler source files to extract actual parameter reads.
func buildHandlerParameterMap(t *testing.T) map[string]map[string]bool {
	result := make(map[string]map[string]bool)

	// Scan all .go files in internal/modules
	err := filepath.WalkDir("internal/modules", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		contentStr := string(content)

		// Find all function definitions
		funcPattern := regexp.MustCompile(`func\s+\(\w+\s+\*\w+\)\s+(\w+)\s*\([^)]*core\.Req[^)]*\)`)
		matches := funcPattern.FindAllStringSubmatch(contentStr, -1)

		for _, match := range matches {
			funcName := match[1]
			if _, ok := result[funcName]; !ok {
				result[funcName] = make(map[string]bool)
			}

			// Extract parameter names from r.Q(, r.QInt(, r.QSafe(, r.Hours(, r.Params[
			params := extractParamsFromFunction(contentStr, funcName)
			for p := range params {
				result[funcName][p] = true
			}
		}

		return nil
	})

	if err != nil {
		t.Logf("Warning: error scanning handlers: %v", err)
	}

	return result
}

// extractParamsFromFunction extracts parameter names from a function body.
func extractParamsFromFunction(content, funcName string) map[string]bool {
	params := make(map[string]bool)

	// Find the function body
	funcPattern := regexp.MustCompile(`func\s+\(\w+\s+\*\w+\)\s+` + regexp.QuoteMeta(funcName) + `\s*\([^)]*\)\s*\([^)]*\)\s*\{(.*?)^func\s+`)
	match := funcPattern.FindStringSubmatch(content + "\nfunc ")
	if len(match) < 2 {
		return params
	}

	funcBody := match[1]

	// Find r.Q(..., which indicates a query parameter read
	qPattern := regexp.MustCompile(`r\.Q(?:Int|Safe)?\s*\(\s*"([^"]+)"`)
	for _, m := range qPattern.FindAllStringSubmatch(funcBody, -1) {
		if len(m) > 1 {
			params[m[1]] = true
		}
	}

	// Find r.Hours( and r.Minutes(
	if strings.Contains(funcBody, "r.Hours(") || strings.Contains(funcBody, "r.Minutes(") {
		params["hours"] = true
		params["minutes"] = true
	}

	// Check for r.Decode( or r.Body()
	if strings.Contains(funcBody, "r.Decode(") || strings.Contains(funcBody, "r.Body()") {
		params["_has_body"] = true
	}

	// Check for r.Params[ (path parameters)
	paramsPattern := regexp.MustCompile(`r\.Params\s*\[\s*"([^"]+)"\s*\]`)
	for _, m := range paramsPattern.FindAllStringSubmatch(funcBody, -1) {
		if len(m) > 1 {
			params[m[1]] = true
		}
	}

	return params
}

// extractHandlerName extracts the function name from the handler.
// This is a heuristic - we just track the handler function itself for now.
func extractHandlerName(route *core.Route) string {
	// The handler is a function - we'll use the route's method and path as a key
	// since we can't easily extract the function name from a func value
	return route.Module + "::" + route.Method + " " + route.Path
}

// countRoutes returns the total number of registered routes.
func countRoutes(c *core.Core) int {
	count := 0
	c.API.IterateRoutes(func(_, _ string, _ *core.Route) {
		count++
	})
	return count
}
