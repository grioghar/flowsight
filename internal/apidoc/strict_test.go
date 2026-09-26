package apidoc

// The documentation contract, checked from the source. A route is documented
// when its description says what it is for, every query and path parameter
// its handler reads is declared, a handler that decodes a body declares the
// body, and a GET answers with a real example rather than a stub. The
// handler is found from the registered function value, and what it reads is
// found by walking its syntax tree, so nothing here depends on naming
// conventions or on the author remembering to say what the code does.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

type reads struct {
	queries map[string]bool
	window  bool // r.Hours / r.Minutes / r.Since: hours, minutes (and from/to when used)
	body    bool
	params  map[string]bool
}

func TestRouteDocumentationIsReal(t *testing.T) {
	tempDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 100}))
	c, err := core.New("0.9.8r000000000000", "", tempDir, nil, logger)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	c.LoadModules()
	facts := scanHandlers(t)
	var offenders []string
	total, stubsOnWrites := 0, 0
	c.API.IterateRoutes(func(method, path string, route *core.Route) {
		total++
		var issues []string
		if len(strings.TrimSpace(route.Description)) < 25 {
			issues = append(issues, "description shorter than 25 characters")
		}
		name := handlerKey(route.Handler)
		f, known := facts[name]
		if !known {
			issues = append(issues, "handler "+name+" not found in source (helper or closure?)")
		}
		declared := map[string]bool{}
		for _, p := range route.Parameters {
			declared[p.In+":"+p.Name] = true
		}
		for k := range route.Params {
			declared["query:"+k] = true
		}
		for _, seg := range strings.Split(path, "/") {
			if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
				n := strings.Trim(seg, "{}")
				if !declared["path:"+n] {
					issues = append(issues, "path parameter {"+n+"} not declared")
				}
			}
		}
		if known {
			for q := range f.queries {
				if !declared["query:"+q] {
					issues = append(issues, "query parameter "+q+" read but not declared")
				}
			}
			if f.window && !(declared["query:hours"] || declared["query:minutes"]) {
				issues = append(issues, "time window (hours/minutes) read but not declared")
			}
			for p := range f.params {
				if !declared["path:"+p] {
					issues = append(issues, "path parameter "+p+" read via r.Params but not declared")
				}
			}
			if f.body && route.RequestBody == nil {
				issues = append(issues, "request body decoded but not declared")
			}
		}
		if route.Response == nil {
			issues = append(issues, "no response documented")
		} else if isStub(route.Response.Example) && route.Response.Schema == nil {
			if method == "GET" {
				issues = append(issues, "GET response is the {\"ok\": true} stub")
			} else {
				stubsOnWrites++
			}
		}
		if len(issues) > 0 {
			offenders = append(offenders, fmt.Sprintf("%s %s (%s): %s", method, path, name, strings.Join(issues, "; ")))
		}
	})
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Log(o)
	}
	t.Logf("routes %d, offenders %d, stub responses on write routes %d", total, len(offenders), stubsOnWrites)
	if len(offenders) > 0 {
		t.Fatalf("%d of %d routes are not documented to the contract", len(offenders), total)
	}
}

func isStub(ex any) bool {
	if ex == nil {
		return true
	}
	m, ok := ex.(map[string]any)
	if !ok {
		return false
	}
	if len(m) == 0 {
		return true
	}
	if len(m) == 1 {
		if v, ok := m["ok"]; ok {
			b, isB := v.(bool)
			return isB && b
		}
	}
	return false
}

// handlerKey is "package.method" for the registered handler function.
func handlerKey(h core.Handler) string {
	if h == nil {
		return "nil"
	}
	n := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	n = strings.TrimSuffix(n, "-fm")
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	// alerting.(*Module).apiGetRules  or  alerting.apiFoo
	parts := strings.Split(n, ".")
	return parts[0] + "." + parts[len(parts)-1]
}

// scanHandlers walks every module's source and records, per method or
// function that takes a *core.Req, what it reads from the request.
func scanHandlers(t *testing.T) map[string]*reads {
	out := map[string]*reads{}
	fset := token.NewFileSet()
	err := filepath.WalkDir("../modules", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.Contains(d.Name(), ".backup") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		pkg := file.Name.Name
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			reqVar := reqParamName(fn)
			if reqVar == "" {
				continue
			}
			r := &reads{queries: map[string]bool{}, params: map[string]bool{}}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok || id.Name != reqVar {
						return true
					}
					switch sel.Sel.Name {
					case "Q", "QInt", "QSafe", "QBool", "QFloat", "QStr":
						if len(x.Args) > 0 {
							if lit, ok := x.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								r.queries[strings.Trim(lit.Value, "`\"")] = true
							}
						}
					case "Hours", "Minutes", "Since", "Window":
						r.window = true
					case "Decode", "Body", "BodyBytes", "JSON":
						r.body = true
					}
				case *ast.IndexExpr:
					sel, ok := x.X.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Params" {
						return true
					}
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == reqVar {
						if lit, ok := x.Index.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							r.params[strings.Trim(lit.Value, "`\"")] = true
						}
					}
				}
				return true
			})
			out[pkg+"."+fn.Name.Name] = r
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

// reqParamName is the name of the *core.Req parameter, or "" when the
// function is not a handler.
func reqParamName(fn *ast.FuncDecl) string {
	for _, p := range fn.Type.Params.List {
		star, ok := p.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Req" {
			continue
		}
		if len(p.Names) > 0 {
			return p.Names[0].Name
		}
	}
	return ""
}
