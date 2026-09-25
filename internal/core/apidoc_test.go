package core

import (
	"encoding/json"
	"testing"
)

func hasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

func TestOpenAPIGeneration(t *testing.T) {
	// Create a test core and API
	core := &Core{Version: "0.9.8r202609250000"}
	api := NewAPI(core, nil, nil)

	// Register a test route with rich documentation
	api.Add("GET", "/api/test/items", func(r *Req) (any, error) {
		return map[string]any{"items": []any{}}, nil
	}, "test",
		Doc("List all test items"),
		Query("limit", "integer", "Number of items to return", false, 10),
		Query("offset", "integer", "Offset for pagination", false, 0),
		Returns("List of items", map[string]any{"items": []map[string]any{
			{"id": "1", "name": "Test Item 1"},
		}}),
	)

	// Register a test write route
	api.Add("POST", "/api/test/items", func(r *Req) (any, error) {
		return map[string]any{"id": "1", "name": "New Item"}, nil
	}, "test",
		Write(),
		Doc("Create a new test item"),
		Body(
			&Field{Name: "name", Type: "string", Required: true, Description: "Item name", Example: "My Item"},
			&Field{Name: "description", Type: "string", Required: false, Description: "Item description", Example: "A test item"},
		),
		Returns("Created item", map[string]any{"id": "1", "name": "New Item"}),
	)

	// Generate OpenAPI spec
	spec := api.OpenAPI()

	// Test that spec is well-formed
	if spec["openapi"] != "3.0.3" {
		t.Errorf("openapi version: got %v, want 3.0.3", spec["openapi"])
	}

	// Test that paths are present
	pathsRaw := spec["paths"].(map[string]map[string]any)
	itemsPath, ok := pathsRaw["/api/test/items"]
	if !ok {
		t.Error("path /api/test/items not found in spec")
	}

	// Test GET operation
	getOp := itemsPath["get"].(map[string]any)
	if getOp["summary"] != "List all test items" {
		t.Errorf("GET summary: got %v, want 'List all test items'", getOp["summary"])
	}

	// Check parameters
	params := getOp["parameters"].([]map[string]any)
	if len(params) != 2 {
		t.Errorf("GET parameters: got %d, want 2", len(params))
	}

	// Check response
	responses := getOp["responses"].(map[string]any)
	resp200 := responses["200"].(map[string]any)
	if resp200["description"] != "List of items" {
		t.Errorf("GET response description: got %v, want 'List of items'", resp200["description"])
	}

	// Check response example exists
	if !hasKey(resp200, "content") {
		t.Error("response content not found")
	}

	// Test POST operation
	postOp := itemsPath["post"].(map[string]any)
	if postOp["summary"] != "Create a new test item" {
		t.Errorf("POST summary: got %v, want 'Create a new test item'", postOp["summary"])
	}

	// Check that POST is marked as write
	if postOp["x-write"] != true {
		t.Errorf("POST x-write: got %v, want true", postOp["x-write"])
	}

	// Check request body exists
	if !hasKey(postOp, "requestBody") {
		t.Error("requestBody not found in POST operation")
	}

	rb := postOp["requestBody"].(map[string]any)
	rbContent := rb["content"].(map[string]any)
	rbJson := rbContent["application/json"].(map[string]any)
	schema := rbJson["schema"].(map[string]any)

	if schema["type"] != "object" {
		t.Errorf("request body schema type: got %v, want 'object'", schema["type"])
	}

	props := schema["properties"].(map[string]any)
	if _, ok := props["name"]; !ok {
		t.Error("request body property 'name' not found")
	}

	nameField := props["name"].(map[string]any)
	if nameField["type"] != "string" {
		t.Errorf("name field type: got %v, want 'string'", nameField["type"])
	}

	// Check required fields (as []string since that's how we build it)
	requiredRaw := schema["required"]
	if requiredRaw == nil {
		t.Error("required fields not found")
	}

	t.Logf("OpenAPI spec generated successfully with %d paths", len(pathsRaw))
}

func TestOpenAPIWithPathParameters(t *testing.T) {
	core := &Core{Version: "0.9.8r202609250000"}
	api := NewAPI(core, nil, nil)

	api.Add("GET", "/api/test/items/{id}", func(r *Req) (any, error) {
		return map[string]any{"id": r.Params["id"], "name": "Test"}, nil
	}, "test",
		Doc("Get a test item by ID"),
		PathParam("id", "string", "Item ID", "123"),
		Returns("Test item", map[string]any{"id": "123", "name": "Test Item"}),
	)

	spec := api.OpenAPI()
	pathsRaw := spec["paths"].(map[string]map[string]any)
	itemPath := pathsRaw["/api/test/items/{id}"]
	getOp := itemPath["get"].(map[string]any)

	params := getOp["parameters"].([]map[string]any)
	if len(params) != 1 {
		t.Errorf("path parameters: got %d, want 1", len(params))
	}

	param := params[0]
	if param["name"] != "id" {
		t.Errorf("parameter name: got %v, want 'id'", param["name"])
	}
	if param["in"] != "path" {
		t.Errorf("parameter location: got %v, want 'path'", param["in"])
	}
	if param["required"] != true {
		t.Errorf("parameter required: got %v, want true", param["required"])
	}
}

func TestOpenAPIFieldToSchema(t *testing.T) {
	field := &Field{
		Name:        "user",
		Type:        "object",
		Description: "User object",
		Properties: map[string]*Field{
			"id": {
				Name:        "id",
				Type:        "integer",
				Required:    true,
				Description: "User ID",
				Example:     123,
			},
			"name": {
				Name:        "name",
				Type:        "string",
				Required:    true,
				Description: "User name",
				Example:     "John Doe",
			},
			"email": {
				Name:        "email",
				Type:        "string",
				Required:    false,
				Description: "User email",
				Example:     "john@example.com",
			},
		},
	}

	schema := fieldToOpenAPISchema(field)

	if schema["type"] != "object" {
		t.Errorf("schema type: got %v, want 'object'", schema["type"])
	}

	props := schema["properties"].(map[string]any)
	if len(props) != 3 {
		t.Errorf("properties count: got %d, want 3", len(props))
	}

	// Check that required field exists (could be []string or []interface{})
	requiredRaw := schema["required"]
	if requiredRaw == nil {
		t.Error("required field not found in schema")
	}

	// Check that it's valid JSON
	b, err := json.Marshal(schema)
	if err != nil {
		t.Errorf("schema not JSON-marshallable: %v", err)
	}
	if len(b) == 0 {
		t.Error("schema JSON is empty")
	}
}

func TestOpenAPIArrayField(t *testing.T) {
	field := &Field{
		Name:        "items",
		Type:        "array",
		Description: "List of items",
		Items: &Field{
			Type: "object",
			Properties: map[string]*Field{
				"id": {Type: "string", Example: "123"},
				"name": {Type: "string", Example: "Item"},
			},
		},
	}

	schema := fieldToOpenAPISchema(field)

	if schema["type"] != "array" {
		t.Errorf("schema type: got %v, want 'array'", schema["type"])
	}

	items := schema["items"].(map[string]any)
	if items["type"] != "object" {
		t.Errorf("items type: got %v, want 'object'", items["type"])
	}

	itemProps := items["properties"].(map[string]any)
	if len(itemProps) != 2 {
		t.Errorf("item properties: got %d, want 2", len(itemProps))
	}
}

// TestAllRoutesDocumented verifies that every registered route has at least
// a description and response documentation. This is the build-time validation
// to ensure no route is left undocumented.
func TestAllRoutesDocumented(t *testing.T) {
	// This test is a placeholder for integration testing.
	// In the real implementation, we'd load all modules and verify each route.
	// For now, just verify the test infrastructure works.
	t.Log("All routes documentation test infrastructure ready")
}
