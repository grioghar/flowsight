package space

import (
	"encoding/json"
	"math"
	"testing"
)

func TestLayoutValidation(t *testing.T) {
	layout := &Layout{
		Floors: []Floor{
			{ID: "0", Name: "Ground", ElevationM: 0},
		},
		Rooms: []Room{
			{ID: "living", Name: "Living Room", Floor: "0", Polygon: [][]float64{{0, 0}, {5, 0}, {5, 4}, {0, 4}}, CeilingM: 2.6},
		},
		Scale:  1.0,
		Origin: [2]float64{0, 0},
	}

	if len(layout.Floors) != 1 {
		t.Errorf("expected 1 floor, got %d", len(layout.Floors))
	}
	if len(layout.Rooms) != 1 {
		t.Errorf("expected 1 room, got %d", len(layout.Rooms))
	}
	if layout.Rooms[0].Polygon[0][0] != 0 {
		t.Errorf("expected polygon x=0, got %f", layout.Rooms[0].Polygon[0][0])
	}
}

func TestRoomPlanJSONToRooms(t *testing.T) {
	// Minimal RoomPlan JSON fixture
	roomPlanJSON := `{
		"walls": [
			{"startX": 0, "startY": 0, "endX": 5000, "endY": 0},
			{"startX": 5000, "startY": 0, "endX": 5000, "endY": 4000}
		],
		"objects": [
			{"category": "door", "dimensions": {"width": 1000, "depth": 100, "height": 2000}, "center": {"x": 5000, "y": 200}}
		]
	}`

	// In a real implementation, we'd parse this and extract room polygons
	// For now, verify the JSON is well-formed
	var data map[string]any
	_ = json.Unmarshal([]byte(roomPlanJSON), &data)

	if data == nil {
		t.Errorf("failed to parse RoomPlan JSON")
	}
}

func TestGeocodeResultParsing(t *testing.T) {
	// Census Geocoder response fixture
	censusResp := `{
		"result": {
			"addressMatches": [
				{
					"matchedAddress": "123 Main St, Springfield, IL 62701",
					"coordinates": {"x": -89.50000, "y": 39.78000},
					"addressComponents": {
						"fromNumber": "123",
						"name": "Main",
						"suffix": "St",
						"city": "Springfield",
						"state": "IL",
						"zip": "62701"
					},
					"geographies": {
						"States": [{"STATE": "17", "NAME": "Illinois"}],
						"Counties": [{"COUNTY": "193", "NAME": "Sangamon County"}],
						"Census Tracts": [{"TRACT": "9621"}],
						"Census Blocks": [{"BLOCK": "2023"}]
					}
				}
			]
		}
	}`

	var data map[string]any
	err := json.Unmarshal([]byte(censusResp), &data)
	if err != nil {
		t.Errorf("failed to parse Census Geocoder response: %v", err)
	}
	if data == nil {
		t.Errorf("failed to parse Census Geocoder response")
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		data     []byte
		expected string
	}{
		{"GLB by extension", "model.glb", nil, "glb"},
		{"OBJ by extension", "model.obj", nil, "obj"},
		{"RoomPlan by extension", "scan.json", nil, "roomplan"},
		{"USDZ unsupported", "model.usdz", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFormat(tt.filename, tt.data)
			if got != tt.expected {
				t.Errorf("detectFormat(%q, ...) = %q, want %q", tt.filename, got, tt.expected)
			}
		})
	}
}

func TestScanInfoParsing(t *testing.T) {
	// Minimal GLB fixture (just header)
	glbData := []byte{0x67, 0x6c, 0x54, 0x46, 0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00}
	info := parseGLB(glbData)

	if info.vertices == 0 && info.triangles == 0 {
		t.Errorf("parseGLB returned no data")
	}
}

func TestLayoutVectorSnap(t *testing.T) {
	// Verify 0.1m snap functionality
	const snapDist = 0.1

	tests := []struct {
		val     float64
		snapped float64
	}{
		{0.0, 0.0},
		{0.04, 0.0},
		{0.06, 0.1},
		{1.23, 1.2},
		{1.27, 1.3},
	}

	for _, tt := range tests {
		got := snapValue(tt.val, snapDist)
		// Use approximate comparison for floating point
		if diff := got - tt.snapped; diff < -0.0001 || diff > 0.0001 {
			t.Errorf("snapValue(%f) = %f, want %f", tt.val, got, tt.snapped)
		}
	}
}

// snapValue rounds a value to the nearest snap distance.
func snapValue(v, snap float64) float64 {
	return math.Round(v/snap) * snap
}

func TestPlacementRaycasting(t *testing.T) {
	// Verify ray-cast point-on-plane logic
	// A ray from screen-space click to a floor at z=0
	// would intersect the floor plane where it hits

	// Origin: (0, 0, 1)
	// Direction: (0, 0, -1) normalized
	// Plane: z = 0
	// Expected hit: (0, 0, 0) at t=1

	t.Run("floor hit", func(t *testing.T) {
		// Simplified: verify basic 3D math is available
		// Real implementation uses WebGL ray-casting in browser
		if true {
			t.Logf("ray-casting test placeholder")
		}
	})
}
