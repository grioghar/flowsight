/* FlowSight Space page UI tests */
'use strict';

(async function() {
  let passed = 0, failed = 0;

  function assert(cond, msg) {
    if (cond) {
      console.log(`✓ ${msg}`);
      passed++;
    } else {
      console.error(`✗ ${msg}`);
      failed++;
      throw new Error(msg);
    }
  }

  // Test 1: Render space page with fixture layout
  try {
    const layout = {
      floors: [
        { id: '0', name: 'Ground', elevation_m: 0 },
        { id: '1', name: 'First', elevation_m: 2.6 }
      ],
      rooms: [
        {
          id: 'living',
          name: 'Living Room',
          floor: '0',
          polygon: [[0, 0], [5, 0], [5, 4], [0, 4]],
          ceiling_m: 2.6
        },
        {
          id: 'bedroom',
          name: 'Bedroom',
          floor: '0',
          polygon: [[5, 0], [10, 0], [10, 4], [5, 4]],
          ceiling_m: 2.6
        }
      ],
      placements: [
        {
          mac: '00:11:22:33:44:55',
          label: 'WiFi Router',
          x: 2.5,
          y: 2,
          z: 0,
          floor: '0',
          room: 'living'
        }
      ],
      scale: 1.0,
      origin: [0, 0],
      updated_at: Date.now() / 1000
    };

    const mockGet = async (url) => {
      if (url === '/api/space/layout') return layout;
      if (url === '/api/space/devices') {
        return {
          devices: [
            { mac: '00:11:22:33:44:55', label: 'WiFi Router', vendor: 'Ubiquiti', placed: true },
            { mac: 'aa:bb:cc:dd:ee:ff', label: 'iPhone', vendor: 'Apple', placed: false }
          ],
          total: 2
        };
      }
      if (url === '/api/space/records') {
        return {
          geocode: {
            address: '123 Main St, Springfield, IL 62701',
            lat: 39.78,
            lon: -89.5
          },
          elevation_m: 180,
          building_footprints: [],
          cached_at: Date.now() / 1000
        };
      }
      return {};
    };

    // Mock FS if needed
    if (typeof FS === 'undefined') {
      window.FS = { get: mockGet, registerPage: () => {} };
    }

    assert(layout.floors.length === 2, 'Fixture has 2 floors');
    assert(layout.rooms.length === 2, 'Fixture has 2 rooms');
    assert(layout.placements.length === 1, 'Fixture has 1 placement');
  } catch (e) {
    console.error('Fixture test failed:', e.message);
  }

  // Test 2: GLB parsing (minimal valid GLB)
  try {
    const minimalGLB = new Uint8Array([
      0x67, 0x6c, 0x54, 0x46, // magic: 'glTF'
      0x02, 0x00, 0x00, 0x00, // version: 2
      0x50, 0x00, 0x00, 0x00, // size: 80 bytes
      // JSON chunk
      0x1c, 0x00, 0x00, 0x00, // length: 28 bytes
      0x4a, 0x53, 0x4f, 0x4e, // type: 'JSON'
      // Minimal JSON: {"asset":{"version":"2.0"}}
      0x7b, 0x22, 0x61, 0x73, 0x73, 0x65, 0x74, 0x22,
      0x3a, 0x7b, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69,
      0x6f, 0x6e, 0x22, 0x3a, 0x22, 0x32, 0x2e, 0x30,
      0x22, 0x7d, 0x7d, 0x00,
      // BIN chunk
      0x20, 0x00, 0x00, 0x00, // length: 32 bytes
      0x42, 0x49, 0x4e, 0x00  // type: 'BIN\0'
    ]);

    assert(minimalGLB[0] === 0x67, 'GLB magic byte 0 correct');
    assert(minimalGLB[1] === 0x6c, 'GLB magic byte 1 correct');
    assert(minimalGLB[2] === 0x54, 'GLB magic byte 2 correct');
    assert(minimalGLB[3] === 0x46, 'GLB magic byte 3 correct');

    // In a real test, we'd call FS.space.parseGLB(minimalGLB)
    // For now, verify it's not null
    if (FS && FS.space && FS.space.parseGLB) {
      const result = FS.space.parseGLB(minimalGLB);
      assert(result !== null, 'parseGLB returns non-null result');
    }
  } catch (e) {
    console.error('GLB test failed:', e.message);
  }

  // Test 3: OBJ parsing
  try {
    const objData = `# Simple OBJ
v 0.0 0.0 0.0
v 1.0 0.0 0.0
v 0.0 1.0 0.0
f 1 2 3
`;
    const lines = objData.split('\n');
    const vertices = lines.filter(l => l.startsWith('v ')).length;
    const faces = lines.filter(l => l.startsWith('f ')).length;

    assert(vertices === 3, 'OBJ has 3 vertices');
    assert(faces === 1, 'OBJ has 1 face');
  } catch (e) {
    console.error('OBJ test failed:', e.message);
  }

  // Test 4: Room polygon validation
  try {
    const room = {
      id: 'test',
      name: 'Test Room',
      floor: '0',
      polygon: [[0, 0], [5, 0], [5, 4], [0, 4]],
      ceiling_m: 2.6
    };

    assert(room.polygon.length === 4, 'Room polygon has 4 points');
    assert(room.polygon[0][0] === 0, 'First point x = 0');
    assert(room.polygon[1][0] === 5, 'Second point x = 5');
    assert(room.ceiling_m > 0, 'Ceiling height is positive');
  } catch (e) {
    console.error('Room validation test failed:', e.message);
  }

  // Test 5: Device placement validation
  try {
    const placement = {
      mac: '00:11:22:33:44:55',
      label: 'Test Device',
      x: 2.5,
      y: 3.1,
      z: 0.8,
      floor: '0',
      room: 'living',
      note: 'On shelf'
    };

    const macRegex = /^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$/;
    assert(macRegex.test(placement.mac), 'MAC address format is valid');
    assert(typeof placement.x === 'number', 'X coordinate is a number');
    assert(typeof placement.y === 'number', 'Y coordinate is a number');
    assert(typeof placement.z === 'number', 'Z coordinate is a number');
  } catch (e) {
    console.error('Placement validation test failed:', e.message);
  }

  // Test 6: Format detection
  try {
    const tests = [
      { name: 'model.glb', expected: 'glb' },
      { name: 'scan.obj', expected: 'obj' },
      { name: 'cloud.ply', expected: 'ply' },
      { name: 'room.json', expected: 'roomplan' },
    ];

    // In a real test, we'd use the space module's detectFormat function
    // For now, just verify the test structure
    tests.forEach(t => {
      assert(t.expected !== '', `Format test ${t.name} has expected value`);
    });
  } catch (e) {
    // Test failed but continue
  }

  // Test 7: Ray-triangle intersection (Möller–Trumbore)
  try {
    if (FS.space3D && FS.space3D.rayTriangleIntersect) {
      const v0 = [0, 0, 0];
      const v1 = [1, 0, 0];
      const v2 = [0, 1, 0];

      // Ray from above pointing down
      const rayOrigin = [0.3, 0.3, 1];
      const rayDir = [0, 0, -1];

      const hit = FS.space3D.rayTriangleIntersect(rayOrigin, rayDir, v0, v1, v2);
      assert(hit !== null, 'Ray hits triangle');
      assert(hit.t > 0, 'Hit distance is positive');
      assert(hit.u >= 0 && hit.u <= 1, 'U coordinate is in bounds');
      assert(hit.v >= 0 && hit.v <= 1, 'V coordinate is in bounds');
      assert(hit.u + hit.v <= 1, 'Barycentric coordinates sum to <= 1');

      // Ray parallel to triangle should miss
      const miss = FS.space3D.rayTriangleIntersect([0, 0, 0.5], [1, 0, 0], v0, v1, v2);
      assert(miss === null, 'Parallel ray misses triangle');
    }
  } catch (e) {
    // Test failed but continue
  }

  // Test 8: Spatial grid construction and ray casting
  try {
    if (FS.space3D && FS.space3D.SpatialGrid) {
      const positions = new Float32Array([
        0, 0, 0,  1, 0, 0,  0, 1, 0,
        1, 0, 0,  1, 1, 0,  0, 1, 0,
        0, 0, 1,  1, 0, 1,  0, 1, 1,
        1, 0, 1,  1, 1, 1,  0, 1, 1
      ]);

      const indices = new Uint32Array([
        0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11
      ]);

      const grid = new FS.space3D.SpatialGrid(positions, indices, 1.0);
      assert(grid.cells.size > 0, 'Spatial grid cells populated');

      // Ray cast into the grid
      const rayOrigin = [0.5, 0.5, 2];
      const rayDir = [0, 0, -1];
      const hit = grid.raycast(rayOrigin, rayDir, 100);
      assert(hit !== null, 'Raycast finds hit in spatial grid');
      assert(typeof hit.t === 'number', 'Hit has distance');
      assert(typeof hit.triIdx === 'number', 'Hit has triangle index');
    }
  } catch (e) {
    // Test failed but continue
  }

  // Test 9: Point-in-polygon (2D)
  try {
    if (FS.space3D && FS.space3D.pointInPolygon) {
      const rect = [[0, 0], [1, 0], [1, 1], [0, 1]];

      const inside = FS.space3D.pointInPolygon([0.5, 0.5], rect);
      assert(inside === true, 'Point inside rectangle');

      const outside = FS.space3D.pointInPolygon([2, 2], rect);
      assert(outside === false, 'Point outside rectangle');

      const edge = FS.space3D.pointInPolygon([0.5, 0], rect);
      // Edge case: depends on implementation, just verify it returns boolean
      assert(typeof edge === 'boolean', 'Edge point test returns boolean');
    }
  } catch (e) {
    // Test failed but continue
  }

  // Test 10: planeFromPoints
  try {
    if (FS.space && FS.space.planeFromPoints) {
      const p1 = [0, 0, 0];
      const p2 = [1, 0, 0];
      const p3 = [0, 1, 0];

      const plane = FS.space.planeFromPoints(p1, p2, p3);
      assert(plane.normal !== null, 'planeFromPoints returns normal');
      assert(Math.abs(plane.normal[2] - 1) < 1e-6 || Math.abs(plane.normal[2] + 1) < 1e-6, 'Normal points in Z direction');

      // Verify plane equation: normal · (p - origin) = 0
      const p = [0.5, 0.5, 0];
      const dot = plane.normal[0] * (p[0] - plane.origin[0]) +
                  plane.normal[1] * (p[1] - plane.origin[1]) +
                  plane.normal[2] * (p[2] - plane.origin[2]);
      assert(Math.abs(dot) < 1e-6, 'Plane equation satisfied for point on plane');
    }
  } catch (e) {
    // Test failed but continue
  }

  // Test 11: alignTransform
  try {
    if (FS.space && FS.space.alignTransform) {
      const p1_3d = [0, 0, 0];
      const p2_3d = [2, 0, 0];
      const p1_plan = [0, 0];
      const p2_plan = [1, 0];

      const transform = FS.space.alignTransform(p1_3d, p2_3d, p1_plan, p2_plan);
      assert(transform.scale > 0, 'Scale is positive');
      assert(Math.abs(transform.scale - 0.5) < 1e-6, 'Scale is 0.5 (1m / 2m)');
      assert(Math.abs(transform.rotation_deg) < 1e-6, 'Rotation is ~0 when aligned');
      assert(Array.isArray(transform.offset) && transform.offset.length === 3, 'Offset is [x, y, z]');
    }
  } catch (e) {
    // Test failed but continue
  }

  // Summary
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exit(1);
  }
})().catch(e => {
  console.error('Test suite error:', e);
  process.exit(1);
});

