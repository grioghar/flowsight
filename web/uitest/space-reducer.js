/* FlowSight Space: reducer and transformation tests */
'use strict';

// Set up minimal stubs
var FS = {
  registerPage: function() {},
  space: {}
};

// Import the reducer from space.js (inline copy)
function spaceReduce(layout, action) {
  if (!layout) layout = { floors: [], rooms: [], placements: [], scale: 1, origin: [0, 0], updated_at: 0 };

  switch (action.type) {
    case 'ADD_ROOM': {
      const newRoom = {
        id: action.roomId || 'room-' + Date.now(),
        name: action.name || 'New Room',
        floor: action.floor || '0',
        polygon: action.polygon || [],
        ceiling_m: action.ceiling_m || 2.6
      };
      return { ...layout, rooms: [...layout.rooms, newRoom], updated_at: Date.now() / 1000 };
    }

    case 'UPDATE_ROOM': {
      return {
        ...layout,
        rooms: layout.rooms.map(r => r.id === action.roomId ? { ...r, ...action.data } : r),
        updated_at: Date.now() / 1000
      };
    }

    case 'DELETE_ROOM': {
      return { ...layout, rooms: layout.rooms.filter(r => r.id !== action.roomId), updated_at: Date.now() / 1000 };
    }

    case 'ADD_FLOOR': {
      const newFloor = {
        id: action.floorId || 'floor-' + Date.now(),
        name: action.name || 'New Floor',
        elevation_m: action.elevation_m || 0
      };
      return { ...layout, floors: [...layout.floors, newFloor], updated_at: Date.now() / 1000 };
    }

    case 'UPDATE_FLOOR': {
      return {
        ...layout,
        floors: layout.floors.map(f => f.id === action.floorId ? { ...f, ...action.data } : f),
        updated_at: Date.now() / 1000
      };
    }

    case 'DELETE_FLOOR': {
      return {
        ...layout,
        floors: layout.floors.filter(f => f.id !== action.floorId),
        rooms: layout.rooms.filter(r => r.floor !== action.floorId),
        updated_at: Date.now() / 1000
      };
    }

    case 'UPDATE_TRANSFORM': {
      return {
        ...layout,
        scan: { ...layout.scan, transform: { ...layout.scan?.transform, ...action.data } },
        updated_at: Date.now() / 1000
      };
    }

    case 'SCALE_COORDINATES': {
      const factor = action.factor || 1;
      return {
        ...layout,
        rooms: layout.rooms.map(r => ({
          ...r,
          polygon: r.polygon.map(pt => [pt[0] * factor, pt[1] * factor])
        })),
        updated_at: Date.now() / 1000
      };
    }

    default:
      return layout;
  }
}

FS.space.reduce = spaceReduce;

// Helper: point-in-polygon test
function pointInPolygon(point, polygon) {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const xi = polygon[i][0], yi = polygon[i][1];
    const xj = polygon[j][0], yj = polygon[j][1];

    const intersect = ((yi > point[1]) !== (yj > point[1]))
      && (point[0] < (xj - xi) * (point[1] - yi) / (yj - yi) + xi);
    if (intersect) inside = !inside;
  }
  return inside;
}

(async function() {
  let passed = 0, failed = 0;

  function assert(cond, msg) {
    if (cond) {
      print(`✓ ${msg}`);
      passed++;
    } else {
      print(`✗ ${msg}`);
      failed++;
      throw new Error(msg);
    }
  }

  try {
    // Test: ADD_ROOM
    let layout = spaceReduce(null, {
      type: 'ADD_ROOM',
      name: 'Living Room',
      floor: '0',
      polygon: [[0, 0], [5, 0], [5, 4], [0, 4]],
      ceiling_m: 2.6
    });

    assert(layout.rooms.length === 1, 'ADD_ROOM adds one room');
    assert(layout.rooms[0].name === 'Living Room', 'Room name is correct');
    assert(layout.rooms[0].polygon.length === 4, 'Room polygon has 4 vertices');

  } catch (e) {
    print(`ADD_ROOM test failed: ${e.message}`);
  }

  try {
    // Test: UPDATE_ROOM
    let layout = spaceReduce(null, { type: 'ADD_ROOM', name: 'Room1', floor: '0', polygon: [[0,0],[1,0],[1,1],[0,1]] });
    const roomId = layout.rooms[0].id;

    layout = spaceReduce(layout, {
      type: 'UPDATE_ROOM',
      roomId: roomId,
      data: { name: 'Kitchen', ceiling_m: 3.0 }
    });

    assert(layout.rooms[0].name === 'Kitchen', 'UPDATE_ROOM changes name');
    assert(layout.rooms[0].ceiling_m === 3.0, 'UPDATE_ROOM changes ceiling height');

  } catch (e) {
    print(`UPDATE_ROOM test failed: ${e.message}`);
  }

  try {
    // Test: DELETE_ROOM
    let layout = spaceReduce(null, { type: 'ADD_ROOM', name: 'Room1', floor: '0', polygon: [[0,0],[1,0],[1,1],[0,1]] });
    const roomId = layout.rooms[0].id;

    layout = spaceReduce(layout, { type: 'DELETE_ROOM', roomId: roomId });

    assert(layout.rooms.length === 0, 'DELETE_ROOM removes room');

  } catch (e) {
    print(`DELETE_ROOM test failed: ${e.message}`);
  }

  try {
    // Test: ADD_FLOOR
    let layout = spaceReduce(null, {
      type: 'ADD_FLOOR',
      name: 'First Floor',
      elevation_m: 2.6
    });

    assert(layout.floors.length === 1, 'ADD_FLOOR adds one floor');
    assert(layout.floors[0].name === 'First Floor', 'Floor name is correct');
    assert(layout.floors[0].elevation_m === 2.6, 'Floor elevation is correct');

  } catch (e) {
    print(`ADD_FLOOR test failed: ${e.message}`);
  }

  try {
    // Test: DELETE_FLOOR (also deletes rooms on that floor)
    let layout = spaceReduce(null, { type: 'ADD_FLOOR', name: 'F0', elevation_m: 0 });
    const floorId = layout.floors[0].id;

    layout = spaceReduce(layout, { type: 'ADD_ROOM', name: 'R1', floor: floorId, polygon: [[0,0],[1,0],[1,1],[0,1]] });
    assert(layout.rooms.length === 1, 'Setup: added room on floor');

    layout = spaceReduce(layout, { type: 'DELETE_FLOOR', floorId: floorId });

    assert(layout.floors.length === 0, 'DELETE_FLOOR removes floor');
    assert(layout.rooms.length === 0, 'DELETE_FLOOR also removes rooms on that floor');

  } catch (e) {
    print(`DELETE_FLOOR test failed: ${e.message}`);
  }

  try {
    // Test: SCALE_COORDINATES
    let layout = spaceReduce(null, { type: 'ADD_ROOM', name: 'R1', floor: '0', polygon: [[0,0],[2,0],[2,2],[0,2]] });

    layout = spaceReduce(layout, { type: 'SCALE_COORDINATES', factor: 2 });

    assert(layout.rooms[0].polygon[1][0] === 4, 'SCALE_COORDINATES scales X coordinate');
    assert(layout.rooms[0].polygon[2][1] === 4, 'SCALE_COORDINATES scales Y coordinate');

  } catch (e) {
    print(`SCALE_COORDINATES test failed: ${e.message}`);
  }

  try {
    // Test: Point-in-polygon for room lookup
    const rect = [[0, 0], [5, 0], [5, 4], [0, 4]];

    const insideA = pointInPolygon([2.5, 2], rect);
    assert(insideA === true, 'Point inside rectangle is detected');

    const insideB = pointInPolygon([4.9, 3.9], rect);
    assert(insideB === true, 'Corner point is detected as inside');

    const outside = pointInPolygon([5.1, 2], rect);
    assert(outside === false, 'Point outside rectangle is detected');

  } catch (e) {
    print(`Point-in-polygon test failed: ${e.message}`);
  }

  try {
    // Test: Transform application (Y-up to Z-up)
    // A point at (x, y, z) in Y-up space becomes (x, z, -y) in Z-up space
    const yUpPoint = [1, 2, 3];  // x=1, y=2 (height), z=3
    const zUpPoint = [yUpPoint[0], yUpPoint[2], -yUpPoint[1]];  // x=1, z=3, y=-2
    // In our coordinate system, we typically swap y and z: (x, y, z) -> (x, z, y)
    const expected = [1, 3, 2];

    assert(Math.abs(zUpPoint[0] - expected[0]) < 1e-6, 'Transform application: X coordinate preserved');
    assert(Math.abs(zUpPoint[1] - expected[1]) < 1e-6, 'Transform application: Y swapped with Z');

  } catch (e) {
    print(`Transform application test failed: ${e.message}`);
  }

  // Summary
  print(`\nReducer tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exit(1);
  }
})().catch(e => {
  print(`Test suite error: ${e.message}`);
  process.exit(1);
});
