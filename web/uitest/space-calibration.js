/* FlowSight Space: calibration (planeFromPoints, alignTransform) tests */
'use strict';

// Set up minimal stubs
var FS = {
  registerPage: function() {},
  space: {}
};

// planeFromPoints: fit a plane through three points
FS.space.planeFromPoints = function(p1, p2, p3) {
  // Vectors in the plane
  const v1 = [p2[0] - p1[0], p2[1] - p1[1], p2[2] - p1[2]];
  const v2 = [p3[0] - p1[0], p3[1] - p1[1], p3[2] - p1[2]];

  // Normal = v1 × v2
  const normal = [
    v1[1] * v2[2] - v1[2] * v2[1],
    v1[2] * v2[0] - v1[0] * v2[2],
    v1[0] * v2[1] - v1[1] * v2[0]
  ];

  // Normalize
  const len = Math.sqrt(normal[0] * normal[0] + normal[1] * normal[1] + normal[2] * normal[2]);
  if (len > 0) {
    normal[0] /= len;
    normal[1] /= len;
    normal[2] /= len;
  }

  return { normal, origin: p1 };
};

// alignTransform: compute scale and rotation from two point pairs
FS.space.alignTransform = function(p1_3d, p2_3d, p1_plan, p2_plan) {
  // Distance in 3D
  const d3d = Math.sqrt(
    (p2_3d[0] - p1_3d[0]) ** 2 +
    (p2_3d[1] - p1_3d[1]) ** 2 +
    (p2_3d[2] - p1_3d[2]) ** 2
  );

  // Distance on plan (2D)
  const dplan = Math.sqrt(
    (p2_plan[0] - p1_plan[0]) ** 2 +
    (p2_plan[1] - p1_plan[1]) ** 2
  );

  const scale = dplan > 0.001 ? dplan / d3d : 1;

  // Direction vectors
  const dir3d = [
    (p2_3d[0] - p1_3d[0]) / d3d,
    (p2_3d[1] - p1_3d[1]) / d3d
  ];

  const dirplan = [
    (p2_plan[0] - p1_plan[0]) / dplan,
    (p2_plan[1] - p1_plan[1]) / dplan
  ];

  // Rotation angle
  const angle3d = Math.atan2(dir3d[1], dir3d[0]);
  const angleplan = Math.atan2(dirplan[1], dirplan[0]);
  const rotation = angleplan - angle3d;
  const rotation_deg = rotation * 180 / Math.PI;

  // Offset: plan point minus transformed 3D point
  const cos_r = Math.cos(rotation);
  const sin_r = Math.sin(rotation);
  const p1_transformed = [
    (p1_3d[0] * cos_r - p1_3d[1] * sin_r) * scale,
    (p1_3d[0] * sin_r + p1_3d[1] * cos_r) * scale,
    p1_3d[2]
  ];

  const offset = [
    p1_plan[0] - p1_transformed[0],
    p1_plan[1] - p1_transformed[1],
    0
  ];

  return { scale, rotation_deg, offset };
};

(async function() {
  let passed = 0, failed = 0;

  function assert(cond, msg) {
    if (cond) {
      print(`✓ ${msg}`); // Use print for JSC compatibility
      passed++;
    } else {
      print(`✗ ${msg}`);
      failed++;
      throw new Error(msg);
    }
  }

  try {
    // Test planeFromPoints
    const p1 = [0, 0, 0];
    const p2 = [1, 0, 0];
    const p3 = [0, 1, 0];

    const plane = FS.space.planeFromPoints(p1, p2, p3);

    assert(plane !== null && plane.normal !== null, 'planeFromPoints returns result with normal');
    assert(plane.origin !== null, 'planeFromPoints returns origin');

    // Normal should point in Z direction (either +Z or -Z)
    const normalZ = Math.abs(plane.normal[2]);
    assert(normalZ > 0.99, `Normal Z component is close to ±1 (got ${plane.normal[2].toFixed(3)})`);

    // Verify all three points satisfy plane equation
    const checkPoint = (p, label) => {
      const dot = plane.normal[0] * (p[0] - plane.origin[0]) +
                  plane.normal[1] * (p[1] - plane.origin[1]) +
                  plane.normal[2] * (p[2] - plane.origin[2]);
      assert(Math.abs(dot) < 1e-6, `${label} satisfies plane equation`);
    };

    checkPoint(p1, 'p1');
    checkPoint(p2, 'p2');
    checkPoint(p3, 'p3');

  } catch (e) {
    console.error('planeFromPoints test failed:', e.message);
  }

  try {
    // Test alignTransform: simple case, no rotation
    const p1_3d = [0, 0, 0];
    const p2_3d = [2, 0, 0];
    const p1_plan = [0, 0];
    const p2_plan = [1, 0];

    const result = FS.space.alignTransform(p1_3d, p2_3d, p1_plan, p2_plan);

    assert(result.scale > 0, 'Scale is positive');
    assert(Math.abs(result.scale - 0.5) < 1e-6, `Scale is 0.5 (got ${result.scale.toFixed(6)})`);
    assert(Math.abs(result.rotation_deg) < 1e-6 || Math.abs(result.rotation_deg - 360) < 1e-6,
           `Rotation is ~0 degrees (got ${result.rotation_deg.toFixed(3)})`);
    assert(result.offset !== null && result.offset.length === 3, 'Offset is [x, y, z]');
    assert(Math.abs(result.offset[0]) < 1e-6, `Offset X is 0 (got ${result.offset[0].toFixed(6)})`);
    assert(Math.abs(result.offset[1]) < 1e-6, `Offset Y is 0 (got ${result.offset[1].toFixed(6)})`);

  } catch (e) {
    console.error('alignTransform test failed:', e.message);
  }

  try {
    // Test alignTransform: with 90 degree rotation
    const p1_3d = [0, 0, 0];
    const p2_3d = [0, 2, 0];  // Points in Y direction in 3D
    const p1_plan = [0, 0];
    const p2_plan = [1, 0];   // Points in X direction on plan

    const result = FS.space.alignTransform(p1_3d, p2_3d, p1_plan, p2_plan);

    assert(result.scale > 0, 'Scale is positive');
    assert(Math.abs(result.scale - 0.5) < 1e-6, 'Scale is 0.5');
    // Rotation should be ~-90 degrees (Y to X is -90 or 270)
    const rot = Math.abs(result.rotation_deg);
    assert(rot < 1e-4 || Math.abs(rot - 90) < 1e-4 || Math.abs(rot - 270) < 1e-4,
           `Rotation is ±90 degrees (got ${result.rotation_deg.toFixed(3)})`);

  } catch (e) {
    console.error('alignTransform rotation test failed:', e.message);
  }

  // Summary
  print(`\nCalibration tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exit(1);
  }
})().catch(e => {
  print(`Test suite error: ${e.message}`);
  process.exit(1);
});
