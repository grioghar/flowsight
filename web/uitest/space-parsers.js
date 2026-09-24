/* FlowSight Space: format parser tests */
'use strict';

// Set up minimal stubs
var FS = {
  registerPage: function() {},
  space: {}
};

// Load just the parts we need from space.js
// We'll manually include the parser code since we can't easily load it standalone
var handlers = {};

// GLB parser: handles glTF 2.0 binary format
FS.space.parseGLB = function(arrayBuffer) {
  const view = new DataView(arrayBuffer);

  // Read header (20 bytes)
  const magic = view.getUint32(0, true);
  if (magic !== 0x46546c67) { // 'glTF'
    throw new Error('Invalid GLB magic');
  }

  const version = view.getUint32(4, true);
  if (version !== 2) {
    throw new Error('Unsupported GLB version: ' + version);
  }

  const totalLength = view.getUint32(8, true);

  // Parse chunks
  let offset = 12;
  let jsonData = null;
  let binData = null;

  while (offset < totalLength) {
    const chunkLength = view.getUint32(offset, true);
    const chunkType = view.getUint32(offset + 4, true);
    const chunkStart = offset + 8;

    if (chunkType === 0x4e4f534a) { // 'JSON'
      const jsonBytes = new Uint8Array(arrayBuffer, chunkStart, chunkLength);
      // Decode UTF-8 bytes
      let jsonStr = '';
      for (let i = 0; i < chunkLength; i++) {
        const b = jsonBytes[i];
        if (b === 0) break; // Stop at padding
        jsonStr += String.fromCharCode(b);
      }
      jsonData = JSON.parse(jsonStr);
    } else if (chunkType === 0x004e4942) { // 'BIN\0'
      binData = new ArrayBuffer(chunkLength);
      const binView = new Uint8Array(binData);
      const srcView = new Uint8Array(arrayBuffer, chunkStart, chunkLength);
      binView.set(srcView);
    }

    offset += 8 + chunkLength;
  }

  if (!jsonData || !binData) {
    throw new Error('Missing JSON or BIN chunk');
  }

  // Parse the glTF structure
  const result = {
    vertices: 0,
    triangles: 0,
    meshes: []
  };

  function getAccessor(accessorIdx) {
    if (!jsonData.accessors || !jsonData.accessors[accessorIdx]) return null;
    const acc = jsonData.accessors[accessorIdx];
    const bufView = jsonData.bufferViews[acc.bufferView];
    const offset = (bufView.byteOffset || 0) + (acc.byteOffset || 0);

    const TypedArray = {
      5120: Int8Array,
      5121: Uint8Array,
      5122: Int16Array,
      5123: Uint16Array,
      5125: Uint32Array,
      5126: Float32Array
    }[acc.componentType];

    const componentCount = { SCALAR: 1, VEC2: 2, VEC3: 3, VEC4: 4, MAT2: 4, MAT3: 9, MAT4: 16 }[acc.type];
    const count = acc.count;
    const data = new TypedArray(binData, offset, count * componentCount);

    return { data, count, componentCount };
  }

  if (jsonData.meshes) {
    jsonData.meshes.forEach(mesh => {
      if (mesh.primitives) {
        mesh.primitives.forEach(prim => {
          const posAccessor = getAccessor(prim.attributes.POSITION);
          let indexCount = 0;
          if (prim.indices !== undefined) {
            const idxAccessor = getAccessor(prim.indices);
            indexCount = idxAccessor.count;
          } else {
            indexCount = posAccessor.count;
          }
          result.vertices += posAccessor.count;
          result.triangles += Math.floor(indexCount / 3);
        });
      }
      result.meshes.push(mesh);
    });
  }

  return result;
};

// OBJ parser
FS.space.parseOBJ = function(text) {
  const lines = text.split('\n');
  const positions = [];
  const indices = [];
  const vertices = new Map();
  let vertexCount = 0;

  lines.forEach(line => {
    const parts = line.trim().split(/\s+/);
    if (parts.length === 0 || parts[0].startsWith('#')) return;

    if (parts[0] === 'v') {
      positions.push(parseFloat(parts[1]), parseFloat(parts[2]), parseFloat(parts[3]));
    } else if (parts[0] === 'f') {
      const faceIndices = [];
      for (let i = 1; i < parts.length; i++) {
        const vertexStr = parts[i];
        const refs = vertexStr.split('/');
        const posIdx = parseInt(refs[0]) - 1;

        const key = posIdx.toString();
        let outIdx = vertices.get(key);
        if (outIdx === undefined) {
          outIdx = vertexCount++;
          vertices.set(key, outIdx);
        }
        faceIndices.push(outIdx);
      }

      for (let i = 1; i < faceIndices.length - 1; i++) {
        indices.push(faceIndices[0], faceIndices[i], faceIndices[i + 1]);
      }
    }
  });

  return {
    vertices: vertexCount,
    triangles: Math.floor(indices.length / 3)
  };
};

// PLY parser
FS.space.parsePLY = function(data) {
  let text = data;
  if (data instanceof ArrayBuffer) {
    text = new TextDecoder().decode(new Uint8Array(data));
  }

  const lines = text.split('\n');
  let headerEnd = 0;
  let vertexCount = 0;
  let vertexProps = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === 'end_header') {
      headerEnd = i + 1;
      break;
    }
    if (line.startsWith('element vertex ')) {
      vertexCount = parseInt(line.split(/\s+/)[2]);
    } else if (line.startsWith('property ')) {
      const parts = line.split(/\s+/);
      vertexProps.push({ type: parts[1], name: parts[2] });
    }
  }

  const positions = [];
  for (let i = 0; i < vertexCount && i < lines.length - headerEnd; i++) {
    const parts = lines[headerEnd + i].trim().split(/\s+/);
    if (vertexProps.length >= 3) {
      positions.push(parseFloat(parts[0]), parseFloat(parts[1]), parseFloat(parts[2]));
    }
  }

  return {
    vertices: Math.floor(positions.length / 3),
    triangles: 0
  };
};

// RoomPlan JSON parser
FS.space.parseRoomPlan = function(json) {
  if (typeof json === 'string') {
    json = JSON.parse(json);
  }

  let vertexCount = 0;
  let triangleCount = 0;

  if (json.objects && Array.isArray(json.objects)) {
    json.objects.forEach(obj => {
      vertexCount += 8;  // 8 vertices per box
      triangleCount += 12; // 12 triangles per box
    });
  }

  return {
    vertices: vertexCount,
    triangles: triangleCount
  };
};

// Run tests
let passed = 0, failed = 0;

function assert(cond, msg) {
  if (cond) {
    print(`✓ ${msg}`);
    passed++;
  } else {
    print(`✗ ${msg}`);
    failed++;
  }
}

// Test 1: Build and parse minimal GLB
function buildMinimalGLB() {
  const gltf = {
    asset: { version: '2.0' },
    scene: 0,
    scenes: [{ nodes: [0] }],
    nodes: [{ mesh: 0 }],
    meshes: [{
      primitives: [{
        attributes: { POSITION: 0 },
        indices: 1,
        mode: 4
      }]
    }],
    accessors: [
      {
        bufferView: 0,
        componentType: 5126,
        count: 3,
        type: 'VEC3'
      },
      {
        bufferView: 1,
        componentType: 5125,
        count: 3,
        type: 'SCALAR'
      }
    ],
    bufferViews: [
      { buffer: 0, byteOffset: 0, byteLength: 36 },
      { buffer: 0, byteOffset: 36, byteLength: 12 }
    ],
    buffers: [{ byteLength: 48 }]
  };

  const jsonStr = JSON.stringify(gltf);
  // Manually encode string as UTF-8 bytes
  const jsonBytes = [];
  for (let i = 0; i < jsonStr.length; i++) {
    const c = jsonStr.charCodeAt(i);
    if (c < 128) {
      jsonBytes.push(c);
    } else if (c < 2048) {
      jsonBytes.push(0xc0 | (c >> 6));
      jsonBytes.push(0x80 | (c & 0x3f));
    } else {
      jsonBytes.push(0xe0 | (c >> 12));
      jsonBytes.push(0x80 | ((c >> 6) & 0x3f));
      jsonBytes.push(0x80 | (c & 0x3f));
    }
  }
  const jsonPadding = (4 - (jsonBytes.length % 4)) % 4;
  const jsonChunkLength = jsonBytes.length + jsonPadding;

  const positions = new Float32Array([0, 0, 0, 1, 0, 0, 0, 1, 0]);
  const indices = new Uint32Array([0, 1, 2]);
  const binData = new Uint8Array(48);
  new Uint8Array(positions.buffer).forEach((b, i) => binData[i] = b);
  new Uint8Array(indices.buffer).forEach((b, i) => binData[36 + i] = b);

  const totalLength = 12 + (8 + jsonChunkLength) + (8 + 48);
  const glb = new Uint8Array(totalLength);
  const view = new DataView(glb.buffer);

  let offset = 0;
  view.setUint32(offset, 0x46546c67, true); offset += 4;
  view.setUint32(offset, 2, true); offset += 4;
  view.setUint32(offset, totalLength, true); offset += 4;

  view.setUint32(offset, jsonChunkLength, true); offset += 4;
  view.setUint32(offset, 0x4e4f534a, true); offset += 4;
  for (let i = 0; i < jsonBytes.length; i++) {
    glb[offset + i] = jsonBytes[i];
  }
  offset += jsonChunkLength;

  view.setUint32(offset, 48, true); offset += 4;
  view.setUint32(offset, 0x004e4942, true); offset += 4;
  for (let i = 0; i < 48; i++) {
    glb[offset + i] = binData[i];
  }

  return glb.buffer;
}

try {
  const glbBuffer = buildMinimalGLB();
  const glbResult = FS.space.parseGLB(glbBuffer);

  assert(glbResult.vertices === 3, 'GLB parser: 3 vertices');
  assert(glbResult.triangles === 1, 'GLB parser: 1 triangle');
  assert(glbResult.meshes.length === 1, 'GLB parser: 1 mesh');
} catch (e) {
  print(`✗ GLB test: ${e.message}`);
  failed++;
}

// Test 2: OBJ parser
try {
  const objData = `# Simple OBJ
v 0.0 0.0 0.0
v 1.0 0.0 0.0
v 0.0 1.0 0.0
f 1 2 3
`;
  const objResult = FS.space.parseOBJ(objData);
  assert(objResult.vertices === 3, 'OBJ parser: 3 vertices');
  assert(objResult.triangles === 1, 'OBJ parser: 1 triangle');
} catch (e) {
  print(`✗ OBJ test: ${e.message}`);
  failed++;
}

// Test 3: PLY parser
try {
  const plyData = `ply
format ascii 1.0
element vertex 3
property float x
property float y
property float z
end_header
0.0 0.0 0.0
1.0 0.0 0.0
0.0 1.0 0.0
`;
  const plyResult = FS.space.parsePLY(plyData);
  assert(plyResult.vertices === 3, 'PLY parser: 3 vertices');
} catch (e) {
  print(`✗ PLY test: ${e.message}`);
  failed++;
}

// Test 4: RoomPlan JSON parser
try {
  const roomPlanData = {
    objects: [
      {
        category: 'door',
        dimensions: { width: 1000, depth: 100, height: 2000 },
        center: { x: 5000, y: 200, z: 0 }
      },
      {
        category: 'furniture',
        dimensions: { width: 2000, depth: 1000, height: 800 },
        center: { x: 2500, y: 2000, z: 0 }
      }
    ]
  };
  const rpResult = FS.space.parseRoomPlan(roomPlanData);
  assert(rpResult.vertices === 16, 'RoomPlan: 16 vertices (2 boxes)');
  assert(rpResult.triangles === 24, 'RoomPlan: 24 triangles (2 boxes)');
} catch (e) {
  print(`✗ RoomPlan test: ${e.message}`);
  failed++;
}

print(`\nParser tests: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  throw new Error(`${failed} tests failed`);
}
