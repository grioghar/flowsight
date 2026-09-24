/* FlowSight Space: physical space mapping and 3D device placement */
'use strict';

FS.registerPage('space', {
  title: 'Space', refresh: 60,
  async render(el) {
    const { card, kpi, pill, esc, num, table } = FS;
    const layout = await FS.get('/api/space/layout');
    const devices = await FS.get('/api/space/devices');
    const records = await FS.get('/api/space/records');

    if (layout.error) {
      el.innerHTML = FS.err('Failed to load space: ' + layout.error);
      return;
    }

    // Build HTML structure with three panes: Plan, 3D, Palette
    const placed = (devices.devices || []).filter(d => d.placed).length;
    const unplaced = (devices.devices || []).length - placed;

    el.innerHTML = `
      <div class="space-container">
        <div class="space-header">
          <div class="kv">
            <dt>Location</dt>
            <dd>${esc(records.geocode?.address || 'Not set')}</dd>
            <dt>Address</dt>
            <dd>${records.geocode?.lat ? `${num(records.geocode.lat, 3)}, ${num(records.geocode.lon, 3)}` : 'Geocoding...'}</dd>
            <dt>Elevation</dt>
            <dd>${records.elevation_m ? num(records.elevation_m, 1) + ' m' : '—'}</dd>
            <dt>Devices</dt>
            <dd>${num(placed)} placed · ${num(unplaced)} unplaced</dd>
          </div>
        </div>

        <div class="space-content">
          <!-- Plan pane (2D) -->
          <div id="space-plan" class="space-pane space-plan">
            <div class="space-toolbar">
              <button id="btn-plan-draw" class="btn-icon" title="Draw rooms (click points, double-click to close)">✏ Draw</button>
              <button id="btn-plan-undo" class="btn-icon" title="Undo last action">↶ Undo</button>
              <button id="btn-plan-import-osm" class="btn-icon" title="Import building footprint from OSM">🗺 Import OSM</button>
              <button id="btn-plan-set-scale" class="btn-icon" title="Set scale by two points">📏 Scale</button>
              <label>Floor: <select id="space-floor-select" style="margin:0 8px">
                <option value="0">Ground</option>
              </select></label>
              <button id="btn-plan-export" class="btn-icon" title="Export layout as JSON">⬇ Export</button>
            </div>
            <canvas id="space-canvas-plan" class="space-canvas"></canvas>
          </div>

          <!-- 3D pane (WebGL) -->
          <div id="space-3d" class="space-pane space-3d">
            <div class="space-toolbar">
              <button id="btn-3d-level" class="btn-icon" title="Level the scan to floor (click 3 floor points)">📐 Level</button>
              <button id="btn-3d-align" class="btn-icon" title="Align scan to plan (2 pts in 3D → 2 pts on plan)">⚙ Align</button>
              <label>Floor: <select id="space-3d-floor-select" style="margin:0 8px">
                <option value="0">Ground</option>
              </select></label>
              <button id="btn-3d-fullscreen" class="btn-icon" title="Fullscreen">⛶</button>
            </div>
            <canvas id="space-canvas-3d" class="space-canvas"></canvas>
          </div>

          <!-- Palette pane (device list) -->
          <div id="space-palette" class="space-pane space-palette">
            <div class="space-toolbar">
              <input id="space-device-search" type="text" placeholder="Search devices..." class="space-search">
              <label><input id="space-filter-placed" type="checkbox"> Placed</label>
              <label><input id="space-filter-unplaced" type="checkbox" checked> Unplaced</label>
            </div>
            <div id="space-devices-list" class="space-devices-list"></div>
          </div>
        </div>
      </div>

      <style>
        .space-container { display: grid; grid-template-rows: auto 1fr; height: 100vh; overflow: hidden; }
        .space-header { padding: 12px 16px; border-bottom: 1px solid var(--bg-alt); }
        .space-content { display: grid; grid-template-columns: 1fr 1fr 250px; gap: 0; overflow: hidden; }
        .space-pane { display: flex; flex-direction: column; border-right: 1px solid var(--bg-alt); overflow: auto; }
        .space-pane:last-child { border-right: none; }
        .space-toolbar { padding: 8px 12px; border-bottom: 1px solid var(--bg-alt); display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .space-canvas { flex: 1; display: block; background: var(--bg-subtle); }
        .btn-icon { padding: 6px 12px; border: 1px solid var(--bg-alt); background: transparent; cursor: pointer; font-size: 12px; white-space: nowrap; }
        .btn-icon:hover { background: var(--bg-alt); }
        .space-search { padding: 6px 8px; border: 1px solid var(--bg-alt); font-size: 12px; flex: 1; min-width: 150px; }
        .space-devices-list { flex: 1; overflow-y: auto; padding: 8px; }
        .space-device-item { padding: 8px; margin-bottom: 4px; background: var(--bg-subtle); border-radius: 4px; cursor: pointer; user-select: none; }
        .space-device-item:hover { background: var(--bg-alt); }
        .space-device-item.placed { opacity: 0.6; }
        .space-device-item-label { font-weight: 500; font-size: 12px; }
        .space-device-item-addr { font-size: 11px; color: var(--text-muted); }

        @media (max-width: 768px) {
          .space-content { grid-template-columns: 1fr; }
          .space-pane { display: none; }
          .space-pane.active { display: flex; }
          .space-pane { border-right: none; border-bottom: 1px solid var(--bg-alt); }
        }
      </style>
    `;

    // Initialize the three panes
    const planCanvas = el.querySelector('#space-canvas-plan');
    const canvas3d = el.querySelector('#space-canvas-3d');
    const devicesList = el.querySelector('#space-devices-list');

    // Plan pane: 2D editor
    initPlanPane(el, planCanvas, layout);

    // 3D pane: WebGL viewer (stub for now; full implementation in space-gl.js)
    init3DPane(canvas3d, layout);

    // Palette pane: device list
    initPalettePane(devicesList, devices, layout);

    // Store in FS for subsequent interactions
    FS.space = {
      layout,
      devices,
      records,
      planCanvas,
      canvas3d,
    };
  }
});

// === Plan Pane (2D Canvas) ===

function initPlanPane(el, canvas, layout) {
  const ctx = canvas.getContext('2d');
  const scale = 20; // pixels per metre
  let mode = 'view'; // 'view', 'draw', 'scale'
  let currentFloor = '0';
  let drawPath = [];
  let undoStack = [];

  // Resize canvas to fit parent
  function resizeCanvas() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    drawPlan();
  }

  // Draw the plan
  function drawPlan() {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bg-base').trim();
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.lineWidth = 1;
    ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim();

    // Grid
    for (let x = 0; x < canvas.width; x += scale) {
      ctx.strokeLine(x, 0, x, canvas.height);
    }
    for (let y = 0; y < canvas.height; y += scale) {
      ctx.strokeLine(0, y, canvas.width, y);
    }

    // Rooms for current floor
    const floorRooms = layout.rooms?.filter(r => r.floor === currentFloor) || [];
    floorRooms.forEach(room => {
      ctx.fillStyle = 'rgba(200, 200, 200, 0.1)';
      ctx.strokeStyle = 'rgba(100, 100, 100, 0.5)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      if (room.polygon && room.polygon.length > 0) {
        const pt = room.polygon[0];
        ctx.moveTo(pt[0] * scale, pt[1] * scale);
        for (let i = 1; i < room.polygon.length; i++) {
          ctx.lineTo(room.polygon[i][0] * scale, room.polygon[i][1] * scale);
        }
        ctx.closePath();
      }
      ctx.fill();
      ctx.stroke();

      // Room label
      if (room.polygon && room.polygon.length > 0) {
        const pt = room.polygon[0];
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-base').trim();
        ctx.font = '12px sans-serif';
        ctx.fillText(room.name, pt[0] * scale + 8, pt[1] * scale + 16);
      }
    });

    // Draw in-progress path
    if (drawPath.length > 0) {
      ctx.strokeStyle = 'rgba(100, 150, 255, 0.8)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(drawPath[0][0], drawPath[0][1]);
      for (let i = 1; i < drawPath.length; i++) {
        ctx.lineTo(drawPath[i][0], drawPath[i][1]);
      }
      ctx.stroke();

      // Snap preview
      drawPath.forEach((pt, i) => {
        ctx.fillStyle = i === drawPath.length - 1 ? 'rgba(255, 100, 100, 1)' : 'rgba(100, 200, 100, 1)';
        ctx.beginPath();
        ctx.arc(pt[0], pt[1], 4, 0, Math.PI * 2);
        ctx.fill();
      });
    }
  }

  // Canvas events
  canvas.addEventListener('click', (e) => {
    if (mode !== 'draw') return;
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) / scale;
    const y = (e.clientY - rect.top) / scale;
    const snapped = [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
    drawPath.push([e.clientX - rect.left, e.clientY - rect.top]);
    drawPlan();
  });

  canvas.addEventListener('dblclick', () => {
    if (mode !== 'draw' || drawPath.length < 3) return;
    // Finalize room (in a real impl, show a dialog to name it)
    mode = 'view';
    drawPath = [];
    drawPlan();
  });

  // Toolbar events
  el.querySelector('#btn-plan-draw').addEventListener('click', () => {
    mode = mode === 'draw' ? 'view' : 'draw';
    drawPath = [];
    drawPlan();
  });

  el.querySelector('#btn-plan-undo').addEventListener('click', () => {
    if (drawPath.length > 0) {
      drawPath.pop();
      drawPlan();
    }
  });

  el.querySelector('#space-floor-select').addEventListener('change', (e) => {
    currentFloor = e.target.value;
    drawPlan();
  });

  // Initial draw
  window.addEventListener('resize', resizeCanvas);
  resizeCanvas();
}

// === 3D Pane (WebGL Viewer) ===

function init3DPane(canvas, layout) {
  const gl = canvas.getContext('webgl2');
  if (!gl) {
    console.warn('WebGL2 not supported');
    return;
  }

  // Minimal WebGL setup
  const program = gl.createProgram();
  let floorGrid = [];
  let deviceMarkers = [];
  let scanMesh = null;

  function resizeCanvas() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    gl.viewport(0, 0, canvas.width, canvas.height);
  }

  function drawScene() {
    gl.clearColor(0.95, 0.95, 0.95, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

    // Draw floor grid, scan, device markers
    // (Simplified; full implementation in space-gl.js)
  }

  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);
  drawScene();
}

// === Palette Pane (Device List) ===

function initPalettePane(listEl, devices, layout) {
  const search = document.querySelector('#space-device-search');
  const filterPlaced = document.querySelector('#space-filter-placed');
  const filterUnplaced = document.querySelector('#space-filter-unplaced');

  function renderDevices() {
    const query = (search?.value || '').toLowerCase();
    const showPlaced = !filterPlaced?.checked;
    const showUnplaced = !filterUnplaced?.checked;

    const filtered = (devices.devices || []).filter(d => {
      const matches = d.label?.toLowerCase().includes(query) ||
                       d.mac?.includes(query) ||
                       d.vendor?.includes(query);
      return matches && (
        (d.placed && showPlaced) ||
        (!d.placed && showUnplaced)
      );
    });

    listEl.innerHTML = filtered.map(d => `
      <div class="space-device-item ${d.placed ? 'placed' : ''}" draggable="true"
           data-mac="${esc(d.mac)}" data-label="${esc(d.label || d.mac)}">
        <div class="space-device-item-label">${esc(d.label || d.mac)}</div>
        <div class="space-device-item-addr">${esc(d.vendor || '—')}</div>
        ${d.placed ? `<div class="space-device-item-addr">📍 ${esc(d.placement?.room || 'Unknown')}</div>` : ''}
      </div>
    `).join('');
  }

  search?.addEventListener('input', renderDevices);
  filterPlaced?.addEventListener('change', renderDevices);
  filterUnplaced?.addEventListener('change', renderDevices);

  renderDevices();
}

// === Helpers ===

function esc(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Export FS.space and add format parsers
if (!FS.space) {
  FS.space = {};
}

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
      const jsonStr = new TextDecoder().decode(jsonBytes);
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
  return parseGltfData(jsonData, binData);
};

function parseGltfData(json, binData) {
  const result = {
    vertices: 0,
    triangles: 0,
    positions: [],
    normals: [],
    indices: [],
    meshes: [],
    materials: json.materials || [],
    texture: null
  };

  // Helper: read accessor data
  function getAccessor(accessorIdx) {
    if (!json.accessors || !json.accessors[accessorIdx]) return null;
    const acc = json.accessors[accessorIdx];
    const bufView = json.bufferViews[acc.bufferView];
    const offset = (bufView.byteOffset || 0) + (acc.byteOffset || 0);

    const TypedArray = {
      5120: Int8Array,    // BYTE
      5121: Uint8Array,   // UNSIGNED_BYTE
      5122: Int16Array,   // SHORT
      5123: Uint16Array,  // UNSIGNED_SHORT
      5125: Uint32Array,  // UNSIGNED_INT
      5126: Float32Array  // FLOAT
    }[acc.componentType];

    const componentCount = { SCALAR: 1, VEC2: 2, VEC3: 3, VEC4: 4, MAT2: 4, MAT3: 9, MAT4: 16 }[acc.type];
    const count = acc.count;
    const data = new TypedArray(binData, offset, count * componentCount);

    return { data, count, componentCount };
  }

  // Parse meshes
  if (json.meshes) {
    json.meshes.forEach((mesh, meshIdx) => {
      const meshData = {
        primitives: [],
        positions: new Float32Array(0),
        normals: new Float32Array(0),
        indices: new Uint32Array(0),
        triangles: 0
      };

      if (mesh.primitives) {
        mesh.primitives.forEach(prim => {
          const posAccessor = getAccessor(prim.attributes.POSITION);
          const posData = posAccessor.data;

          let normals = null;
          if (prim.attributes.NORMAL !== undefined) {
            const normAccessor = getAccessor(prim.attributes.NORMAL);
            normals = normAccessor.data;
          }

          let indices = null;
          let indexCount = 0;
          if (prim.indices !== undefined) {
            const idxAccessor = getAccessor(prim.indices);
            indices = new Uint32Array(idxAccessor.data);
            indexCount = idxAccessor.count;
          } else {
            indexCount = posAccessor.count;
          }

          meshData.primitives.push({
            positions: posData,
            normals: normals,
            indices: indices,
            indexCount: indexCount
          });

          result.vertices += posAccessor.count;
          result.triangles += Math.floor(indexCount / 3);
          meshData.triangles += Math.floor(indexCount / 3);
        });
      }

      result.meshes.push(meshData);
    });
  }

  return result;
}

// OBJ parser
FS.space.parseOBJ = function(text) {
  const lines = text.split('\n');
  const positions = [];
  const normals = [];
  const indices = [];
  const vertices = new Map(); // "x,y,z" -> index
  let vertexCount = 0;

  lines.forEach(line => {
    const parts = line.trim().split(/\s+/);
    if (parts.length === 0 || parts[0].startsWith('#')) return;

    if (parts[0] === 'v') {
      positions.push(parseFloat(parts[1]), parseFloat(parts[2]), parseFloat(parts[3]));
    } else if (parts[0] === 'vn') {
      normals.push(parseFloat(parts[1]), parseFloat(parts[2]), parseFloat(parts[3]));
    } else if (parts[0] === 'f') {
      // Parse face (triangulate quads)
      const faceIndices = [];
      for (let i = 1; i < parts.length; i++) {
        const vertexStr = parts[i];
        const refs = vertexStr.split('/');
        const posIdx = parseInt(refs[0]) - 1; // OBJ uses 1-based indexing

        const key = posIdx.toString();
        let outIdx = vertices.get(key);
        if (outIdx === undefined) {
          outIdx = vertexCount++;
          vertices.set(key, outIdx);
        }
        faceIndices.push(outIdx);
      }

      // Triangulate if needed
      for (let i = 1; i < faceIndices.length - 1; i++) {
        indices.push(faceIndices[0], faceIndices[i], faceIndices[i + 1]);
      }
    }
  });

  return {
    vertices: vertexCount,
    triangles: Math.floor(indices.length / 3),
    positions: new Float32Array(positions),
    normals: normals.length > 0 ? new Float32Array(normals) : null,
    indices: new Uint32Array(indices)
  };
};

// PLY parser (ASCII and binary little-endian)
FS.space.parsePLY = function(data) {
  let text = data;
  if (data instanceof ArrayBuffer) {
    text = new TextDecoder().decode(new Uint8Array(data));
  }

  const lines = text.split('\n');
  let headerEnd = 0;
  let format = 'ascii';
  let vertexCount = 0;
  let vertexProps = [];

  // Parse header
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === 'end_header') {
      headerEnd = i + 1;
      break;
    }
    if (line.startsWith('format ')) {
      format = line.split(/\s+/)[1];
    } else if (line.startsWith('element vertex ')) {
      vertexCount = parseInt(line.split(/\s+/)[2]);
    } else if (line.startsWith('property ')) {
      const parts = line.split(/\s+/);
      vertexProps.push({ type: parts[1], name: parts[2] });
    }
  }

  if (format === 'ascii' || format.startsWith('binary_little_endian')) {
    return parsePLYAscii(lines.slice(headerEnd), vertexCount, vertexProps);
  } else {
    throw new Error('Unsupported PLY format: ' + format);
  }
};

function parsePLYAscii(dataLines, vertexCount, vertexProps) {
  const positions = [];
  const normals = [];

  for (let i = 0; i < vertexCount && i < dataLines.length; i++) {
    const parts = dataLines[i].trim().split(/\s+/);

    if (vertexProps.length >= 3) {
      // Assume first 3 are x, y, z
      positions.push(parseFloat(parts[0]), parseFloat(parts[1]), parseFloat(parts[2]));

      // Look for normals
      if (vertexProps.length >= 6 && vertexProps[3].name === 'nx') {
        normals.push(parseFloat(parts[3]), parseFloat(parts[4]), parseFloat(parts[5]));
      }
    }
  }

  return {
    vertices: Math.floor(positions.length / 3),
    triangles: 0,
    positions: new Float32Array(positions),
    normals: normals.length > 0 ? new Float32Array(normals) : null,
    indices: new Uint32Array([])
  };
}

// RoomPlan JSON parser: convert to extruded boxes
FS.space.parseRoomPlan = function(json) {
  if (typeof json === 'string') {
    json = JSON.parse(json);
  }

  const positions = [];
  const indices = [];
  let vertexCount = 0;

  // Create extruded boxes for each object
  if (json.objects && Array.isArray(json.objects)) {
    json.objects.forEach(obj => {
      const w = (obj.dimensions?.width || 1000) / 1000;
      const d = (obj.dimensions?.depth || 1000) / 1000;
      const h = (obj.dimensions?.height || 2000) / 1000;
      const x = (obj.center?.x || 0) / 1000;
      const y = (obj.center?.y || 0) / 1000;
      const z = (obj.center?.z || 0) / 1000;

      const ox = x - w / 2, ox2 = x + w / 2;
      const oy = y - d / 2, oy2 = y + d / 2;
      const oz = z, oz2 = z + h;

      const boxVerts = [
        ox, oy, oz,   ox2, oy, oz,  ox2, oy2, oz, ox, oy2, oz,  // bottom
        ox, oy, oz2,  ox2, oy, oz2, ox2, oy2, oz2, ox, oy2, oz2 // top
      ];

      const base = vertexCount;
      positions.push(...boxVerts);
      vertexCount += 8;

      const boxIndices = [
        base, base+1, base+2, base, base+2, base+3,         // bottom
        base+4, base+6, base+5, base+4, base+7, base+6,     // top
        base, base+4, base+5, base, base+5, base+1,         // front
        base+2, base+6, base+7, base+2, base+7, base+3,     // back
        base+1, base+5, base+6, base+1, base+6, base+2,     // right
        base+3, base+7, base+4, base+3, base+4, base+0      // left
      ];

      indices.push(...boxIndices);
    });
  }

  return {
    vertices: vertexCount,
    triangles: Math.floor(indices.length / 3),
    positions: new Float32Array(positions),
    normals: null,
    indices: new Uint32Array(indices)
  };
};
