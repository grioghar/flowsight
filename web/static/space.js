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

// Export FS.space for further use
if (!FS.space) {
  FS.space = {
    parseGLB(data) {
      // Placeholder: parse GLB format
      // Returns { vertices, triangles, mesh }
      return { vertices: 0, triangles: 0 };
    }
  };
}
