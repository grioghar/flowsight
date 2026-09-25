/* FlowSight Space: WebGL 3D viewer for space and devices */
'use strict';

// WebGL2 3D viewer for the Space module
// Features: orbit camera, floor grid, translucent rooms, device markers, scan mesh, ray-casting for placement

FS.space3D = (function() {
  'use strict';

  // === Shaders ===

  const meshVertexShader = `#version 300 es
  precision highp float;

  in vec3 position;
  in vec3 normal;
  in vec4 color;

  uniform mat4 projection;
  uniform mat4 view;
  uniform mat4 model;

  out vec3 vNormal;
  out vec4 vColor;
  out vec3 vPos;
  out vec3 vWorldPos;

  void main() {
    vWorldPos = (model * vec4(position, 1.0)).xyz;
    vNormal = normalize((model * vec4(normal, 0.0)).xyz);
    vColor = color;
    vPos = vWorldPos;
    gl_Position = projection * view * vec4(vWorldPos, 1.0);
  }
  `;

  const meshFragmentShader = `#version 300 es
  precision highp float;

  in vec3 vNormal;
  in vec4 vColor;
  in vec3 vPos;
  in vec3 vWorldPos;

  out vec4 outColor;

  void main() {
    vec3 lightDir = normalize(vec3(1.0, 1.0, 2.0));
    float diffuse = max(dot(vNormal, lightDir), 0.0);
    float ambient = 0.4;
    vec3 col = vColor.rgb * (ambient + diffuse * 0.6);
    outColor = vec4(col, vColor.a);
  }
  `;

  // Grid/axis shader
  const lineVertexShader = `#version 300 es
  precision highp float;

  in vec3 position;
  in vec4 color;

  uniform mat4 projection;
  uniform mat4 view;
  uniform mat4 model;

  out vec4 vColor;

  void main() {
    vColor = color;
    gl_Position = projection * view * model * vec4(position, 1.0);
  }
  `;

  const lineFragmentShader = `#version 300 es
  precision highp float;

  in vec4 vColor;
  out vec4 outColor;

  void main() {
    outColor = vColor;
  }
  `;

  // === Math utilities ===

  function vec3(x, y, z) {
    return [x, y, z];
  }

  function vec3add(a, b) {
    return [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
  }

  function vec3sub(a, b) {
    return [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
  }

  function vec3scale(v, s) {
    return [v[0] * s, v[1] * s, v[2] * s];
  }

  function vec3dot(a, b) {
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
  }

  function vec3cross(a, b) {
    return [
      a[1] * b[2] - a[2] * b[1],
      a[2] * b[0] - a[0] * b[2],
      a[0] * b[1] - a[1] * b[0]
    ];
  }

  function vec3len(v) {
    return Math.sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
  }

  function vec3normalize(v) {
    const len = vec3len(v);
    return len > 0 ? vec3scale(v, 1 / len) : [0, 0, 1];
  }

  // === Ray-Triangle Intersection (Möller–Trumbore) ===

  function rayTriangleIntersect(rayOrigin, rayDir, v0, v1, v2) {
    const EPSILON = 1e-8;

    const edge1 = vec3sub(v1, v0);
    const edge2 = vec3sub(v2, v0);
    const h = vec3cross(rayDir, edge2);
    const a = vec3dot(edge1, h);

    if (Math.abs(a) < EPSILON) return null;

    const f = 1.0 / a;
    const s = vec3sub(rayOrigin, v0);
    const u = f * vec3dot(s, h);

    if (u < 0.0 || u > 1.0) return null;

    const q = vec3cross(s, edge1);
    const v = f * vec3dot(rayDir, q);

    if (v < 0.0 || u + v > 1.0) return null;

    const t = f * vec3dot(edge2, q);

    if (t > EPSILON) {
      return { t, u, v };
    }
    return null;
  }

  // === Spatial Index (uniform grid) ===

  class SpatialGrid {
    constructor(positions, indices, cellSize = 1.0) {
      this.cellSize = cellSize;
      this.cells = new Map();
      this.positions = positions;
      this.indices = indices;

      for (let i = 0; i < indices.length; i += 3) {
        const i0 = indices[i] * 3;
        const i1 = indices[i + 1] * 3;
        const i2 = indices[i + 2] * 3;

        const v0 = [positions[i0], positions[i0 + 1], positions[i0 + 2]];
        const v1 = [positions[i1], positions[i1 + 1], positions[i1 + 2]];
        const v2 = [positions[i2], positions[i2 + 1], positions[i2 + 2]];

        const minX = Math.floor(Math.min(v0[0], v1[0], v2[0]) / cellSize);
        const maxX = Math.ceil(Math.max(v0[0], v1[0], v2[0]) / cellSize);
        const minY = Math.floor(Math.min(v0[1], v1[1], v2[1]) / cellSize);
        const maxY = Math.ceil(Math.max(v0[1], v1[1], v2[1]) / cellSize);
        const minZ = Math.floor(Math.min(v0[2], v1[2], v2[2]) / cellSize);
        const maxZ = Math.ceil(Math.max(v0[2], v1[2], v2[2]) / cellSize);

        for (let x = minX; x <= maxX; x++) {
          for (let y = minY; y <= maxY; y++) {
            for (let z = minZ; z <= maxZ; z++) {
              const key = `${x},${y},${z}`;
              if (!this.cells.has(key)) {
                this.cells.set(key, []);
              }
              this.cells.get(key).push(i / 3);
            }
          }
        }
      }
    }

    raycast(rayOrigin, rayDir, maxDist = Infinity) {
      const visited = new Set();
      let hit = null;

      for (let t = 0; t < maxDist; t += this.cellSize * 0.5) {
        const p = [
          rayOrigin[0] + rayDir[0] * t,
          rayOrigin[1] + rayDir[1] * t,
          rayOrigin[2] + rayDir[2] * t
        ];

        const x = Math.floor(p[0] / this.cellSize);
        const y = Math.floor(p[1] / this.cellSize);
        const z = Math.floor(p[2] / this.cellSize);
        const key = `${x},${y},${z}`;

        const triangles = this.cells.get(key) || [];
        for (const triIdx of triangles) {
          if (visited.has(triIdx)) continue;
          visited.add(triIdx);

          const i = triIdx * 3;
          const i0 = this.indices[i] * 3;
          const i1 = this.indices[i + 1] * 3;
          const i2 = this.indices[i + 2] * 3;

          const v0 = [this.positions[i0], this.positions[i0 + 1], this.positions[i0 + 2]];
          const v1 = [this.positions[i1], this.positions[i1 + 1], this.positions[i1 + 2]];
          const v2 = [this.positions[i2], this.positions[i2 + 1], this.positions[i2 + 2]];

          const result = rayTriangleIntersect(rayOrigin, rayDir, v0, v1, v2);
          if (result && result.t < maxDist) {
            if (!hit || result.t < hit.t) {
              hit = { ...result, triIdx, v0, v1, v2 };
              maxDist = result.t * 1.1;
            }
          }
        }
      }

      return hit;
    }
  }

  // === Viewer Class ===

  class Viewer {
    constructor(canvas) {
      this.canvas = canvas;
      this.gl = canvas.getContext('webgl2');
      if (!this.gl) {
        throw new Error('WebGL2 not supported');
      }

      const gl = this.gl;
      gl.enable(gl.DEPTH_TEST);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.clearColor(0.95, 0.95, 0.95, 1.0);

      this.meshProgram = this.createProgram(meshVertexShader, meshFragmentShader);
      this.lineProgram = this.createProgram(lineVertexShader, lineFragmentShader);

      this.camera = {
        eye: [10, 10, 10],
        center: [0, 0, 0],
        up: [0, 0, 1]
      };

      this.meshes = [];
      this.grid = null;
      this.axes = null;
      this.spatialIndex = null;

      this.mouseDown = false;
      this.touchCount = 0;
      this.lastMouse = [0, 0];
      this.lastTouchDist = 0;
      this.setupInput();

      this.layout = null;

      this.resize();
      window.addEventListener('resize', () => this.resize());

      this.running = true;
      this.animate();
    }

    createProgram(vSource, fSource) {
      const gl = this.gl;
      const vs = gl.createShader(gl.VERTEX_SHADER);
      gl.shaderSource(vs, vSource);
      gl.compileShader(vs);
      if (!gl.getShaderParameter(vs, gl.COMPILE_STATUS)) {
        console.error('Vertex shader error:', gl.getShaderInfoLog(vs));
      }

      const fs = gl.createShader(gl.FRAGMENT_SHADER);
      gl.shaderSource(fs, fSource);
      gl.compileShader(fs);
      if (!gl.getShaderParameter(fs, gl.COMPILE_STATUS)) {
        console.error('Fragment shader error:', gl.getShaderInfoLog(fs));
      }

      const prog = gl.createProgram();
      gl.attachShader(prog, vs);
      gl.attachShader(prog, fs);
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
        console.error('Program link error:', gl.getProgramParameter(prog));
      }
      return prog;
    }

    setupInput() {
      this.canvas.addEventListener('mousedown', (e) => {
        this.mouseDown = true;
        this.lastMouse = [e.clientX, e.clientY];
      });

      this.canvas.addEventListener('mousemove', (e) => {
        if (!this.mouseDown) return;
        const dx = e.clientX - this.lastMouse[0];
        const dy = e.clientY - this.lastMouse[1];

        if (e.buttons === 1) {
          this.orbit(dx, dy);
        } else if (e.buttons === 2 || e.shiftKey) {
          this.pan(dx, dy);
        }

        this.lastMouse = [e.clientX, e.clientY];
      });

      this.canvas.addEventListener('mouseup', () => {
        this.mouseDown = false;
      });

      this.canvas.addEventListener('contextmenu', (e) => e.preventDefault());

      this.canvas.addEventListener('wheel', (e) => {
        e.preventDefault();
        const factor = 1 + e.deltaY * 0.001;
        const eye = this.camera.eye;
        const center = this.camera.center;
        const dir = vec3sub(eye, center);
        const dist = vec3len(dir);
        const newDist = Math.max(0.1, Math.min(100, dist * factor));
        const normalized = vec3normalize(dir);
        this.camera.eye = vec3add(center, vec3scale(normalized, newDist));
      });

      this.canvas.addEventListener('touchstart', (e) => {
        this.touchCount = e.touches.length;
        if (e.touches.length === 1) {
          this.lastMouse = [e.touches[0].clientX, e.touches[0].clientY];
        } else if (e.touches.length === 2) {
          const dx = e.touches[0].clientX - e.touches[1].clientX;
          const dy = e.touches[0].clientY - e.touches[1].clientY;
          this.lastTouchDist = Math.sqrt(dx * dx + dy * dy);
        }
      });

      this.canvas.addEventListener('touchmove', (e) => {
        if (e.touches.length === 1) {
          const dx = e.touches[0].clientX - this.lastMouse[0];
          const dy = e.touches[0].clientY - this.lastMouse[1];
          this.orbit(dx, dy);
          this.lastMouse = [e.touches[0].clientX, e.touches[0].clientY];
        } else if (e.touches.length === 2) {
          const dx = e.touches[0].clientX - e.touches[1].clientX;
          const dy = e.touches[0].clientY - e.touches[1].clientY;
          const dist = Math.sqrt(dx * dx + dy * dy);
          const factor = 1 + (this.lastTouchDist - dist) * 0.02;

          const eye = this.camera.eye;
          const center = this.camera.center;
          const dir = vec3sub(eye, center);
          const d = vec3len(dir);
          const newDist = Math.max(0.1, Math.min(100, d * factor));
          const normalized = vec3normalize(dir);
          this.camera.eye = vec3add(center, vec3scale(normalized, newDist));

          this.lastTouchDist = dist;
        }
      });

      this.canvas.addEventListener('touchend', () => {
        this.touchCount = 0;
      });
    }

    orbit(dx, dy) {
      const eye = this.camera.eye;
      const center = this.camera.center;
      let dir = vec3sub(eye, center);
      const dist = vec3len(dir);

      const angleX = -dy * 0.005;
      const angleY = -dx * 0.005;

      let x = dir[0];
      let z = dir[2];
      let r = Math.sqrt(x * x + z * z);
      let theta = Math.atan2(z, x) + angleY;
      x = r * Math.cos(theta);
      z = r * Math.sin(theta);
      dir = [x, dir[1], z];

      let y = dir[1];
      let xzLen = Math.sqrt(dir[0] * dir[0] + dir[2] * dir[2]);
      theta = Math.atan2(y, xzLen) + angleX;
      y = dist * Math.sin(theta);
      xzLen = dist * Math.cos(theta);
      const phi = Math.atan2(dir[2], dir[0]);
      dir = [xzLen * Math.cos(phi), y, xzLen * Math.sin(phi)];

      this.camera.eye = vec3add(center, dir);
    }

    pan(dx, dy) {
      const eye = this.camera.eye;
      const center = this.camera.center;
      const up = this.camera.up;

      const forward = vec3normalize(vec3sub(center, eye));
      const right = vec3normalize(vec3cross(forward, up));
      const actualUp = vec3cross(right, forward);

      const moveDir = vec3add(vec3scale(right, -dx * 0.01), vec3scale(actualUp, dy * 0.01));
      this.camera.eye = vec3add(eye, moveDir);
      this.camera.center = vec3add(center, moveDir);
    }

    resize() {
      const rect = this.canvas.parentElement?.getBoundingClientRect();
      if (!rect) return;
      this.canvas.width = rect.width;
      this.canvas.height = rect.height;
      this.gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    }

    computeNormals(positions, indices) {
      const normals = new Float32Array(positions.length);

      for (let i = 0; i < normals.length; i++) {
        normals[i] = 0;
      }

      for (let i = 0; i < indices.length; i += 3) {
        const i0 = indices[i] * 3;
        const i1 = indices[i + 1] * 3;
        const i2 = indices[i + 2] * 3;

        const v0 = [positions[i0], positions[i0 + 1], positions[i0 + 2]];
        const v1 = [positions[i1], positions[i1 + 1], positions[i1 + 2]];
        const v2 = [positions[i2], positions[i2 + 1], positions[i2 + 2]];

        const edge1 = vec3sub(v1, v0);
        const edge2 = vec3sub(v2, v0);
        const faceNormal = vec3normalize(vec3cross(edge1, edge2));

        normals[i0] += faceNormal[0];
        normals[i0 + 1] += faceNormal[1];
        normals[i0 + 2] += faceNormal[2];

        normals[i1] += faceNormal[0];
        normals[i1 + 1] += faceNormal[1];
        normals[i1 + 2] += faceNormal[2];

        normals[i2] += faceNormal[0];
        normals[i2 + 1] += faceNormal[1];
        normals[i2 + 2] += faceNormal[2];
      }

      for (let i = 0; i < normals.length; i += 3) {
        const nx = normals[i];
        const ny = normals[i + 1];
        const nz = normals[i + 2];
        const len = Math.sqrt(nx * nx + ny * ny + nz * nz);
        if (len > 0) {
          normals[i] = nx / len;
          normals[i + 1] = ny / len;
          normals[i + 2] = nz / len;
        }
      }

      return normals;
    }

    addMesh(geometry, color = [0.7, 0.7, 0.7, 1.0], label = '') {
      const gl = this.gl;

      let normals = geometry.normals;
      if (!normals && geometry.indices && geometry.indices.length > 0) {
        normals = this.computeNormals(geometry.positions, geometry.indices);
      }

      const vao = gl.createVertexArray();
      gl.bindVertexArray(vao);

      const posBuffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, posBuffer);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(geometry.positions), gl.STATIC_DRAW);

      let normalBuffer = null;
      if (normals) {
        normalBuffer = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, normalBuffer);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(normals), gl.STATIC_DRAW);
      }

      let indexBuffer = null;
      let indexCount = 0;
      if (geometry.indices && geometry.indices.length > 0) {
        indexBuffer = gl.createBuffer();
        gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, indexBuffer);
        gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, new Uint32Array(geometry.indices), gl.STATIC_DRAW);
        indexCount = geometry.indices.length;
      }

      gl.bindVertexArray(null);

      const mesh = {
        geometry,
        color,
        label,
        vao,
        posBuffer,
        normalBuffer,
        indexBuffer,
        indexCount,
        normals
      };

      this.meshes.push(mesh);

      if (indexCount > 0 && indexCount < 1500000) {
        try {
          const grid = new SpatialGrid(geometry.positions, geometry.indices, 2.0);
          if (!this.spatialIndex) {
            this.spatialIndex = grid;
          }
        } catch (e) {
          console.warn('Failed to build spatial index:', e);
        }
      }

      return mesh;
    }

    fitToView() {
      let minX = Infinity, minY = Infinity, minZ = Infinity;
      let maxX = -Infinity, maxY = -Infinity, maxZ = -Infinity;

      for (const mesh of this.meshes) {
        const pos = mesh.geometry.positions;
        for (let i = 0; i < pos.length; i += 3) {
          minX = Math.min(minX, pos[i]);
          maxX = Math.max(maxX, pos[i]);
          minY = Math.min(minY, pos[i + 1]);
          maxY = Math.max(maxY, pos[i + 1]);
          minZ = Math.min(minZ, pos[i + 2]);
          maxZ = Math.max(maxZ, pos[i + 2]);
        }
      }

      if (!isFinite(minX)) {
        this.camera.eye = [5, 5, 5];
        this.camera.center = [0, 0, 0];
        return;
      }

      const center = [(minX + maxX) / 2, (minY + maxY) / 2, (minZ + maxZ) / 2];
      const size = Math.max(maxX - minX, maxY - minY, maxZ - minZ);
      const dist = size * 1.5;

      this.camera.center = center;
      this.camera.eye = vec3add(center, [dist * 0.6, dist * 0.6, dist * 0.7]);
    }

    createGrid(size = 10, step = 1) {
      const positions = [];
      const colors = [];

      for (let i = -size; i <= size; i += step) {
        positions.push(i, -size, 0, i, size, 0);
        colors.push(0.8, 0.2, 0.2, 1, 0.8, 0.2, 0.2, 1);

        positions.push(-size, i, 0, size, i, 0);
        colors.push(0.2, 0.8, 0.2, 1, 0.2, 0.8, 0.2, 1);
      }

      const gl = this.gl;
      const vao = gl.createVertexArray();
      gl.bindVertexArray(vao);

      const posBuffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, posBuffer);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(positions), gl.STATIC_DRAW);

      const colorBuffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, colorBuffer);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(colors), gl.STATIC_DRAW);

      gl.bindVertexArray(null);

      this.grid = {
        vao,
        count: positions.length / 3
      };
    }

    createAxes(size = 1) {
      const positions = [
        0, 0, 0,  size, 0, 0,
        0, 0, 0,  0, size, 0,
        0, 0, 0,  0, 0, size
      ];

      const colors = [
        1, 0, 0, 1, 1, 0, 0, 1,
        0, 1, 0, 1, 0, 1, 0, 1,
        0, 0, 1, 1, 0, 0, 1, 1
      ];

      const gl = this.gl;
      const vao = gl.createVertexArray();
      gl.bindVertexArray(vao);

      const posBuffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, posBuffer);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(positions), gl.STATIC_DRAW);

      const colorBuffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, colorBuffer);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(colors), gl.STATIC_DRAW);

      gl.bindVertexArray(null);

      this.axes = {
        vao,
        count: 6
      };
    }

    render() {
      const gl = this.gl;
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

      const aspect = this.canvas.width / this.canvas.height;
      const proj = this.perspectiveMatrix(Math.PI / 4, aspect, 0.1, 1000);
      const view = this.lookAtMatrix(this.camera.eye, this.camera.center, this.camera.up);

      if (this.grid) {
        gl.useProgram(this.lineProgram);
        const projLoc = gl.getUniformLocation(this.lineProgram, 'projection');
        const viewLoc = gl.getUniformLocation(this.lineProgram, 'view');
        const modelLoc = gl.getUniformLocation(this.lineProgram, 'model');
        gl.uniformMatrix4fv(projLoc, false, proj);
        gl.uniformMatrix4fv(viewLoc, false, view);
        gl.uniformMatrix4fv(modelLoc, false, this.identityMatrix());

        gl.bindVertexArray(this.grid.vao);
        gl.drawArrays(gl.LINES, 0, this.grid.count);
      }

      if (this.axes) {
        gl.useProgram(this.lineProgram);
        const projLoc = gl.getUniformLocation(this.lineProgram, 'projection');
        const viewLoc = gl.getUniformLocation(this.lineProgram, 'view');
        const modelLoc = gl.getUniformLocation(this.lineProgram, 'model');
        gl.uniformMatrix4fv(projLoc, false, proj);
        gl.uniformMatrix4fv(viewLoc, false, view);
        gl.uniformMatrix4fv(modelLoc, false, this.identityMatrix());

        gl.bindVertexArray(this.axes.vao);
        gl.drawArrays(gl.LINES, 0, this.axes.count);
      }

      gl.useProgram(this.meshProgram);
      const projLoc = gl.getUniformLocation(this.meshProgram, 'projection');
      const viewLoc = gl.getUniformLocation(this.meshProgram, 'view');
      const modelLoc = gl.getUniformLocation(this.meshProgram, 'model');
      gl.uniformMatrix4fv(projLoc, false, proj);
      gl.uniformMatrix4fv(viewLoc, false, view);

      for (const mesh of this.meshes) {
        gl.uniformMatrix4fv(modelLoc, false, this.identityMatrix());
        gl.bindVertexArray(mesh.vao);
        gl.drawElements(gl.TRIANGLES, mesh.indexCount, gl.UNSIGNED_INT, 0);
      }

      gl.bindVertexArray(null);
    }

    animate() {
      if (!this.running) return;
      this.render();
      requestAnimationFrame(() => this.animate());
    }

    perspectiveMatrix(fov, aspect, near, far) {
      const f = 1 / Math.tan(fov / 2);
      const m = new Float32Array(16);
      m[0] = f / aspect;
      m[5] = f;
      m[10] = (far + near) / (near - far);
      m[11] = -1;
      m[14] = (2 * far * near) / (near - far);
      return m;
    }

    lookAtMatrix(eye, center, up) {
      const z = vec3normalize(vec3sub(eye, center));
      const x = vec3normalize(vec3cross(up, z));
      const y = vec3cross(z, x);

      const m = new Float32Array(16);
      m[0] = x[0]; m[4] = x[1]; m[8] = x[2]; m[12] = 0;
      m[1] = y[0]; m[5] = y[1]; m[9] = y[2]; m[13] = 0;
      m[2] = z[0]; m[6] = z[1]; m[10] = z[2]; m[14] = 0;
      m[3] = 0; m[7] = 0; m[11] = 0; m[15] = 1;

      m[12] = -vec3dot(x, eye);
      m[13] = -vec3dot(y, eye);
      m[14] = -vec3dot(z, eye);

      return m;
    }

    identityMatrix() {
      const m = new Float32Array(16);
      m[0] = m[5] = m[10] = m[15] = 1;
      return m;
    }

    // Unproject screen coordinates to world ray
    unproject(screenX, screenY) {
      const aspect = this.canvas.width / this.canvas.height;
      const proj = this.perspectiveMatrix(Math.PI / 4, aspect, 0.1, 1000);
      const view = this.lookAtMatrix(this.camera.eye, this.camera.center, this.camera.up);

      // Normalize screen coordinates
      const x = (screenX / this.canvas.width) * 2 - 1;
      const y = 1 - (screenY / this.canvas.height) * 2;

      // Unproject near and far planes
      const near = this.unprojectPoint(x, y, 0, proj, view);
      const far = this.unprojectPoint(x, y, 1, proj, view);

      const dir = vec3normalize(vec3sub(far, near));
      return { origin: near, dir };
    }

    unprojectPoint(x, y, z, proj, view) {
      // Invert projection and view matrices
      const invProj = this.invertMatrix(proj);
      const invView = this.invertMatrix(view);

      // Unproject from screen space
      const p = [x, y, z * 2 - 1, 1];
      const p1 = this.multiplyMatrixVector(invProj, p);
      p1[0] /= p1[3];
      p1[1] /= p1[3];
      p1[2] /= p1[3];
      p1[3] = 1;

      const p2 = this.multiplyMatrixVector(invView, p1);
      return [p2[0], p2[1], p2[2]];
    }

    invertMatrix(m) {
      const m16 = new Float32Array(16);
      const a00 = m[0], a01 = m[1], a02 = m[2], a03 = m[3];
      const a10 = m[4], a11 = m[5], a12 = m[6], a13 = m[7];
      const a20 = m[8], a21 = m[9], a22 = m[10], a23 = m[11];
      const a30 = m[12], a31 = m[13], a32 = m[14], a33 = m[15];

      const b00 = a00 * a11 - a01 * a10;
      const b01 = a00 * a12 - a02 * a10;
      const b02 = a00 * a13 - a03 * a10;
      const b03 = a01 * a12 - a02 * a11;
      const b04 = a01 * a13 - a03 * a11;
      const b05 = a02 * a13 - a03 * a12;
      const b06 = a20 * a31 - a21 * a30;
      const b07 = a20 * a32 - a22 * a30;
      const b08 = a20 * a33 - a23 * a30;
      const b09 = a21 * a32 - a22 * a31;
      const b10 = a21 * a33 - a23 * a31;
      const b11 = a22 * a33 - a23 * a32;

      let det = b00 * b11 - b01 * b10 + b02 * b09 + b03 * b08 - b04 * b07 + b05 * b06;
      if (Math.abs(det) < 1e-10) return this.identityMatrix();

      det = 1 / det;

      m16[0] = (a11 * b11 - a12 * b10 + a13 * b09) * det;
      m16[1] = (a02 * b10 - a01 * b11 - a03 * b09) * det;
      m16[2] = (a31 * b05 - a32 * b04 + a33 * b03) * det;
      m16[3] = (a22 * b04 - a21 * b05 - a23 * b03) * det;
      m16[4] = (a12 * b08 - a10 * b11 - a13 * b07) * det;
      m16[5] = (a00 * b11 - a02 * b08 + a03 * b07) * det;
      m16[6] = (a32 * b02 - a30 * b05 - a33 * b01) * det;
      m16[7] = (a20 * b05 - a22 * b02 + a23 * b01) * det;
      m16[8] = (a10 * b10 - a11 * b08 + a13 * b06) * det;
      m16[9] = (a01 * b08 - a00 * b10 - a03 * b06) * det;
      m16[10] = (a30 * b04 - a31 * b02 + a33 * b00) * det;
      m16[11] = (a21 * b02 - a20 * b04 - a23 * b00) * det;
      m16[12] = (a11 * b07 - a10 * b09 - a12 * b06) * det;
      m16[13] = (a00 * b09 - a01 * b07 + a02 * b06) * det;
      m16[14] = (a31 * b01 - a30 * b03 - a32 * b00) * det;
      m16[15] = (a20 * b03 - a21 * b01 + a22 * b00) * det;

      return m16;
    }

    multiplyMatrixVector(m, v) {
      return [
        m[0] * v[0] + m[4] * v[1] + m[8] * v[2] + m[12] * v[3],
        m[1] * v[0] + m[5] * v[1] + m[9] * v[2] + m[13] * v[3],
        m[2] * v[0] + m[6] * v[1] + m[10] * v[2] + m[14] * v[3],
        m[3] * v[0] + m[7] * v[1] + m[11] * v[2] + m[15] * v[3]
      ];
    }

    // Ray-cast from screen coordinates
    raycast(screenX, screenY) {
      const ray = this.unproject(screenX, screenY);
      let closest = null;
      let minDist = Infinity;

      // Ray-cast against spatial grid if available
      if (this.spatialIndex) {
        const hit = this.spatialIndex.raycast(ray.origin, ray.dir, 1000);
        if (hit) {
          return {
            x: ray.origin[0] + ray.dir[0] * hit.t,
            y: ray.origin[1] + ray.dir[1] * hit.t,
            z: ray.origin[2] + ray.dir[2] * hit.t,
            t: hit.t
          };
        }
      }

      // Ray-cast against floor plane (z = 0) as fallback
      const t = -ray.origin[2] / (ray.dir[2] || 1e-6);
      if (t > 0.1 && t < 1000) {
        return {
          x: ray.origin[0] + ray.dir[0] * t,
          y: ray.origin[1] + ray.dir[1] * t,
          z: 0,
          t
        };
      }

      return null;
    }

    destroy() {
      this.running = false;
    }
  }

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

  return { Viewer, rayTriangleIntersect, SpatialGrid, pointInPolygon };
})();
