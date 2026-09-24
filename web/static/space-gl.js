/* FlowSight Space: WebGL 3D viewer for space and devices */
'use strict';

// WebGL2 3D viewer for the Space module
// Features: orbit camera, floor grid, translucent rooms, device markers, scan mesh

FS.space3D = (function() {
  'use strict';

  // === Vertex/Fragment Shaders ===

  const vertexShader = `#version 300 es
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

  void main() {
    vPos = (model * vec4(position, 1.0)).xyz;
    vNormal = normalize((model * vec4(normal, 0.0)).xyz);
    vColor = color;
    gl_Position = projection * view * vec4(vPos, 1.0);
  }
  `;

  const fragmentShader = `#version 300 es
  precision highp float;

  in vec3 vNormal;
  in vec4 vColor;
  in vec3 vPos;

  out vec4 outColor;

  void main() {
    vec3 light = normalize(vec3(1.0, 1.0, 2.0));
    float diffuse = max(dot(vNormal, light), 0.3);
    float ambient = 0.3;
    outColor = vec4(vColor.rgb * (ambient + diffuse), vColor.a);
  }
  `;

  // === Viewer Class ===

  class Viewer {
    constructor(canvas) {
      this.canvas = canvas;
      this.gl = canvas.getContext('webgl2');
      if (!this.gl) throw new Error('WebGL2 not supported');

      this.gl.enable(this.gl.DEPTH_TEST);
      this.gl.enable(this.gl.BLEND);
      this.gl.blendFunc(this.gl.SRC_ALPHA, this.gl.ONE_MINUS_SRC_ALPHA);

      // Compile shaders
      this.program = this.createProgram(vertexShader, fragmentShader);
      this.gl.useProgram(this.program);

      // Camera
      this.camera = {
        eye: [5, 5, 5],
        center: [0, 0, 0],
        up: [0, 0, 1]
      };
      this.zoom = 15;

      // Input
      this.mouseDown = false;
      this.lastMouse = [0, 0];
      this.setupInput();

      // Meshes
      this.meshes = [];

      // Resize
      this.resize();
      window.addEventListener('resize', () => this.resize());
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
        console.error('Program link error:', gl.getProgramInfoLog(prog));
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
        this.lastMouse = [e.clientX, e.clientY];

        // Orbit camera
        const angle = 0.01;
        const axis = [dy, dx, 0];
        this.rotateCamera(axis, angle);
      });

      this.canvas.addEventListener('mouseup', () => {
        this.mouseDown = false;
      });

      this.canvas.addEventListener('wheel', (e) => {
        e.preventDefault();
        this.zoom *= (1 + e.deltaY * 0.001);
        this.zoom = Math.max(0.1, Math.min(100, this.zoom));
      });
    }

    rotateCamera(axis, angle) {
      // Simple rotation around center
      const len = Math.sqrt(axis[0] * axis[0] + axis[1] * axis[1] + axis[2] * axis[2]);
      if (len > 0) {
        axis = [axis[0] / len, axis[1] / len, axis[2] / len];
      }

      const eye = this.camera.eye;
      const c = this.camera.center;
      let x = eye[0] - c[0];
      let y = eye[1] - c[1];
      let z = eye[2] - c[2];

      // Rodrigues rotation formula
      const cosA = Math.cos(angle);
      const sinA = Math.sin(angle);
      const one = 1 - cosA;

      const xx = axis[0] * axis[0] * one + cosA;
      const xy = axis[0] * axis[1] * one - axis[2] * sinA;
      const xz = axis[0] * axis[2] * one + axis[1] * sinA;
      const yx = axis[1] * axis[0] * one + axis[2] * sinA;
      const yy = axis[1] * axis[1] * one + cosA;
      const yz = axis[1] * axis[2] * one - axis[0] * sinA;
      const zx = axis[2] * axis[0] * one - axis[1] * sinA;
      const zy = axis[2] * axis[1] * one + axis[0] * sinA;
      const zz = axis[2] * axis[2] * one + cosA;

      this.camera.eye = [
        c[0] + x * xx + y * xy + z * xz,
        c[1] + x * yx + y * yy + z * yz,
        c[2] + x * zx + y * zy + z * zz
      ];
    }

    resize() {
      const rect = this.canvas.parentElement?.getBoundingClientRect();
      if (!rect) return;
      this.canvas.width = rect.width;
      this.canvas.height = rect.height;
      this.gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    }

    addMesh(geometry, color = [0.7, 0.7, 0.7, 1.0]) {
      const mesh = {
        geometry,
        color,
        vao: this.gl.createVertexArray(),
        posBuffer: this.gl.createBuffer(),
        normalBuffer: this.gl.createBuffer(),
        indexBuffer: this.gl.createBuffer(),
        indexCount: geometry.indices?.length || 0,
      };

      this.gl.bindVertexArray(mesh.vao);

      // Positions
      this.gl.bindBuffer(this.gl.ARRAY_BUFFER, mesh.posBuffer);
      this.gl.bufferData(this.gl.ARRAY_BUFFER, new Float32Array(geometry.positions), this.gl.STATIC_DRAW);
      const posLoc = this.gl.getAttribLocation(this.program, 'position');
      this.gl.vertexAttribPointer(posLoc, 3, this.gl.FLOAT, false, 0, 0);
      this.gl.enableVertexAttribArray(posLoc);

      // Normals
      if (geometry.normals) {
        this.gl.bindBuffer(this.gl.ARRAY_BUFFER, mesh.normalBuffer);
        this.gl.bufferData(this.gl.ARRAY_BUFFER, new Float32Array(geometry.normals), this.gl.STATIC_DRAW);
        const normalLoc = this.gl.getAttribLocation(this.program, 'normal');
        this.gl.vertexAttribPointer(normalLoc, 3, this.gl.FLOAT, false, 0, 0);
        this.gl.enableVertexAttribArray(normalLoc);
      }

      // Indices
      if (geometry.indices) {
        this.gl.bindBuffer(this.gl.ELEMENT_ARRAY_BUFFER, mesh.indexBuffer);
        this.gl.bufferData(this.gl.ELEMENT_ARRAY_BUFFER, new Uint32Array(geometry.indices), this.gl.STATIC_DRAW);
      }

      this.gl.bindVertexArray(null);
      this.meshes.push(mesh);
      return mesh;
    }

    render() {
      this.gl.clearColor(0.95, 0.95, 0.95, 1.0);
      this.gl.clear(this.gl.COLOR_BUFFER_BIT | this.gl.DEPTH_BUFFER_BIT);

      // Matrices
      const aspect = this.canvas.width / this.canvas.height;
      const proj = this.perspectiveMatrix(Math.PI / 4, aspect, 0.1, 1000);
      const view = this.lookAtMatrix(this.camera.eye, this.camera.center, this.camera.up);

      const projLoc = this.gl.getUniformLocation(this.program, 'projection');
      const viewLoc = this.gl.getUniformLocation(this.program, 'view');
      const modelLoc = this.gl.getUniformLocation(this.program, 'model');

      this.gl.uniformMatrix4fv(projLoc, false, proj);
      this.gl.uniformMatrix4fv(viewLoc, false, view);

      // Draw meshes
      this.meshes.forEach(mesh => {
        this.gl.uniformMatrix4fv(modelLoc, false, this.identityMatrix());
        this.gl.bindVertexArray(mesh.vao);
        this.gl.drawElements(this.gl.TRIANGLES, mesh.indexCount, this.gl.UNSIGNED_INT, 0);
      });

      this.gl.bindVertexArray(null);
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
      const z = [
        eye[0] - center[0],
        eye[1] - center[1],
        eye[2] - center[2]
      ];
      const zLen = Math.sqrt(z[0] * z[0] + z[1] * z[1] + z[2] * z[2]);
      z[0] /= zLen; z[1] /= zLen; z[2] /= zLen;

      const x = [
        up[1] * z[2] - up[2] * z[1],
        up[2] * z[0] - up[0] * z[2],
        up[0] * z[1] - up[1] * z[0]
      ];
      const xLen = Math.sqrt(x[0] * x[0] + x[1] * x[1] + x[2] * x[2]);
      x[0] /= xLen; x[1] /= xLen; x[2] /= xLen;

      const y = [
        z[1] * x[2] - z[2] * x[1],
        z[2] * x[0] - z[0] * x[2],
        z[0] * x[1] - z[1] * x[0]
      ];

      const m = new Float32Array(16);
      m[0] = x[0]; m[4] = x[1]; m[8] = x[2];
      m[1] = y[0]; m[5] = y[1]; m[9] = y[2];
      m[2] = z[0]; m[6] = z[1]; m[10] = z[2];
      m[3] = 0; m[7] = 0; m[11] = 0;
      m[12] = -x[0] * eye[0] - x[1] * eye[1] - x[2] * eye[2];
      m[13] = -y[0] * eye[0] - y[1] * eye[1] - y[2] * eye[2];
      m[14] = -z[0] * eye[0] - z[1] * eye[1] - z[2] * eye[2];
      m[15] = 1;
      return m;
    }

    identityMatrix() {
      const m = new Float32Array(16);
      m[0] = m[5] = m[10] = m[15] = 1;
      return m;
    }
  }

  return { Viewer };
})();
