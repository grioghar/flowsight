// Proxmox inventory and map page
if (!FS.proxmox) FS.proxmox = {};

// Layout functions for the dependency map SVG
FS.proxmox.layout = function(guests, nodes) {
  const nodeList = nodes || [];
  const guestsByNode = {};
  for (const g of (guests || [])) {
    if (!guestsByNode[g.node]) guestsByNode[g.node] = [];
    guestsByNode[g.node].push(g);
  }

  const nodeWidth = 280;
  const nodeHeight = 100;
  const columnGap = 60;
  const rowGap = 40;
  let x = 40;
  const positions = {};

  for (const node of nodeList) {
    let y = 40;
    const nodeGuests = guestsByNode[node.name] || [];
    for (const g of nodeGuests) {
      positions[g.vmid] = { x, y, node: node.name, nodeWidth, nodeHeight };
      y += nodeHeight + rowGap;
    }
    x += nodeWidth + columnGap;
  }

  return { positions, totalWidth: x + 40, totalHeight: 600 };
};

FS.proxmox.edgePath = function(fromPos, toPos) {
  const x1 = fromPos.x + fromPos.nodeWidth;
  const y1 = fromPos.y + fromPos.nodeHeight / 2;
  const x2 = toPos.x;
  const y2 = toPos.y + toPos.nodeHeight / 2;
  const cpx = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${cpx} ${y1} ${cpx} ${y2} ${x2} ${y2}`;
};

FS.proxmox.requirementsMarkdown = function(req) {
  let md = `# Guest: ${req.vmid} (${req.node})\n\n`;

  if (req.cores || req.memory) {
    md += `## Resources\n- Cores: ${req.cores || 'N/A'}\n- Memory: ${req.memory ? (req.memory / 1024) + ' GiB' : 'N/A'}\n\n`;
  }

  if (req.depends_on && req.depends_on.length) {
    md += `## Depends On\n`;
    for (const dep of req.depends_on) {
      md += `- ${dep.name || dep.vmid} (port ${dep.port || 'N/A'} / ${dep.proto || 'N/A'})\n`;
    }
    md += '\n';
  }

  if (req.dependent_on && req.dependent_on.length) {
    md += `## Used By\n`;
    for (const dep of req.dependent_on) {
      md += `- ${dep.name || dep.vmid} (port ${dep.port || 'N/A'} / ${dep.proto || 'N/A'})\n`;
    }
    md += '\n';
  }

  if (req.external_deps && req.external_deps.length) {
    md += `## External Dependencies\n`;
    for (const ext of req.external_deps) {
      md += `- ${ext.name || ext.destination} (${Math.round(ext.bytes / 1024 / 1024)} MB)\n`;
    }
    md += '\n';
  }

  return md;
};

FS.registerPage("proxmox", async function() {
  return await FS.html(`
    <div class="panel">
      <style>
        .proxmox-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }
        .proxmox-tabs { display: flex; gap: 5px; margin-bottom: 20px; border-bottom: 1px solid var(--color-border); }
        .proxmox-tab { padding: 10px 15px; cursor: pointer; border: none; background: transparent; color: var(--color-text); font-size: 0.95em; }
        .proxmox-tab.active { border-bottom: 2px solid var(--color-primary); color: var(--color-primary); }
        .proxmox-tab-content { display: none; }
        .proxmox-tab-content.active { display: block; }
        .proxmox-nodes { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .node-card { border: 1px solid var(--color-border); border-radius: 8px; padding: 15px; background: var(--color-card); }
        .node-card h3 { margin-top: 0; }
        .node-stat { display: flex; justify-content: space-between; padding: 5px 0; font-size: 0.9em; }
        .guests-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .guests-table th { text-align: left; padding: 10px; border-bottom: 2px solid var(--color-border); background: var(--color-header); }
        .guests-table td { padding: 10px; border-bottom: 1px solid var(--color-border); }
        .guests-table tr:hover { background: var(--color-hover); }
        .status-running { color: var(--color-success); font-weight: bold; }
        .status-stopped { color: var(--color-muted); }
        .vmid-tag { display: inline-block; padding: 2px 6px; border-radius: 3px; background: var(--color-tag); font-size: 0.85em; }
        .agent-state { font-size: 0.85em; }
        .agent-responding { color: var(--color-success); }
        .agent-not-responding { color: var(--color-warn); }
        .btn-group { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .error-msg { color: var(--color-error); padding: 10px; border-left: 3px solid var(--color-error); background: var(--color-error-bg); margin-bottom: 20px; }
        .unconfigured { padding: 20px; background: var(--color-info-bg); border: 1px solid var(--color-info); border-radius: 8px; }
        .cmd-block { background: var(--color-mono-bg); padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.85em; margin: 10px 0; }
        .map-container { position: relative; border: 1px solid var(--color-border); border-radius: 8px; background: var(--color-card); padding: 20px; overflow-x: auto; }
        .map-window-buttons { margin-bottom: 15px; display: flex; gap: 8px; }
        .map-window-buttons button { padding: 6px 12px; font-size: 0.9em; }
        .map-window-buttons button.active { background: var(--color-primary); color: white; }
        .guest-box { rx: 4; }
        .guest-box.qemu { stroke-width: 2; }
        .guest-box.lxc { stroke-dasharray: 5,5; stroke-width: 2; }
        .guest-box-text { font-size: 12px; pointer-events: none; }
        .edge-line { fill: none; stroke-width: 1; }
        .edge-line.observed { stroke: var(--color-success); }
        .edge-line.declared { stroke: var(--color-info); stroke-dasharray: 5,5; }
        .edge-line.sockets { stroke: var(--color-warn); stroke-dasharray: 2,2; }
        .edge-label { font-size: 10px; pointer-events: none; }
        .map-legend { margin-top: 15px; padding: 10px; background: var(--color-header); border-radius: 4px; font-size: 0.85em; }
        .legend-item { display: inline-flex; align-items: center; gap: 8px; margin-right: 15px; }
        .legend-box { width: 30px; height: 20px; border-radius: 3px; border: 1px solid var(--color-text); }
        .legend-line { display: inline-block; width: 30px; height: 2px; }
        @media (max-width: 768px) {
          .proxmox-tabs { flex-wrap: wrap; }
          .map-container { overflow-x: auto; }
        }
      </style>

      <div class="proxmox-header">
        <h2>Proxmox</h2>
        <div>
          <button class="btn" onclick="proxmoxPollNow()">Poll Now</button>
        </div>
      </div>

      <div class="proxmox-tabs">
        <button class="proxmox-tab active" onclick="switchProxmoxTab(event, 'inventory')">Inventory</button>
        <button class="proxmox-tab" onclick="switchProxmoxTab(event, 'map')">Map</button>
      </div>

      <div id="proxmoxInventory" class="proxmox-tab-content active">
        <div id="proxmoxInventoryContent">
          <div style="text-align: center; padding: 40px;">
            <div class="spinner"></div>
            <p>Loading Proxmox inventory...</p>
          </div>
        </div>
      </div>

      <div id="proxmoxMap" class="proxmox-tab-content">
        <div id="proxmoxMapContent">
          <div style="text-align: center; padding: 40px;">
            <div class="spinner"></div>
            <p>Loading dependency map...</p>
          </div>
        </div>
      </div>
    </div>

    <script>
      async function switchProxmoxTab(event, tab) {
        event.target.classList.toggle('active');
        document.querySelectorAll('.proxmox-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        document.querySelectorAll('.proxmox-tab-content').forEach(c => c.classList.remove('active'));
        const el = document.getElementById('proxmox' + tab.charAt(0).toUpperCase() + tab.slice(1));
        if (el) el.classList.add('active');
        if (tab === 'map') await loadProxmoxMap();
      }

      async function proxmoxPollNow() {
        try {
          const res = await FS.post("/api/proxmox/poll", {});
          FS.toast("Poll started", "info");
          setTimeout(() => { loadProxmoxInventory(); loadProxmoxMap(); }, 2000);
        } catch (err) {
          FS.toast("Poll failed: " + err.message, "error");
        }
      }

      async function loadProxmoxInventory() {
        try {
          const inv = await FS.get("/api/proxmox/inventory");
          const status = await FS.get("/api/proxmox/status");

          if (!inv.nodes || inv.nodes.length === 0) {
            document.getElementById("proxmoxInventoryContent").innerHTML = `
              <div class="unconfigured">
                <h3>Proxmox not configured</h3>
                <p>To enable Proxmox inventory mapping, configure the following in Settings:</p>
                <ul>
                  <li><strong>Hosts:</strong> One or more Proxmox node URLs (e.g., https://pve.local:8006)</li>
                  <li><strong>Token ID:</strong> API token, format: user@realm!tokenname</li>
                  <li><strong>Token Secret:</strong> The API token secret</li>
                  <li><strong>Fingerprint:</strong> Optional TLS certificate SHA-256 fingerprint (pinning)</li>
                </ul>
                <p>To create a least-privilege API token:</p>
                <div class="cmd-block">pveum role add FlowSight -privs "VM.Audit VM.Config.Options Sys.Audit"</div>
                <div class="cmd-block">pveum user add flowsight@pve</div>
                <div class="cmd-block">pveum user token add flowsight@pve flowsight --privsep 0</div>
                <div class="cmd-block">pveum acl modify / --users flowsight@pve --roles FlowSight</div>
                <p>To read the TLS fingerprint:</p>
                <div class="cmd-block">pvenode cert info | grep Fingerprint</div>
              </div>
            `;
            return;
          }

          let html = '';

          if (status.error) {
            html += '<div class="error-msg"><strong>Last poll error:</strong> ' + FS.esc(status.error) + '</div>';
          }

          html += '<div class="proxmox-nodes">';
          for (const node of inv.nodes || []) {
            html += `
              <div class="node-card">
                <h3>${FS.esc(node.name)}</h3>
                <div class="node-stat">
                  <span>PVE Version:</span>
                  <span>${FS.esc(node.pve_version)}</span>
                </div>
                <div class="node-stat">
                  <span>Kernel:</span>
                  <span>${FS.esc(node.kernel)}</span>
                </div>
                <div class="node-stat">
                  <span>CPU:</span>
                  <span>${(node.cpu / 100).toFixed(1)}%</span>
                </div>
                <div class="node-stat">
                  <span>Memory:</span>
                  <span>${node.mem_percent}%</span>
                </div>
                <div class="node-stat">
                  <span>Rootfs:</span>
                  <span>${node.rootfs_pct}%</span>
                </div>
                <div class="node-stat">
                  <span>Uptime:</span>
                  <span>${FS.ago(node.uptime)}</span>
                </div>
              </div>
            `;
          }
          html += '</div>';

          html += '<h3>Guests</h3>';
          html += `
            <table class="guests-table">
              <thead>
                <tr>
                  <th>VMID</th>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Node</th>
                  <th>Status</th>
                  <th>IPs</th>
                  <th>OS</th>
                  <th>Agent</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
          `;

          for (const guest of inv.guests || []) {
            const statusClass = guest.status === 'running' ? 'status-running' : 'status-stopped';
            const agentClass = guest.agent_state === 'responding' ? 'agent-responding' : 'agent-not-responding';
            const ips = (guest.ips || []).join(', ') || '—';
            const os = guest.os || guest.ostype || '—';
            const agentText = guest.agent_state || 'N/A';

            html += `
              <tr>
                <td><span class="vmid-tag">${guest.vmid}</span></td>
                <td>${FS.esc(guest.name)}</td>
                <td>${guest.type}</td>
                <td>${guest.node}</td>
                <td><span class="${statusClass}">${guest.status}</span></td>
                <td>${FS.esc(ips)}</td>
                <td>${FS.esc(os)}</td>
                <td><span class="agent-state ${agentClass}">${agentText}</span></td>
                <td>
                  <button class="btn btn-sm" onclick="showProxmoxNotes('${guest.vmid}', '${guest.node}', '${FS.esc(guest.name)}')">Notes</button>
                </td>
              </tr>
            `;
          }

          html += `
              </tbody>
            </table>
          `;

          document.getElementById("proxmoxInventoryContent").innerHTML = html;
        } catch (err) {
          document.getElementById("proxmoxInventoryContent").innerHTML = '<div class="error-msg">Error loading Proxmox data: ' + FS.esc(err.message) + '</div>';
        }
      }

      async function loadProxmoxMap() {
        try {
          const inv = await FS.get("/api/proxmox/inventory");
          if (!inv.nodes || inv.nodes.length === 0) {
            document.getElementById("proxmoxMapContent").innerHTML = '<div class="unconfigured"><p>Proxmox not configured</p></div>';
            return;
          }

          const mapHours = 24;
          const mapData = await FS.get(`/api/proxmox/map?hours=${mapHours}`);

          const layout = FS.proxmox.layout(mapData.guests, inv.nodes);
          let html = `
            <div class="map-window-buttons">
              <button class="btn active" onclick="proxmoxMapWindow(1)">1h</button>
              <button class="btn" onclick="proxmoxMapWindow(24)">24h</button>
              <button class="btn" onclick="proxmoxMapWindow(168)">7d</button>
              <button class="btn" style="margin-left:auto;" onclick="proxmoxExportMap(24)">Export JSON</button>
            </div>
            <div class="map-container">
              <svg width="${Math.min(layout.totalWidth, 1200)}" height="${layout.totalHeight}" style="min-width:100%;border:1px solid var(--color-border);border-radius:4px;">
          `;

          // Draw edges
          for (const edge of (mapData.edges || [])) {
            const fromPos = layout.positions[edge.from];
            const toPos = layout.positions[edge.to];
            if (fromPos && toPos) {
              const path = FS.proxmox.edgePath(fromPos, toPos);
              const strokeWidth = Math.max(1, Math.min(4, Math.log10(edge.bytes + 1) / 2));
              html += `<path d="${path}" class="edge-line ${edge.source}" stroke-width="${strokeWidth}" />`;
              const midX = (fromPos.x + fromPos.nodeWidth + toPos.x) / 2;
              const midY = (fromPos.y + toPos.y) / 2 + fromPos.nodeHeight / 2;
              if (edge.port) {
                html += `<text x="${midX}" y="${midY}" class="edge-label" text-anchor="middle">${edge.port}/${edge.proto}</text>`;
              }
            }
          }

          // Draw guest boxes
          for (const guest of (mapData.guests || [])) {
            const pos = layout.positions[guest.vmid];
            if (!pos) continue;
            const boxColor = guest.type === 'qemu' ? 'var(--color-info)' : 'var(--color-warn)';
            const ips = (guest.ips && guest.ips.length > 0) ? guest.ips[0] : '';
            html += `
              <rect x="${pos.x}" y="${pos.y}" width="${pos.nodeWidth}" height="${pos.nodeHeight}"
                    class="guest-box ${guest.type}" fill="var(--color-card)" stroke="${boxColor}"
                    onclick="showProxmoxRequirements(${guest.vmid}, '${guest.node}')"
                    style="cursor:pointer;" />
              <text x="${pos.x + 10}" y="${pos.y + 20}" class="guest-box-text" font-weight="bold">${FS.esc(guest.name)}</text>
              <text x="${pos.x + 10}" y="${pos.y + 35}" class="guest-box-text">${guest.vmid}</text>
              <text x="${pos.x + 10}" y="${pos.y + 50}" class="guest-box-text">${FS.esc(ips)}</text>
            `;
          }

          html += `
              </svg>
            </div>
            <div class="map-legend">
              <div class="legend-item"><div class="legend-box" style="border:2px solid var(--color-info);"></div>QEMU VM</div>
              <div class="legend-item"><div class="legend-box" style="border:2px dashed var(--color-warn);"></div>LXC Container</div>
              <div class="legend-item"><div class="legend-line" style="background:var(--color-success);"></div>Observed</div>
              <div class="legend-item"><div class="legend-line" style="background:var(--color-info);border-top:1px dashed var(--color-info);"></div>Declared</div>
              <div class="legend-item"><div class="legend-line" style="background:var(--color-warn);border-top:1px dotted var(--color-warn);"></div>Sockets</div>
            </div>
          `;

          document.getElementById("proxmoxMapContent").innerHTML = html;
          window.proxmoxMapData = mapData;
        } catch (err) {
          document.getElementById("proxmoxMapContent").innerHTML = '<div class="error-msg">Error loading map: ' + FS.esc(err.message) + '</div>';
        }
      }

      function proxmoxMapWindow(hours) {
        document.querySelectorAll('.map-window-buttons button').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');
        // Reload with new hours
        loadProxmoxMap();
      }

      function showProxmoxRequirements(vmid, node) {
        if (!window.proxmoxMapData || !window.proxmoxMapData.requirements) {
          FS.toast('Requirements not found', 'error');
          return;
        }
        const key = vmid + ':' + node;
        const req = window.proxmoxMapData.requirements[key];
        if (!req) {
          FS.toast('Requirements not found', 'error');
          return;
        }
        const md = FS.proxmox.requirementsMarkdown(req);
        FS.modal(`Requirements: VMID ${vmid}`, `
          <div style="white-space:pre-wrap;font-family:monospace;font-size:0.9em;max-height:500px;overflow-y:auto;">
${FS.esc(md)}
          </div>
          <div style="margin-top:20px;display:flex;gap:10px;">
            <button class="btn" onclick="proxmoxExportRequirement(${vmid}, '${FS.esc(node)}')">Export Markdown</button>
            <button class="btn btn-secondary" onclick="FS.modal.close()">Close</button>
          </div>
        `);
      }

      function proxmoxExportMap(hours) {
        FS.get(`/api/proxmox/map?hours=${hours}`).then(data => {
          const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `proxmox-map-${hours}h.json`;
          a.click();
        }).catch(err => FS.toast('Export failed: ' + err.message, 'error'));
      }

      function proxmoxExportRequirement(vmid, node) {
        FS.get(`/api/proxmox/requirements?vmid=${vmid}&node=${encodeURIComponent(node)}`).then(req => {
          const md = FS.proxmox.requirementsMarkdown(req);
          const blob = new Blob([md], {type: 'text/markdown'});
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `proxmox-guest-${vmid}-requirements.md`;
          a.click();
        }).catch(err => FS.toast('Export failed: ' + err.message, 'error'));
      }

      async function showProxmoxNotes(vmid, node, name) {
        try {
          const preview = await FS.get("/api/proxmox/notes/preview?vmid=" + vmid + "&node=" + FS.esc(node));
          FS.modal(`Notes Preview: ${name}`, `
            <div style="font-family: monospace; white-space: pre-wrap; background: var(--color-mono-bg); padding: 10px; border-radius: 4px; max-height: 400px; overflow-y: auto;">
${FS.esc(preview.block)}
            </div>
            <div style="margin-top: 20px; display: flex; gap: 10px;">
              <button class="btn" onclick="writeProxmoxNotes('${vmid}', '${FS.esc(node)}'); location.reload();">Write to Proxmox</button>
              <button class="btn btn-secondary" onclick="FS.modal.close()">Close</button>
            </div>
          `);
        } catch (err) {
          FS.toast("Error loading notes: " + err.message, "error");
        }
      }

      async function writeProxmoxNotes(vmid, node) {
        try {
          if (!confirm("Write notes to guest on Proxmox? This will update the description field.")) {
            return;
          }
          await FS.post("/api/proxmox/notes/write", { vmid: parseInt(vmid), node: node });
          FS.toast("Notes written successfully", "success");
        } catch (err) {
          FS.toast("Error writing notes: " + err.message, "error");
        }
      }

      loadProxmoxInventory();
    </script>
  `);
});
