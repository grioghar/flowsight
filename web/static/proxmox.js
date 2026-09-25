// Proxmox inventory page
FS.registerPage("proxmox", async function() {
  return await FS.html(`
    <div class="panel">
      <style>
        .proxmox-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
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
        .btn-group { display: flex; gap: 10px; margin-bottom: 20px; }
        .error-msg { color: var(--color-error); padding: 10px; border-left: 3px solid var(--color-error); background: var(--color-error-bg); margin-bottom: 20px; }
        .unconfigured { padding: 20px; background: var(--color-info-bg); border: 1px solid var(--color-info); border-radius: 8px; }
        .cmd-block { background: var(--color-mono-bg); padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.85em; margin: 10px 0; }
      </style>

      <div class="proxmox-header">
        <h2>Proxmox</h2>
        <button class="btn" onclick="proxmoxPollNow()">Poll Now</button>
      </div>

      <div id="proxmoxContent">
        <div style="text-align: center; padding: 40px;">
          <div class="spinner"></div>
          <p>Loading Proxmox inventory...</p>
        </div>
      </div>
    </div>

    <script>
      async function proxmoxPollNow() {
        try {
          const res = await FS.post("/api/proxmox/poll", {});
          FS.toast("Poll started", "info");
          setTimeout(() => loadProxmoxData(), 2000);
        } catch (err) {
          FS.toast("Poll failed: " + err.message, "error");
        }
      }

      async function loadProxmoxData() {
        try {
          const inv = await FS.get("/api/proxmox/inventory");
          const status = await FS.get("/api/proxmox/status");

          if (!inv.nodes || inv.nodes.length === 0) {
            document.getElementById("proxmoxContent").innerHTML = `
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

          document.getElementById("proxmoxContent").innerHTML = html;
        } catch (err) {
          document.getElementById("proxmoxContent").innerHTML = '<div class="error-msg">Error loading Proxmox data: ' + FS.esc(err.message) + '</div>';
        }
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

      loadProxmoxData();
    </script>
  `);
});
