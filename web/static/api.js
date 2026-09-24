/* FlowSight API explorer: Interactive OpenAPI documentation. */
'use strict';
(function () {
  const { esc, card, table, get, post } = FS;

  FS.registerPage('api', {
    title: 'API',
    refresh: 0,
    async render(el) {
      const spec = await get('/api/openapi.json');
      if (spec.error) {
        el.innerHTML = FS.err(spec.error);
        return;
      }

      // Build grouped operations
      const ops = [];
      for (const [path, methods] of Object.entries(spec.paths || {})) {
        for (const [method, opData] of Object.entries(methods || {})) {
          ops.push({
            method: method.toUpperCase(),
            path,
            ...opData
          });
        }
      }

      // Group by area/tag
      const grouped = {};
      (spec['x-tagGroups'] || []).forEach(tg => {
        grouped[tg.name] = { name: tg.name, tags: tg.tags, ops: [] };
      });

      ops.forEach(op => {
        const tags = op.tags || [];
        if (tags.length > 0) {
          const area = tags[0];
          if (grouped[area]) {
            grouped[area].ops.push(op);
          }
        }
      });

      // Render
      const areas = ['Monitor', 'Inventory', 'Protect', 'Administration'];
      let html = `<div style="display:flex;gap:20px;margin-bottom:14px">
        <div style="flex:1">${card('', `
          <p class="small">
            <strong>FlowSight API v${esc(spec.info.version)}</strong><br>
            Complete REST API for policy, inventory, monitoring and administration.<br>
            <button class="btn small" id="dl-spec" style="margin-top:8px">Download OpenAPI JSON</button>
          </p>
        `)}</div>
      </div>`;

      areas.forEach(area => {
        const group = grouped[area];
        if (!group || group.ops.length === 0) return;

        html += `<div style="margin-bottom:14px">${card(area, `
          <div class="api-area">
            ${group.ops.map((op, i) => `
              <div class="api-op" data-idx="${i}">
                <div class="api-op-header" style="cursor:pointer;padding:8px;background:#f5f5f5;border-radius:4px;margin-bottom:4px">
                  <span class="pill ${op['x-write'] ? 'bad' : 'ok'}" style="display:inline-block;width:50px;text-align:center">${esc(op.method)}</span>
                  <span class="mono small" style="margin-left:8px">${esc(op.path)}</span>
                  ${op.operationId ? `<span class="pill" style="margin-left:8px;font-size:11px">${esc(op.operationId)}</span>` : ''}
                </div>
                <div class="api-op-detail" style="display:none;padding:8px;border-left:3px solid #ddd;margin-bottom:8px;background:#fafafa">
                  <div class="small"><strong>${esc(op.summary || op.operationId || 'Operation')}</strong></div>
                  ${(op.parameters || []).length > 0 ? `
                    <div style="margin-top:8px">
                      <div class="small" style="font-weight:bold;color:#666">Parameters:</div>
                      ${(op.parameters || []).map(p => `
                        <div style="margin:4px 0;font-size:12px">
                          <span class="mono">${esc(p.name)}</span>
                          <span class="muted"> — ${esc(p.description || '')}</span>
                        </div>
                      `).join('')}
                    </div>
                  ` : ''}
                  ${op['x-write'] ? `
                    <div style="margin-top:8px">
                      <div class="small" style="font-weight:bold;color:#666">Request body (JSON):</div>
                      <textarea class="api-body" data-idx="${i}" style="width:100%;height:100px;font-family:monospace;font-size:12px;padding:4px;border:1px solid #ccc;border-radius:4px;resize:vertical">{}</textarea>
                    </div>
                  ` : ''}
                  <div style="margin-top:8px;display:flex;gap:8px">
                    <button class="btn small api-send" data-idx="${i}">Send request</button>
                    <button class="btn small api-curl" data-idx="${i}">Copy as curl</button>
                  </div>
                  <div class="api-response" data-idx="${i}" style="display:none;margin-top:8px;padding:8px;background:white;border:1px solid #ddd;border-radius:4px;max-height:300px;overflow-y:auto">
                    <div class="small muted">Response will appear here...</div>
                  </div>
                </div>
              </div>
            `).join('')}
          </div>
        `)}</div>`;
      });

      el.innerHTML = html;

      // Event handlers
      FS.$$('.api-op-header', el).forEach(hdr => {
        hdr.onclick = (e) => {
          e.stopPropagation();
          const detail = hdr.nextElementSibling;
          const isOpen = detail.style.display !== 'none';
          FS.$$('.api-op-detail', el).forEach(d => d.style.display = 'none');
          if (!isOpen) detail.style.display = 'block';
        };
      });

      FS.$('#dl-spec', el).onclick = () => {
        const a = document.createElement('a');
        a.href = '/api/openapi.json';
        a.download = `flowsight-api-${spec.info.version}.json`;
        a.click();
      };

      FS.$$('.api-send', el).forEach(btn => {
        btn.onclick = async () => {
          const idx = btn.dataset.idx;
          const op = ops[idx];
          const responseDiv = FS.$(`[data-idx="${idx}"].api-response`, el);
          const bodyInput = FS.$(`[data-idx="${idx}"].api-body`, el);

          if (op['x-write']) {
            if (!await FS.confirm('This is a write operation. Confirm?')) return;
          }

          const t0 = performance.now();
          try {
            const opts = { headers: { 'X-Requested-With': 'Flowsight' } };
            let result;
            if (op['x-write']) {
              const body = bodyInput ? bodyInput.value : '{}';
              result = await post(op.path, JSON.parse(body), opts);
            } else {
              result = await get(op.path, opts);
            }
            const elapsed = (performance.now() - t0).toFixed(0);
            responseDiv.innerHTML = `
              <div class="small" style="color:#666;margin-bottom:8px">Status 200 · ${elapsed}ms</div>
              <pre class="code" style="margin:0;max-height:280px;overflow-y:auto;font-size:11px">${esc(JSON.stringify(result, null, 2))}</pre>
            `;
          } catch (e) {
            responseDiv.innerHTML = `<div class="sev-high small">${esc(e.message)}</div>`;
          }
          responseDiv.style.display = 'block';
        };
      });

      FS.$$('.api-curl', el).forEach(btn => {
        btn.onclick = () => {
          const idx = btn.dataset.idx;
          const op = ops[idx];
          const bodyInput = FS.$(`[data-idx="${idx}"].api-body`, el);
          const body = bodyInput ? bodyInput.value.trim() : '{}';

          let curl = `curl -X ${op.method} https://flowsight.example.com${op.path}`;
          if (op['x-write']) {
            curl += ` -H 'X-Flowsight-Token: YOUR_TOKEN' -H 'X-Requested-With: Flowsight'`;
            if (body && body !== '{}') {
              curl += ` -d '${body.replace(/'/g, "'\\''")}'`;
            }
          } else {
            curl += ` -H 'X-Flowsight-Token: YOUR_TOKEN'`;
          }

          const ta = document.createElement('textarea');
          ta.value = curl;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          FS.toast('Copied to clipboard');
        };
      });
    }
  });
})();
