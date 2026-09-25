/* FlowSight Setup Wizard: first-run configuration. */
'use strict';
(function () {
  const { $, $$, esc, card, get, post } = FS;

  FS.registerPage('setup', {
    title: 'Setup wizard',
    refresh: 0,
    async render(el) {
      const state = await get('/api/setup/state');
      if (state.error) {
        el.innerHTML = FS.err(state.error);
        return;
      }

      // Build the wizard UI with step list and current step
      const stepInfo = {
        1: { title: 'Welcome & license', icon: '◈' },
        2: { title: 'Site basics', icon: '⚙' },
        3: { title: 'Traffic source', icon: '⇢' },
        4: { title: 'DNS source', icon: '◎' },
        5: { title: 'Interception', icon: '🔒' },
        6: { title: 'Identity & zones', icon: '▦' },
        7: { title: 'Security', icon: '⚠' },
        8: { title: 'Inventory', icon: '▣' },
        9: { title: 'Alerting', icon: '🔔' },
        10: { title: 'Updates', icon: '▥' },
        11: { title: 'API access', icon: 'API' },
        12: { title: 'Review & finish', icon: '✓' }
      };

      let currentStep = 1;
      if (state.completed) {
        currentStep = 13; // Show completion screen
      }

      // Main wizard container
      el.innerHTML = `<div style="display:grid;grid-template-columns:200px 1fr;gap:20px;max-width:1200px;margin:0 auto">
        <div class="wizard-steps" style="background:#f5f5f5;padding:16px;border-radius:8px;max-height:calc(100vh - 100px);overflow-y:auto">
          <h3 style="margin:0 0 16px 0;font-size:14px;color:#666">Steps</h3>
          ${Array.from({length: 12}, (_, i) => {
            const step = i + 1;
            const info = stepInfo[step];
            const isActive = step === currentStep;
            const isComplete = step < currentStep || (state.completed && step <= 12);
            return `<div class="step" data-step="${step}" style="padding:8px;margin:4px 0;border-radius:4px;cursor:pointer;background:${isActive ? '#e8e8e8' : 'transparent'};font-size:13px;border-left:3px solid ${isActive ? '#0066cc' : isComplete ? '#66bb6a' : '#ddd'};padding-left:12px">
              <span style="margin-right:6px">${info.icon}</span>${esc(info.title)}
            </div>`;
          }).join('')}
        </div>
        <div class="wizard-content"></div>
      </div>`;

      // Handle step clicks
      $$('.step', el).forEach(stepEl => {
        stepEl.onclick = () => {
          const step = parseInt(stepEl.dataset.step);
          if (step < currentStep || (state.completed && step <= 12)) {
            currentStep = step;
            renderCurrentStep();
          }
        };
      });

      function renderCurrentStep() {
        const content = $('.wizard-content', el);
        if (currentStep === 13) {
          renderCompletion();
        } else {
          renderStep(currentStep);
        }
      }

      function renderStep(step) {
        const content = $('.wizard-content', el);
        let html = '';
        const formId = `step-${step}-form`;

        switch (step) {
          case 1:
            html = renderLicenseStep();
            break;
          case 2:
            html = renderSiteBasicsStep();
            break;
          case 3:
            html = renderTrafficSourceStep();
            break;
          case 4:
            html = renderDNSSourceStep();
            break;
          case 5:
            html = renderInterceptionStep();
            break;
          case 6:
            html = renderIdentityStep();
            break;
          case 7:
            html = renderSecurityStep();
            break;
          case 8:
            html = renderInventoryStep();
            break;
          case 9:
            html = renderAlertingStep();
            break;
          case 10:
            html = renderUpdatesStep();
            break;
          case 11:
            html = renderAPIAccessStep();
            break;
          case 12:
            html = renderReviewStep();
            break;
        }

        content.innerHTML = html;
        attachStepHandlers(step);
      }

      function renderLicenseStep() {
        return card('Welcome to FlowSight', `
          <p>Welcome! This wizard will guide you through the essential configuration steps to get FlowSight up and running.</p>
          <p style="margin-top:12px"><strong>Current tier:</strong> <span class="pill" style="margin-left:8px">${esc(state.license.tier)}</span></p>
          <p style="margin-top:12px;font-size:13px;color:#666">
            FlowSight Community is a complete product with visibility, policies, alerts and optional inspection.
            <a href="https://grio.co/flowsight" target="_blank" style="color:#0066cc">Upgrade to Pro or Business</a> for advanced features.
          </p>
          <div style="margin-top:16px">
            <label>License key (optional)</label>
            <input id="license-key" type="text" placeholder="Paste your license key" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px;font-family:monospace">
            <button class="btn small" id="test-license" style="margin-top:8px">Activate</button>
            <span id="license-status" style="margin-left:8px;font-size:12px"></span>
          </div>
          ${renderStepButtons(1)}
        `);
      }

      function renderSiteBasicsStep() {
        return card('Site basics', `
          <p style="font-size:13px;color:#666">Configure the installation name, timezone and retention.</p>
          <div style="margin-top:16px">
            <label>Site name</label>
            <input id="site-name" type="text" placeholder="My Network" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
            <div class="small muted" style="margin-top:4px">Shows in the sidebar and browser tabs.</div>
          </div>
          <div style="margin-top:12px">
            <label>Data retention (days)</label>
            <input id="retention-days" type="number" min="1" max="90" value="7" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
            <div class="small muted" style="margin-top:4px">How long to keep traffic, DNS and alert records. Rollups and certificates have separate retention.</div>
          </div>
          <div style="margin-top:12px">
            <label>Memory limit (MB)</label>
            <input id="memory-limit" type="number" min="64" value="256" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
            <div class="small muted" style="margin-top:4px">Go's soft memory limit. Default 256 MB.</div>
          </div>
          ${renderStepButtons(2)}
        `);
      }

      function renderTrafficSourceStep() {
        return card('Traffic source (ntopng)', `
          <p style="font-size:13px;color:#666">Tell FlowSight where to pull network traffic data. ${state.binaries.ntopng ? '<span class="pill ok">ntopng detected</span>' : '<span class="pill bad">ntopng not found</span>'}</p>
          <div style="margin-top:16px">
            <label>ntopng URL</label>
            <input id="ntopng-url" type="text" placeholder="http://127.0.0.1:3000" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>Username (if authentication required)</label>
            <input id="ntopng-username" type="text" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>Password</label>
            <input id="ntopng-password" type="password" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <button class="btn small" id="test-ntopng" style="margin-top:8px">Test connection</button>
          <span id="ntopng-status" style="margin-left:8px;font-size:12px"></span>
          ${renderStepButtons(3)}
        `);
      }

      function renderDNSSourceStep() {
        return card('DNS source', `
          <p style="font-size:13px;color:#666">Configure DNS logging. ${state.pihole_found ? '<span class="pill ok">Pi-hole detected at ' + esc(state.pihole_found) + '</span>' : ''}</p>
          <div style="margin-top:16px">
            <label>Pi-hole address</label>
            <input id="pihole-address" type="text" placeholder="${state.pihole_found || '192.168.1.1'}" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
            <div class="small muted" style="margin-top:4px">IP address or hostname. Empty: use local Unbound.</div>
          </div>
          <div style="margin-top:12px">
            <label>API token</label>
            <input id="pihole-token" type="password" placeholder="Optional" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <button class="btn small" id="test-pihole" style="margin-top:8px">Test connection</button>
          <span id="pihole-status" style="margin-left:8px;font-size:12px"></span>
          ${renderStepButtons(4)}
        `);
      }

      function renderInterceptionStep() {
        const ifaces = state.interfaces || [];
        return card('Web interception', `
          <p style="font-size:13px;color:#666">
            Redirect web traffic through FlowSight for TLS server names and blocking.
            <strong>Off by default.</strong>
          </p>
          <div style="margin-top:16px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="intercept-enable" type="checkbox">
              <span>Intercept web traffic (ports 80, 443)</span>
            </label>
          </div>
          <div style="margin-top:12px">
            <label>Interfaces (optional)</label>
            <p style="font-size:12px;color:#666;margin:4px 0">Empty: all interfaces. Otherwise choose specific ones:</p>
            <div id="interfaces-list" style="margin-top:8px">
              ${ifaces.map(iface => `<label style="display:block;margin:4px 0;font-size:13px">
                <input type="checkbox" data-iface="${esc(iface)}" class="intercept-iface">
                ${esc(iface)}
              </label>`).join('')}
            </div>
          </div>
          <div style="margin-top:16px;padding:12px;background:#fff8e1;border-radius:4px;border-left:3px solid #ffc107;font-size:12px">
            <strong>Note:</strong> This does not change OPNsense firewall rules or sshd. It only configures the transparent proxy.
          </div>
          ${renderStepButtons(5)}
        `);
      }

      function renderIdentityStep() {
        return card('Identity & zones', `
          <p style="font-size:13px;color:#666">FlowSight automatically detects local networks as zones. Review and name them here.</p>
          <div style="margin-top:16px;padding:12px;background:#f0f0f0;border-radius:4px;font-size:12px">
            <p style="margin:0">Zone setup is delegated to <strong>Settings › Zones</strong>. This step is informational.</p>
          </div>
          ${renderStepButtons(6)}
        `);
      }

      function renderSecurityStep() {
        return card('Security', `
          <p style="font-size:13px;color:#666">Configure threat detection and TLS monitoring.</p>
          <div style="margin-top:16px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="ids-enable" type="checkbox">
              <span>Enable IDS (Suricata) ${state.binaries.suricata ? '<span class="pill ok">detected</span>' : '<span class="pill bad">not found</span>'}</span>
            </label>
            <div class="small muted" style="margin-top:4px">Network threat detection with Suricata rules.</div>
          </div>
          <div style="margin-top:12px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="tls-probe" type="checkbox">
              <span>TLS probe (record server certificates)</span>
            </label>
            <div class="small muted" style="margin-top:4px">Peek further into TLS handshakes to log server certificates. Requires inspection off.</div>
          </div>
          ${renderStepButtons(7)}
        `);
      }

      function renderInventoryStep() {
        return card('Inventory', `
          <p style="font-size:13px;color:#666">
            Integrate with Proxmox for VM and LXC inventory. ${state.proxmox_found ? '<span class="pill ok">Proxmox detected at ' + esc(state.proxmox_found) + '</span>' : ''}
          </p>
          <div style="margin-top:16px">
            <label>Proxmox host</label>
            <input id="proxmox-host" type="text" placeholder="${state.proxmox_found || 'pve1.example.com'}" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>API token ID</label>
            <input id="proxmox-token-id" type="text" placeholder="user@pam!tokenid" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>API token secret</label>
            <input id="proxmox-token-secret" type="password" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>Server certificate fingerprint (SHA-256)</label>
            <input id="proxmox-fingerprint" type="text" placeholder="Optional" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
            <div class="small muted" style="margin-top:4px">Get it from: <code style="background:#f0f0f0;padding:2px 4px">pveum cert info /etc/pve/pve-root-ca.pem</code></div>
          </div>
          <button class="btn small" id="test-proxmox" style="margin-top:8px">Test connection</button>
          <span id="proxmox-status" style="margin-left:8px;font-size:12px"></span>
          ${renderStepButtons(8)}
        `);
      }

      function renderAlertingStep() {
        return card('Alerting', `
          <p style="font-size:13px;color:#666">Configure notification channels for findings and alerts.</p>
          <div style="margin-top:16px;padding:12px;background:#f0f0f0;border-radius:4px;font-size:12px">
            <p style="margin:0">Alert channel setup is delegated to <strong>Settings › Alerts</strong>. This step is informational.</p>
          </div>
          ${renderStepButtons(9)}
        `);
      }

      function renderUpdatesStep() {
        return card('Updates', `
          <p style="font-size:13px;color:#666">Configure automatic updates from a manifest URL.</p>
          <div style="margin-top:16px">
            <label>Manifest URL</label>
            <input id="manifest-url" type="text" placeholder="https://releases.example.com/flowsight/manifest.json" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
            <div class="small muted" style="margin-top:4px">Empty: use the official manifest.</div>
          </div>
          <div style="margin-top:12px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="auto-apply" type="checkbox">
              <span>Auto-apply updates</span>
            </label>
            <div class="small muted" style="margin-top:4px">Automatically download and install updates.</div>
          </div>
          ${renderStepButtons(10)}
        `);
      }

      function renderAPIAccessStep() {
        return card('API access', `
          <p style="font-size:13px;color:#666">
            The FlowSight API runs on ${esc(state.api_loopback ? '127.0.0.1 (localhost only)' : 'a LAN address')}.
            ${state.api_token_set ? '<span class="pill ok">API token configured</span>' : '<span class="pill bad">No API token</span>'}
          </p>
          <div style="margin-top:16px;padding:12px;background:#f0f0f0;border-radius:4px;font-size:12px">
            <p style="margin:0"><strong>API bind and port are core settings and read-only via the API.</strong></p>
            <p style="margin:8px 0 0 0">Edit the config file to change them:</p>
            <code style="display:block;background:white;padding:8px;margin-top:4px;border-radius:4px;font-size:11px;overflow-x:auto">
  "bind": "0.0.0.0", "port": 8080, "api_token": "token123"
            </code>
          </div>
          <p style="margin-top:12px;font-size:13px">For a token, generate one with:</p>
          <code style="display:block;background:#f0f0f0;padding:8px;border-radius:4px;font-size:11px;margin-top:4px;overflow-x:auto">
  base64 /dev/urandom | head -c 32
          </code>
          ${renderStepButtons(11)}
        `);
      }

      function renderReviewStep() {
        return card('Review & finish', `
          <p style="font-size:13px;color:#666">Review the steps and mark the wizard as completed.</p>
          <div style="margin-top:16px">
            <h4 style="margin:0 0 12px 0;font-size:13px">You have configured:</h4>
            <ul style="margin:0;padding:0 0 0 20px;font-size:12px">
              <li>Site basics (name, retention)</li>
              <li>Traffic source (ntopng)</li>
              <li>DNS source (Pi-hole or Unbound)</li>
              <li>Web interception (optional)</li>
              <li>Security (IDS, TLS probe)</li>
              <li>Inventory (Proxmox)</li>
              <li>Updates</li>
              <li>API access</li>
            </ul>
          </div>
          <p style="margin-top:16px;font-size:13px">
            Next steps: review each page under Settings to fine-tune, then create your first policy under Protect › Policies.
          </p>
          <div style="margin-top:16px;display:flex;gap:12px">
            <button class="btn primary" id="finish-wizard">Mark completed</button>
            <button class="btn" id="run-again">Run again</button>
          </div>
        `);
      }

      function renderCompletion() {
        const content = $('.wizard-content', el);
        content.innerHTML = card('Setup complete!', `
          <div style="text-align:center;padding:20px">
            <div style="font-size:48px;margin-bottom:12px">✓</div>
            <h2 style="margin:0 0 12px 0">Setup wizard completed</h2>
            <p style="color:#666;margin:0">Completed ${new Date(state.completed_at * 1000).toLocaleString()}</p>
            <div style="margin-top:20px;display:flex;gap:12px;justify-content:center">
              <a href="#overview" class="btn primary">Go to Overview</a>
              <button class="btn" id="run-again">Run wizard again</button>
            </div>
          </div>
        `);

        const runAgainBtn = $('#run-again', content);
        if (runAgainBtn) {
          runAgainBtn.onclick = async () => {
            await post('/api/setup/reset', {});
            currentStep = 1;
            state.completed = false;
            renderCurrentStep();
          };
        }
      }

      function renderStepButtons(step) {
        const isLast = step === 12;
        return `<div style="display:flex;gap:12px;margin-top:24px">
          ${step > 1 ? '<button class="btn" id="prev-btn">Previous</button>' : ''}
          <div style="flex:1"></div>
          <button class="btn" id="skip-btn">Skip</button>
          ${isLast ? '<button class="btn primary" id="next-btn">Finish</button>' : '<button class="btn primary" id="next-btn">Next</button>'}
        </div>`;
      }

      function attachStepHandlers(step) {
        const prevBtn = $(`#prev-btn`);
        const nextBtn = $(`#next-btn`);
        const skipBtn = $(`#skip-btn`);

        if (prevBtn) {
          prevBtn.onclick = () => {
            currentStep = Math.max(1, currentStep - 1);
            renderCurrentStep();
          };
        }

        if (skipBtn) {
          skipBtn.onclick = () => {
            currentStep = Math.min(12, currentStep + 1);
            renderCurrentStep();
          };
        }

        if (nextBtn) {
          nextBtn.onclick = async () => {
            // Collect form values
            const values = collectStepValues(step);
            if (!values) return; // Validation failed

            // Apply the step
            const result = await post('/api/setup/apply', { step, values });
            if (result.error) {
              FS.toast(result.error, true);
              return;
            }

            if (step === 12) {
              currentStep = 13;
            } else {
              currentStep = Math.min(12, currentStep + 1);
            }
            renderCurrentStep();
          };
        }

        // Attach step-specific handlers
        if (step === 1) attachLicenseHandlers(step);
        if (step === 3) attachTrafficSourceHandlers(step);
        if (step === 4) attachDNSSourceHandlers(step);
        if (step === 12) attachReviewHandlers(step);
      }

      function collectStepValues(step) {
        const values = {};
        switch (step) {
          case 1:
            break; // License handled separately
          case 2:
            values.site_name = $(`#site-name`).value;
            values.retention_days = parseInt($(`#retention-days`).value) || 7;
            values.memory_limit_mb = parseInt($(`#memory-limit`).value) || 256;
            break;
          case 3:
            values.ntopng_url = $(`#ntopng-url`).value;
            values.ntopng_username = $(`#ntopng-username`).value;
            values.ntopng_password = $(`#ntopng-password`).value;
            break;
          case 4:
            values.pihole_address = $(`#pihole-address`).value;
            values.pihole_token = $(`#pihole-token`).value;
            break;
          case 5:
            values.intercept = $(`#intercept-enable`).checked;
            const ifaces = [];
            $$('.intercept-iface:checked').forEach(cb => {
              ifaces.push(cb.dataset.iface);
            });
            values.interfaces = ifaces;
            break;
          case 6:
            break; // Delegated to identity module
          case 7:
            values.ids_enabled = $(`#ids-enable`).checked;
            values.tls_probe = $(`#tls-probe`).checked;
            break;
          case 8:
            values.proxmox_host = $(`#proxmox-host`).value;
            values.proxmox_token_id = $(`#proxmox-token-id`).value;
            values.proxmox_token_secret = $(`#proxmox-token-secret`).value;
            values.proxmox_fingerprint = $(`#proxmox-fingerprint`).value;
            break;
          case 9:
            break; // Delegated to alerting module
          case 10:
            values.manifest_url = $(`#manifest-url`).value;
            values.auto_apply = $(`#auto-apply`).checked;
            break;
          case 11:
            break; // API settings are read-only
          case 12:
            break; // Review step
        }
        return values;
      }

      function attachLicenseHandlers(step) {
        const testBtn = $(`#test-license`);
        if (testBtn) {
          testBtn.onclick = async () => {
            const key = $(`#license-key`).value.trim();
            if (!key) {
              FS.toast('Enter a license key', true);
              return;
            }
            const result = await post('/api/license/activate', { key });
            const status = $(`#license-status`);
            if (result.error) {
              status.textContent = '❌ ' + result.error;
              FS.toast(result.error, true);
            } else {
              status.textContent = '✓ License activated: ' + result.tier;
              FS.toast('License activated', false);
            }
          };
        }
      }

      function attachTrafficSourceHandlers(step) {
        const testBtn = $(`#test-ntopng`);
        if (testBtn) {
          testBtn.onclick = async () => {
            const url = $(`#ntopng-url`).value;
            if (!url) {
              FS.toast('Enter ntopng URL', true);
              return;
            }
            const username = $(`#ntopng-username`).value;
            const password = $(`#ntopng-password`).value;
            const result = await post('/api/setup/test', {
              step,
              values: { ntopng_url: url, ntopng_username: username, ntopng_password: password }
            });
            const status = $(`#ntopng-status`);
            if (result.error) {
              status.textContent = '❌ ' + result.error;
            } else if (result.ok) {
              status.textContent = '✓ Connected';
            }
          };
        }
      }

      function attachDNSSourceHandlers(step) {
        const testBtn = $(`#test-pihole`);
        if (testBtn) {
          testBtn.onclick = async () => {
            const addr = $(`#pihole-address`).value;
            if (!addr) {
              FS.toast('Enter Pi-hole address', true);
              return;
            }
            const token = $(`#pihole-token`).value;
            const result = await post('/api/setup/test', {
              step,
              values: { pihole_address: addr, pihole_token: token }
            });
            const status = $(`#pihole-status`);
            if (result.error) {
              status.textContent = '❌ ' + result.error;
            } else if (result.ok) {
              status.textContent = '✓ Connected';
            }
          };
        }

        const testProxBtn = $(`#test-proxmox`);
        if (testProxBtn) {
          testProxBtn.onclick = async () => {
            const host = $(`#proxmox-host`).value;
            const tokenId = $(`#proxmox-token-id`).value;
            const tokenSecret = $(`#proxmox-token-secret`).value;
            if (!host || !tokenId || !tokenSecret) {
              FS.toast('Enter all Proxmox fields', true);
              return;
            }
            const result = await post('/api/setup/test', {
              step: 8,
              values: {
                proxmox_host: host,
                proxmox_token_id: tokenId,
                proxmox_token_secret: tokenSecret
              }
            });
            const status = $(`#proxmox-status`);
            if (result.error) {
              status.textContent = '❌ ' + result.error;
            } else if (result.ok) {
              status.textContent = '✓ Connected';
            }
          };
        }
      }

      function attachReviewHandlers(step) {
        const finishBtn = $(`#finish-wizard`);
        if (finishBtn) {
          finishBtn.onclick = async () => {
            const result = await post('/api/setup/apply', { step: 12, values: {} });
            if (!result.error) {
              currentStep = 13;
              renderCurrentStep();
            }
          };
        }

        const runAgainBtn = $(`#run-again`);
        if (runAgainBtn) {
          runAgainBtn.onclick = async () => {
            await post('/api/setup/reset', {});
            currentStep = 1;
            state.completed = false;
            renderCurrentStep();
          };
        }
      }

      // Render the first step
      renderCurrentStep();
    }
  });
})();
