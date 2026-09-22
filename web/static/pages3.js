/* FlowSight pages: firewall hygiene, alerting, reports, updates, devices & zones. */
'use strict';
(function () {
  const { esc, num, bytes, ago, when, pill, card, kpi, table, bars, hostLink, domainLink, get, post } = FS;

  // ------------------------------------------------------------- Firewall hygiene
  FS.registerPage('firewall', {
    title: 'Firewall hygiene', refresh: 60,
    async render(el, ctx) {
      const [s, r, f, c] = await Promise.all([get('/api/rulehygiene/summary'), get('/api/rulehygiene/rules'), get('/api/rulehygiene/findings'), get('/api/rulehygiene/changes')]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const sev = s.by_severity || {};
      const score = Number(s.risk_score || 0);
      const kind = score >= 50 ? 'bad' : score >= 20 ? 'warn' : 'ok';
      const rules = r.rules || [];
      const findings = f.findings || [];
      el.innerHTML = `<div class="grid cols-4">${kpi('Risk score', score, 'lower is better; weighted open findings', kind)}${kpi('Rules analysed', num(s.rules_analysed), s.ruleset_loaded ? 'ruleset loaded ' + esc(s.ruleset_loaded) : '')}${kpi('Findings', num(findings.length), `${num(sev.critical || 0)} critical · ${num(sev.high || 0)} high · ${num(sev.medium || 0)} medium`, sev.critical ? 'bad' : sev.high ? 'warn' : '')}${card('Analysis', `<div class="small muted">Last run ${esc(s.last_run || 'never')}. Findings are grounded in live pf counters, so "unused" means never matched since the ruleset was loaded, not merely quiet today.</div><div class="actions"><button class="btn primary" id="run">Analyse now</button></div>`)}</div>
      <div style="margin-top:14px">${card('Findings', table(findings, [{ t: 'Severity', f: x => FS.sevPill(x.severity), sort: 'severity' }, { t: 'Kind', f: x => pill(x.kind), sort: 'kind' }, { t: 'Finding', f: x => `<b>${esc(x.title)}</b><div class="muted small">${esc(x.detail || '')}</div>` }, { t: 'Rule', f: x => `<span class="mono small">${esc(x.subject || '')}</span>` }, { t: 'Since', f: x => ago(x.ts), sort: 'ts' }]))}</div>
      <div style="margin-top:14px">${card('Rules with live counters', table(rules, [{ t: '#', f: x => x.index != null ? x.index : '', num: true, sort: 'index' }, { t: 'Rule', f: x => `<span class="mono small">${esc(x.rule || x.text || '')}</span>${x.description ? `<div class="small">${esc(x.description)}</div>` : ''}`, sort: 'rule' }, { t: 'Interface', k: 'interface' }, { t: 'Evaluations', f: x => num(x.evaluations), num: true, sort: 'evaluations' }, { t: 'Packets', f: x => num(x.packets), num: true, sort: 'packets' }, { t: 'Bytes', f: x => bytes(x.bytes), num: true, sort: 'bytes' }, { t: 'States', f: x => num(x.states), num: true, sort: 'states' }, { t: 'Findings', f: x => (x.findings || []).map(k => pill(k, 'warn')).join(' ') }]))}</div>
      <div style="margin-top:14px">${card('Ruleset changes', table(c.changes || [], [{ t: 'When', f: x => when(x.ts), sort: 'ts' }, { t: 'By', k: 'actor' }, { t: 'Summary', f: x => esc(x.summary || '') }, { t: '', f: x => x.diff_bytes ? `<button class="btn small" data-diff="${x.id}">diff</button>` : '' }]))}</div>`;
      FS.$('#run', el).onclick = async () => { const x = await post('/api/rulehygiene/run', {}); FS.toast(x.error || 'Analysis started', !!x.error); setTimeout(FS.render, 3000); };
      FS.$$('[data-diff]', el).forEach(b => b.onclick = async () => { const x = await get('/api/system/changes?id=' + b.dataset.diff); FS.modal(`<h2>${esc((x.change || {}).subject || 'change')}</h2><pre class="code">${FS.diffHtml((x.change || {}).diff || '')}</pre><div class="actions"><button class="btn" onclick="FS.closeModal()">Close</button></div>`); });
    }
  });

  // ------------------------------------------------------------- Alerting
  FS.registerPage('alerts', {
    title: 'Alerting', refresh: 60,
    async render(el) {
      const d = await get('/api/alerting/status'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const channels = d.channels || [];
      const rules = Object.values(d.rules || {});
      const TYPES = ['email', 'webhook', 'discord', 'slack', 'ntfy'];
      el.innerHTML = `<div class="grid cols-2">
        ${card('Channels', `<div class="actions"><button class="btn primary" id="ch-new">Add channel</button></div>` + table(channels, [{ t: 'Name', f: x => `<b>${esc(x.name)}</b>` }, { t: 'Type', f: x => pill(x.type, 'info') }, { t: 'Target', f: x => esc(x.to || x.url || x.topic || x.host || '') }, { t: '', f: x => `<button class="btn small" data-test="${esc(x.name)}">Test</button> <button class="btn small" data-edit="${esc(x.name)}">Edit</button> <button class="btn small danger" data-del="${esc(x.name)}">Delete</button>` }], { empty: 'No channels yet. Add email, a webhook, Discord, Slack or ntfy.' }))}
        ${card('Rules', table(rules, [{ t: 'On', f: x => `<input type="checkbox" data-rule="${esc(x.name)}" ${x.enabled ? 'checked' : ''}>` }, { t: 'Rule', f: x => `<b>${esc(x.subject || x.name)}</b><div class="muted small">${esc(x.kind)} · threshold ${x.threshold} in ${FS.dur(x.window || 0)} · cooldown ${FS.dur(x.cooldown || 0)}</div>` }, { t: 'Severity', f: x => FS.sevPill(x.severity) }, { t: 'Channels', f: x => (x.channels || []).length ? (x.channels || []).map(c => pill(c)).join(' ') : '<span class="muted small">all</span>' }]) + `<div class="actions"><button class="btn primary" id="rules-save">Save rules</button></div>`)}
      </div>
      <div style="margin-top:14px">${card('Recent notifications', table(d.notifications || [], [{ t: 'When', f: x => when(x.ts), sort: 'ts' }, { t: 'Rule', k: 'rule' }, { t: 'Subject', k: 'subject' }, { t: 'Channel', k: 'channel' }, { t: 'Result', f: x => x.ok ? pill('sent', 'ok') : pill(x.error || 'failed', 'bad') }]))}</div>`;
      const edit = (name) => {
        const ch = channels.find(x => x.name === name) || { type: 'email' };
        const fieldsFor = (type, v) => ({
          email: [['host', 'SMTP host'], ['port', 'Port'], ['user', 'User'], ['password', 'Password'], ['from', 'From'], ['to', 'To (comma separated)'], ['tls', 'TLS: starttls, implicit or none']],
          webhook: [['url', 'URL']], discord: [['url', 'Webhook URL']], slack: [['url', 'Incoming webhook URL']], ntfy: [['url', 'Topic URL (https://ntfy.sh/topic)'], ['token', 'Access token (optional)']]
        }[type] || []).map(([k, l]) => `<label>${esc(l)}</label><input type="text" name="${k}" value="${esc(v[k] == null ? '' : v[k])}" autocomplete="off">`).join('');
        FS.modal(`<h2>${name ? 'Edit' : 'Add'} channel</h2><form class="f"><label>Name</label><input type="text" name="name" value="${esc(ch.name || '')}" required><label>Type</label><select name="type">${TYPES.map(t => `<option ${t === ch.type ? 'selected' : ''}>${t}</option>`).join('')}</select><div id="cf">${fieldsFor(ch.type, ch)}</div><div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" onclick="FS.closeModal()">Cancel</button></div></form>`, (b) => {
          const f = FS.$('form', b);
          f.type.onchange = () => { FS.$('#cf', b).innerHTML = fieldsFor(f.type.value, {}); };
          f.onsubmit = async (e) => { e.preventDefault(); const o = { name: f.name.value.trim(), type: f.type.value }; FS.$$('#cf input', b).forEach(i => { o[i.name] = i.name === 'port' ? Number(i.value) : i.value; if (i.name === 'to') o.to = i.value.split(',').map(x => x.trim()).filter(Boolean); }); const next = channels.filter(x => x.name !== name && x.name !== o.name); next.push(o); const r = await post('/api/alerting/channels', { channels: next }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.render(); } };
        });
      };
      FS.$('#ch-new', el).onclick = () => edit(null);
      FS.$$('[data-edit]', el).forEach(b => b.onclick = () => edit(b.dataset.edit));
      FS.$$('[data-del]', el).forEach(b => b.onclick = async () => { if (!await FS.confirm(`Delete channel "${b.dataset.del}"?`)) return; const r = await post('/api/alerting/channels', { channels: channels.filter(x => x.name !== b.dataset.del) }); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$$('[data-test]', el).forEach(b => b.onclick = async () => { const r = await post('/api/alerting/channels/test', { name: b.dataset.test }); FS.toast(r.error || 'Test message sent', !!r.error); });
      FS.$('#rules-save', el).onclick = async () => { const out = {}; rules.forEach(x => { out[x.name] = { ...x, enabled: FS.$(`[data-rule="${x.name}"]`, el).checked }; }); const r = await post('/api/alerting/rules', { rules: out }); FS.toast(r.error || 'Rules saved', !!r.error); };
    }
  });

  // ------------------------------------------------------------- Reports
  FS.registerPage('reports', {
    title: 'Reports', refresh: 0,
    async render(el) {
      const d = await get('/api/reports/schedules'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const scheds = d.schedules || [];
      const link = (p) => FS.base ? FS.base + encodeURIComponent(p) : p;
      el.innerHTML = `<div class="grid cols-2">
        ${card('On demand', `<p class="small muted">A self-contained HTML report of the selected window: traffic, hosts, applications, web, DNS, threats, TLS and open findings. Export raw data as CSV.</p><div class="actions"><a class="btn primary" target="_blank" href="${link('/api/reports/preview?hours=' + FS.state.hours)}">Open report (${FS.state.hours}h)</a>${['flows', 'dns', 'alerts', 'hosts'].map(k => `<a class="btn" href="${link('/api/reports/export?kind=' + k + '&hours=' + FS.state.hours)}">${k}.csv</a>`).join('')}</div>`)}
        ${card('Scheduled reports', `<div class="actions"><button class="btn primary" id="new">New schedule</button></div>` + table(scheds, [{ t: 'Name', f: x => `<b>${esc(x.name)}</b>${x.enabled ? '' : ' ' + pill('off', 'warn')}` }, { t: 'Cadence', f: x => `${esc(x.cadence)} at ${String(x.hour).padStart(2, '0')}:00, last ${x.window}h` }, { t: 'Recipients', f: x => esc((x.recipients || []).join(', ')) }, { t: '', f: x => `<button class="btn small" data-run="${esc(x.name)}">Send now</button> <button class="btn small danger" data-del="${esc(x.name)}">Delete</button>` }], { empty: 'No schedules. Reports are emailed through the email channel configured under Alerting.' }))}
      </div>`;
      FS.$('#new', el).onclick = () => FS.modal(`<h2>New scheduled report</h2><form class="f"><label>Name</label><input type="text" name="name" required><div class="row"><div><label>Cadence</label><select name="cadence"><option>daily</option><option>weekly</option><option>monthly</option></select></div><div><label>Hour (0-23)</label><input type="number" name="hour" value="7" min="0" max="23"></div></div><div class="row"><div><label>Window (hours)</label><input type="number" name="window" value="24"></div><div><label>Recipients</label><input type="text" name="recipients" placeholder="a@example.com, b@example.com"></div></div><div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" onclick="FS.closeModal()">Cancel</button></div></form>`, (b) => { FS.$('form', b).onsubmit = async (e) => { e.preventDefault(); const f = e.target; const s = { name: f.name.value.trim(), cadence: f.cadence.value, hour: Number(f.hour.value), window: Number(f.window.value), recipients: f.recipients.value.split(',').map(x => x.trim()).filter(Boolean), enabled: true }; const r = await post('/api/reports/schedules', { schedules: [...scheds.filter(x => x.name !== s.name), s] }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.render(); } }; });
      FS.$$('[data-del]', el).forEach(b => b.onclick = async () => { const r = await post('/api/reports/schedules', { schedules: scheds.filter(x => x.name !== b.dataset.del) }); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$$('[data-run]', el).forEach(b => b.onclick = async () => { const r = await post('/api/reports/run?name=' + encodeURIComponent(b.dataset.run), { name: b.dataset.run }); FS.toast(r.error || 'Report sent', !!r.error); });
    }
  });

  // ------------------------------------------------------------- Updates
  FS.registerPage('updates', {
    title: 'Updates', refresh: 0,
    async render(el) {
      const d = await get('/api/updater/status'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      el.innerHTML = `<div class="grid cols-3">${kpi('Installed', esc(d.current_version), d.last_check > 0 ? 'checked ' + ago(d.last_check) : 'not checked yet')}${kpi('Latest', esc(d.latest_version || '—'), d.available ? (d.applicable ? 'update available' : 'available but not verifiable') : 'up to date', d.available ? 'warn' : 'ok')}${card('Actions', `<div class="actions"><button class="btn" id="check">Check now</button><button class="btn primary" id="apply" ${d.applicable ? '' : 'disabled'}>Install update</button><button class="btn" id="rollback">Roll back</button></div><div class="help">Updates are downloaded from the release manifest, verified by checksum and signature, swapped in atomically and the service restarted. The previous binary is kept for roll back.</div>`)}</div>
      ${d.notes ? `<div style="margin-top:14px">${card('Release notes', `<pre class="code">${esc(d.notes)}</pre>`)}</div>` : ''}${d.error ? `<div style="margin-top:14px">${card('Last error', `<div class="sev-high small">${esc(d.error)}</div>`)}</div>` : ''}`;
      FS.$('#check', el).onclick = async () => { const r = await post('/api/updater/check', {}); FS.toast(r.error || 'Checked', !!r.error); FS.render(); };
      FS.$('#apply', el).onclick = async () => { if (!await FS.confirm('Install the update and restart FlowSight?')) return; const r = await post('/api/updater/apply', {}); FS.toast(r.error || 'Updating… the service will restart', !!r.error); };
      FS.$('#rollback', el).onclick = async () => { if (!await FS.confirm('Roll back to the previous binary and restart?')) return; const r = await post('/api/updater/rollback', {}); FS.toast(r.error || 'Rolling back…', !!r.error); };
    }
  });

  // ------------------------------------------------------------- Devices (enrolment)
  // Shared loader: devices, zones and rules come from the enroll module; the
  // two pages cross-link on the zone id.
  const enrollLoad = async (zoneFilter) => {
    const [s, dv, z, ru] = await Promise.all([get('/api/enroll'), get('/api/enroll/devices' + (zoneFilter ? '?zone=' + encodeURIComponent(zoneFilter) : '')), get('/api/enroll/zones'), get('/api/enroll/rules')]);
    const zones = ((z && z.zones) || ((z && z.document) || {}).zones || []);
    const devices = (dv && dv.devices) || [];
    const mode = (s && s.mode) || (z && z.mode) || 'monitor';
    return { s, dv, z, ru, zones, devices, mode };
  };
  const zoneName = (zones, id) => { const zz = zones.find(x => x.id === id); return zz ? (zz.name || zz.id) : (id || ''); };
  const modeControls = (mode, el) => {
    FS.$('#mode', el).onclick = async () => { const next = mode === 'enforce' ? 'monitor' : 'enforce'; if (next === 'enforce' && !await FS.confirm('Enforce mode writes DHCP reservations and firewall isolation. Devices present now stay where they are; only new devices are placed. Continue?')) return; const r = await post('/api/enroll/mode', { mode: next }); FS.toast(r.error || 'Mode: ' + next, !!r.error); FS.render(); };
  };

  FS.registerPage('devices', {
    title: 'Devices', refresh: 30,
    async render(el, ctx) {
      const { s, zones, devices, mode } = await enrollLoad(ctx.params.zone);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const zoneOpts = (cur) => `<option value="">—</option>` + zones.map(x => `<option value="${esc(x.id)}" ${x.id === cur ? 'selected' : ''}>${esc(x.name || x.id)}</option>`).join('');
      const byZone = {}; devices.forEach(d => { byZone[d.zone || ''] = (byZone[d.zone || ''] || 0) + 1; });
      const unplaced = byZone[''] || 0;
      el.innerHTML = `<div class="grid cols-4">${kpi('Mode', mode === 'enforce' ? 'enforcing' : 'monitor', mode === 'enforce' ? 'placement and isolation are applied' : 'classifying only; nothing is written', mode === 'enforce' ? 'warn' : '')}${kpi('Devices', num(devices.length), `${num(s.unidentified || 0)} unidentified · ${num(unplaced)} without a zone`)}${kpi('Zones', num(zones.length), zones.map(x => `<a href="#zones?zone=${esc(x.id)}">${esc(x.id)}</a> ${num(byZone[x.id] || 0)}`).join(' · ') || 'none defined')}${card('Actions', `<div class="actions"><button class="btn" id="reconcile">Re-identify</button><a class="btn" href="#zones">Zones &amp; placement</a><button class="btn ${mode === 'enforce' ? 'danger' : ''}" id="mode">${mode === 'enforce' ? 'Switch to monitor' : 'Switch to enforce'}</button></div>`)}</div>
      <div style="margin-top:14px">${card('Devices' + (ctx.params.zone ? ` in zone ${esc(zoneName(zones, ctx.params.zone))}` : ''), table(devices, [{ t: 'Device', f: x => `<b>${esc(x.hostname || x.guest_name || x.mac)}</b><div class="muted small mono">${esc(x.mac)}${x.randomized ? ' · private MAC' : ''}</div>`, sort: 'hostname' }, { t: 'Address', f: x => x.ip ? FS.hostLink(x.ip) : '', sort: 'ip' }, { t: 'Vendor', f: x => esc(x.vendor || '') + (x.vendor_class ? `<div class="muted small">${esc(x.vendor_class)}</div>` : ''), sort: 'vendor' }, { t: 'Class', f: x => esc(x.class || ''), sort: 'class' }, { t: 'Zone', f: x => `<select data-mac="${esc(x.mac)}">${zoneOpts(x.zone)}</select>${x.zone ? ` <a class="small" href="#zones?zone=${esc(x.zone)}">view</a>` : ''}${x.pinned ? ' ' + pill('pinned', '') : ''}`, sort: 'zone' }, { t: 'Why', f: x => `<span class="small muted">${esc(x.why || x.rule || '')}</span>` }, { t: 'Seen', f: x => ago(x.last_seen), sort: 'last_seen' }]), ctx.params.zone ? `<a href="#devices">all devices</a>` : zones.map(x => `<a href="#devices?zone=${esc(x.id)}">${esc(x.id)}</a>`).join(' · '))}</div>
      <div class="help" style="margin-top:8px"><b>Devices</b> is the enrolment inventory: one row per physical device (by MAC) learned from DHCP, with a class and a zone, whether or not it is talking right now. <a href="#hosts">Hosts</a> is what traffic shows: one row per address seen in flows and DNS in the selected window, with its traffic. A device's address links to its host page. Addresses are shown by name when FlowSight knows one; with <a href="#modules/enrich">Settings › enrich</a> on, bare addresses gain their reverse-DNS name and country.</div>`;
      FS.$$('select[data-mac]', el).forEach(sel => sel.onchange = async () => { const r = await post('/api/enroll/assign', { mac: sel.dataset.mac, zone: sel.value }); FS.toast(r.error || 'Assigned', !!r.error); });
      FS.$('#reconcile', el).onclick = async () => { const r = await post('/api/enroll/reconcile', {}); FS.toast(r.error || 'Re-identified', !!r.error); FS.render(); };
      modeControls(mode, el);
    }
  });

  // ------------------------------------------------------------- Zones (enrolment)
  FS.registerPage('zones', {
    title: 'Zones', refresh: 0,
    async render(el, ctx) {
      const { s, z, ru, zones, devices, mode } = await enrollLoad('');
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const byZone = {}; devices.forEach(d => { (byZone[d.zone || ''] = byZone[d.zone || ''] || []).push(d); });
      const sel = ctx.params.zone || '';
      const zoneRows = zones.map(x => Object.assign({ count: (byZone[x.id] || []).length }, x));
      el.innerHTML = `<div class="grid cols-4">${kpi('Mode', mode === 'enforce' ? 'enforcing' : 'monitor', mode === 'enforce' ? 'placement and isolation are applied' : 'classifying only; nothing is written', mode === 'enforce' ? 'warn' : '')}${kpi('Zones', num(zones.length), `${num((byZone[''] || []).length)} devices without a zone`)}${kpi('Placed devices', num(devices.length - (byZone[''] || []).length), `of ${num(devices.length)}`)}${card('Actions', `<div class="actions"><button class="btn" id="plan">Plan placement</button><button class="btn primary" id="apply" ${mode === 'enforce' ? '' : 'disabled'}>Apply placement</button><a class="btn" href="#devices">Devices</a><button class="btn ${mode === 'enforce' ? 'danger' : ''}" id="mode">${mode === 'enforce' ? 'Switch to monitor' : 'Switch to enforce'}</button></div>`)}</div>
      <div style="margin-top:14px">${card('Zones', table(zoneRows, [{ t: 'Zone', f: x => `<b>${esc(x.name || x.id)}</b><div class="muted small mono">${esc(x.id)}</div>`, sort: 'id' }, { t: 'Subnet', f: x => `<span class="mono">${esc(x.subnet || x.cidr || '')}</span>` }, { t: 'Isolation', f: x => esc(x.isolation || x.policy || (x.isolate ? 'isolated' : '')) }, { t: 'Devices', f: x => `<a href="#devices?zone=${esc(x.id)}">${num(x.count)}</a>`, num: true, sort: 'count' }, { t: 'Members', f: x => (byZone[x.id] || []).slice(0, 6).map(d => d.ip ? FS.hostLink(d.ip, d.hostname || d.guest_name) : esc(d.hostname || d.mac)).join(', ') + ((byZone[x.id] || []).length > 6 ? ` … <a href="#devices?zone=${esc(x.id)}">all</a>` : '') }]), `<a href="#devices">devices without a zone: ${num((byZone[''] || []).length)}</a>`)}</div>
      ${sel && byZone[sel] ? `<div style="margin-top:14px">${card(`Devices in ${esc(zoneName(zones, sel))}`, table(byZone[sel], [{ t: 'Device', f: x => `<b>${esc(x.hostname || x.guest_name || x.mac)}</b><div class="muted small mono">${esc(x.mac)}</div>` }, { t: 'Address', f: x => x.ip ? FS.hostLink(x.ip) : '' }, { t: 'Class', k: 'class' }, { t: 'Seen', f: x => ago(x.last_seen) }]), `<a href="#devices?zone=${esc(sel)}">open in Devices</a>`)}</div>` : ''}
      <div class="grid cols-2" style="margin-top:14px">${card('Zones (zones.json)', `<form class="f" id="zf"><textarea name="doc" style="min-height:280px">${esc(JSON.stringify((z && (z.document || z)) || {}, null, 1))}</textarea><div class="actions"><button class="btn primary">Save zones</button></div></form>`)}${card('Classification rules (enroll-rules.json)', `<form class="f" id="rf"><textarea name="doc" style="min-height:280px">${esc(JSON.stringify((ru && (ru.document || ru)) || {}, null, 1))}</textarea><div class="actions"><button class="btn primary">Save rules</button></div></form>`)}</div>`;
      FS.$('#plan', el).onclick = async () => { const r = await get('/api/enroll/plan'); FS.modal(`<h2>Placement plan</h2><pre class="code">${esc(JSON.stringify(r, null, 1))}</pre><div class="actions"><button class="btn" onclick="FS.closeModal()">Close</button></div>`); };
      FS.$('#apply', el).onclick = async () => { if (!await FS.confirm('Apply device placement (DHCP reservations) and zone isolation now?')) return; const r = await post('/api/enroll/apply', {}); FS.modal(`<h2>Applied</h2><pre class="code">${esc(JSON.stringify(r, null, 1))}</pre><div class="actions"><button class="btn" onclick="FS.closeModal()">Close</button></div>`); };
      modeControls(mode, el);
      FS.$('#zf', el).onsubmit = async (e) => { e.preventDefault(); let doc; try { doc = JSON.parse(e.target.doc.value); } catch (x) { FS.toast('Invalid JSON: ' + x.message, true); return; } const r = await post('/api/enroll/zones', doc); FS.toast(r.error || 'Zones saved', !!r.error); FS.render(); };
      FS.$('#rf', el).onsubmit = async (e) => { e.preventDefault(); let doc; try { doc = JSON.parse(e.target.doc.value); } catch (x) { FS.toast('Invalid JSON: ' + x.message, true); return; } const r = await post('/api/enroll/rules', doc); FS.toast(r.error || 'Rules saved', !!r.error); };
    }
  });
  // Old deep links keep working.
  FS.registerPage('enroll', { title: 'Devices', refresh: 0, async render(el, ctx) { FS.go('#devices' + (ctx.params.zone ? '?zone=' + encodeURIComponent(ctx.params.zone) : '')); } });

  // ------------------------------------------------------------- Deep inspection
  FS.registerPage('deep', {
    title: 'Deep inspection', refresh: 15,
    async render(el, ctx) {
      const [s, r] = await Promise.all([get('/api/mitm/status'), get('/api/mitm/requests?limit=300' + (ctx.params.q ? '&q=' + encodeURIComponent(ctx.params.q) : ''))]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const state = !s.licensed ? pill('business tier', 'warn') : !s.enabled ? pill('off', '') : s.listening ? pill('inspecting', 'ok') : pill('not listening', 'bad');
      el.innerHTML = `<div class="grid cols-4">
        ${kpi('State', state, s.error ? esc(s.error) : (s.enabled ? `loopback port ${s.port}` : 'switch it on under Settings › mitm'))}
        ${kpi('Requests', num(s.requests), `${bytes(s.bytes_in)} in · ${bytes(s.bytes_out)} out`)}
        ${kpi('Decoded', num(s.decoded), 'DNS-over-HTTPS questions recovered')}
        ${card('Scope', `<div class="small">Clients: ${(s.clients || []).length ? (s.clients || []).map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : '<span class="muted">every client a policy decrypts</span>'}</div>
          <div class="small" style="margin-top:4px">Names: ${(s.names || []).length ? (s.names || []).map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : '<span class="muted">every name that is decrypted</span>'}</div>
          <div class="actions"><a class="btn" href="#modules/mitm">Settings</a><a class="btn" href="#tls">Pinned sites</a></div>`)}
      </div>
      <div style="margin-top:14px">${card('Recent requests', table(r.requests || [], [
        { t: 'When', f: x => when(x.ts), sort: 'ts' },
        { t: 'Client', f: x => FS.hostLink(x.client), sort: 'client' },
        { t: 'Request', f: x => `<span class="mono small">${esc(x.method)} ${esc(x.url)}</span>`, sort: 'url' },
        { t: 'Status', f: x => x.status ? pill(String(x.status), x.status >= 400 ? 'bad' : 'ok') : pill('failed', 'bad'), sort: 'status' },
        { t: 'Type', f: x => `<span class="small muted">${esc((x.content_type || '').split(';')[0])}</span>`, sort: 'content_type' },
        { t: 'Size', f: x => bytes(x.bytes_in), num: true, sort: 'bytes_in' },
        { t: 'Took', f: x => (x.ms || 0).toFixed(0) + ' ms', num: true, sort: 'ms' },
        { t: '', f: x => `<button class="btn small" data-det="${esc(JSON.stringify(x).replace(/"/g, '&quot;'))}">Headers</button>` },
      ]), `<span class="muted small">${esc(s.note || '')}</span>`)}</div>`;
      FS.$$('[data-det]', el).forEach(b => b.onclick = () => {
        const x = JSON.parse(b.dataset.det);
        FS.modal(`<h2>${esc(x.method)} ${esc(x.url)}</h2><pre class="code">${esc(Object.entries(x.headers || {}).map(([k, v]) => k + ': ' + v).join('\n') || 'headers were not recorded')}</pre>
          <div class="small muted">${esc(x.note || '')}</div><div class="actions"><button class="btn" onclick="FS.closeModal()">Close</button></div>`);
      });
    }
  });

})();
