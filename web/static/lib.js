/* FlowSight UI helpers. No framework, no build step, no CDN. */
'use strict';
const FS = window.FS = {};

// --------------------------------------------------------------- API
FS.base = window.FS_API_BASE || '';   // the OPNsense shim sets this to a proxy path
FS.api = async function (path, opts) {
  opts = opts || {};
  const url = FS.base ? FS.base + encodeURIComponent(path) : path;
  const init = { method: opts.method || 'GET', headers: { 'X-Requested-With': 'Flowsight' }, credentials: 'same-origin' };
  if (opts.body !== undefined) { init.method = init.method === 'GET' ? 'POST' : init.method; init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(opts.body); }
  if (window.FS_CSRF) init.headers['X-CSRFToken'] = window.FS_CSRF;
  let r;
  try { r = await fetch(url, init); } catch (e) { return { error: 'network error: ' + e.message }; }
  if (r.status === 401) { FS.needLogin(); return { error: 'authentication required' }; }
  const ct = r.headers.get('content-type') || '';
  if (!ct.includes('json')) { const t = await r.text(); return r.ok ? { text: t } : { error: t.slice(0, 200) || ('HTTP ' + r.status) }; }
  let d; try { d = await r.json(); } catch (e) { return { error: 'bad JSON from ' + path }; }
  if (!r.ok && !d.error) d.error = 'HTTP ' + r.status;
  if (r.status === 402 && d.locked) FS.lastLock = d;
  return d;
};
FS.lastLock = null;
// Auto-refresh: on by default, remembered per browser, and always held back
// while the reader is doing something (a dialog, a form field, a selection).
FS.autoRefresh = (() => { try { return localStorage.getItem('fs.autorefresh') !== '0'; } catch (e) { return true; } })();
FS.infiniteScroll = (() => { try { return localStorage.getItem('fs.infinite') === '1'; } catch (e) { return false; } })();
FS.setInfinite = (on) => { FS.infiniteScroll = !!on; try { localStorage.setItem('fs.infinite', on ? '1' : '0'); } catch (e) { } };
FS.setAutoRefresh = (on) => { FS.autoRefresh = !!on; try { localStorage.setItem('fs.autorefresh', on ? '1' : '0'); } catch (e) { } };
FS.refreshHeld = () => {
  if (!FS.autoRefresh) return true;
  const m = document.getElementById('modal'); if (m && !m.hidden) return true;
  const a = document.activeElement;
  if (a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) && a.id !== 'search') return true;
  const sel = window.getSelection && window.getSelection(); if (sel && String(sel).length > 4) return true;
  return false;
};
// "C=US; O=Google Trust Services; CN=WE1" -> "Google Trust Services · WE1"
FS.issuerName = (dn) => { const g = (k) => ((dn || '').match(new RegExp('(?:^|[;,]\\s*)' + k + '=([^;,]+)')) || [])[1] || ''; const o = g('O'), cn = g('CN'); return o && cn && o !== cn ? `${o} · ${cn}` : (cn || o || dn || ''); };
FS.tierName = (t) => ({ community: 'Community', pro: 'Pro', business: 'Business' })[t] || t;
FS.lockCard = (d) => `<div class="card lock"><h3>${FS.esc(FS.tierName(d.required || 'pro'))} feature</h3><p>${FS.esc(d.error || '')}</p><div class="actions"><a class="btn primary" href="#license">See license options</a></div></div>`;
FS.get = (p) => FS.api(p);
FS.post = (p, body) => FS.api(p, { body: body || {} });

// --------------------------------------------------------------- formatting
FS.esc = (s) => String(s == null ? '' : s).replace(/[&<>"'`]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));
FS.num = (n) => { n = Number(n || 0); if (Math.abs(n) >= 1e9) return (n / 1e9).toFixed(2) + 'B'; if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1) + 'M'; if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1) + 'k'; return n.toLocaleString(); };
FS.bytes = (b) => { b = Number(b || 0); const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; } return (i ? b.toFixed(b < 10 ? 2 : 1) : b) + ' ' + u[i]; };
FS.bps = (b) => { b = Number(b || 0); const u = ['bps', 'kbps', 'Mbps', 'Gbps']; let i = 0; while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; } return (i ? b.toFixed(b < 10 ? 2 : 1) : b.toFixed(0)) + ' ' + u[i]; };
FS.dur = (s) => { s = Number(s || 0); if (s < 60) return s.toFixed(s < 10 ? 1 : 0) + 's'; if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.floor(s % 60) + 's'; if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor(s % 3600 / 60) + 'm'; return Math.floor(s / 86400) + 'd ' + Math.floor(s % 86400 / 3600) + 'h'; };
FS.ago = (ts) => { if (!ts) return ''; const d = Date.now() / 1000 - Number(ts); if (d < 0) return 'now'; if (d < 60) return Math.floor(d) + 's ago'; if (d < 3600) return Math.floor(d / 60) + 'm ago'; if (d < 86400) return Math.floor(d / 3600) + 'h ago'; return Math.floor(d / 86400) + 'd ago'; };
FS.when = (ts) => { if (!ts) return ''; const d = new Date(Number(ts) * 1000); const now = new Date(); const t = d.toTimeString().slice(0, 8); return d.toDateString() === now.toDateString() ? t : d.toISOString().slice(5, 10) + ' ' + t; };
FS.pct = (a, b) => b ? Math.round(100 * a / b) + '%' : '0%';
FS.pill = (text, kind) => `<span class="pill ${kind || ''}">${FS.esc(text)}</span>`;
FS.sevPill = (s) => FS.pill(s, { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: '' }[s] || '');
FS.verdictPill = (v) => v === 'blocked' ? FS.pill('blocked', 'bad') : v === 'allowed' ? FS.pill('allowed', 'ok') : FS.pill(v || 'observed', '');
FS.hostLink = (ip, name) => ip ? `<a href="#host/${encodeURIComponent(ip)}" title="${FS.esc(ip)}" ${name ? '' : `data-ip="${FS.esc(ip)}"`}>${FS.esc(name || ip)}</a>${name ? ` <span class="muted mono small">${FS.esc(ip)}</span>` : ''}` : '';
// A bare address that enrichment may decorate with a reverse-DNS name and a country.
FS.ipTag = (ip, name) => ip ? (name ? `${FS.esc(name)} <span class="muted small mono">${FS.esc(ip)}</span>` : `<span class="mono" data-ip="${FS.esc(ip)}">${FS.esc(ip)}</span>`) : '';
FS.flag = (cc) => cc && /^[A-Z]{2}$/.test(cc) ? `<span class="cc" title="${cc}">${String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65))} ${cc}</span>` : '';
FS.enrichCache = {}; FS.enrichOn = null;
// Ask the enrich module for names and countries of every [data-ip] in el that has none yet, and decorate in place.
FS.enrichIn = async (el) => {
  if (FS.enrichOn === false) return;
  const nodes = FS.$$('[data-ip]:not([data-enriched])', el); if (!nodes.length) return;
  const want = [...new Set(nodes.map(n => n.dataset.ip).filter(ip => !FS.enrichCache[ip]))];
  if (want.length) {
    const r = await FS.post('/api/enrich/lookup', { ips: want });
    if (r.error) { if (r.error.includes('not found')) FS.enrichOn = false; return; }
    FS.enrichOn = !!(r.reverse_dns || r.geoip);
    if (!FS.enrichOn) return;
    Object.assign(FS.enrichCache, r.hosts || {});
    want.forEach(ip => { const h = r.hosts && r.hosts[ip]; if (h && !h.name && r.reverse_dns) h._retry = (FS.enrichCache[ip] && FS.enrichCache[ip]._retry || 0) + 1; });
  }
  nodes.forEach(n => {
    const ip = n.dataset.ip, h = FS.enrichCache[ip]; if (!h) return;
    if (h.name || h.country) {
      const isLink = n.tagName === 'A';
      n.innerHTML = `${h.name ? `${FS.esc(h.name)} <span class="muted small mono">${FS.esc(ip)}</span>` : FS.esc(ip)}${h.country ? ' ' + FS.flag(h.country) : ''}`;
      if (isLink) n.title = ip;
      n.setAttribute('data-enriched', '1');
    } else if ((h._retry || 0) > 2) n.setAttribute('data-enriched', '1'); // gave up on a name for this render cycle
  });
  // Names resolve in the background; look once more shortly after.
  if (nodes.some(n => !n.hasAttribute('data-enriched'))) { clearTimeout(FS._enrichTimer); FS._enrichTimer = setTimeout(() => FS.enrichIn(el), 2500); }
};
FS.domainLink = (d) => d ? `<a href="#flows?domain=${encodeURIComponent(d)}">${FS.esc(d)}</a>` : '<span class="muted">—</span>';

// --------------------------------------------------------------- DOM
FS.$ = (sel, root) => (root || document).querySelector(sel);
FS.$$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
FS.h = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
FS.toast = (msg, bad) => { const el = FS.h(`<div class="t ${bad ? 'bad' : ''}">${FS.esc(msg)}</div>`); FS.$('#toast').appendChild(el); setTimeout(() => el.remove(), bad ? 7000 : 3500); };
FS.modal = (html, onMount) => { const m = FS.$('#modal'); FS.$('#modal-body').innerHTML = html; m.hidden = false; m.onclick = (e) => { if (e.target === m) FS.closeModal(); }; if (onMount) onMount(FS.$('#modal-body')); };
FS.closeModal = () => { FS.$('#modal').hidden = true; FS.$('#modal-body').innerHTML = ''; };
FS.confirm = (text) => new Promise(res => { FS.modal(`<h2>Please confirm</h2><p>${FS.esc(text)}</p><div class="actions"><button class="btn primary" id="ok">Confirm</button><button class="btn" id="cancel">Cancel</button></div>`, (b) => { FS.$('#ok', b).onclick = () => { FS.closeModal(); res(true); }; FS.$('#cancel', b).onclick = () => { FS.closeModal(); res(false); }; }); });

// card(title, bodyHtml, rightHtml)
FS.card = (title, body, right) => `<div class="card"><h3>${FS.esc(title)}${right ? `<span class="right">${right}</span>` : ''}</h3>${body}</div>`;
FS.kpi = (label, value, sub, kind) => `<div class="card kpi ${kind || ''}"><h3>${FS.esc(label)}</h3><div class="v">${value}</div><div class="s">${sub || ''}</div></div>`;
FS.empty = (msg) => `<div class="empty">${FS.esc(msg || 'Nothing to show yet')}</div>`;
FS.err = (msg) => (FS.lastLock && msg === FS.lastLock.error) ? FS.lockCard(FS.lastLock) : `<div class="empty" style="color:var(--bad)">${FS.esc(msg)}</div>`;

// Horizontal bar list: rows [{label, value, sub, href}], max derived.
FS.bars = (rows, fmt) => {
  if (!rows || !rows.length) return FS.empty();
  const max = Math.max(...rows.map(r => Number(r.value) || 0), 1);
  fmt = fmt || FS.num;
  return rows.map(r => `<div class="barrow"><span class="lab">${r.href ? `<a href="${r.href}">${FS.esc(r.label)}</a>` : FS.esc(r.label)}${r.sub ? ` <span class="muted small">${FS.esc(r.sub)}</span>` : ''}</span><span class="num">${fmt(r.value)}</span><span class="bar"><i style="width:${Math.max(1, 100 * (Number(r.value) || 0) / max)}%"></i></span></div>`).join('');
};

// Sortable table. cols: [{k, t, f(row), num, w}]
// A table keeps its sort and its scroll position across the page's periodic
// refresh: both are remembered against the table's column signature, so a
// rebuilt table comes back exactly where the reader left it.
FS.tableState = {};
FS.table = (rows, cols, opts) => {
  opts = opts || {};
  if (!rows || !rows.length) return FS.empty(opts.empty);
  const id = 't' + Math.random().toString(36).slice(2, 8);
  const sig = opts.id || (FS.state.page + '|' + cols.map(c => c.t).join('|'));
  const st = FS.tableState[sig] || (FS.tableState[sig] = { i: -1, dir: -1, top: 0 });
  const order = (list, i, dir) => {
    const c = cols[i]; if (!c) return list;
    const key = c.sort || c.k;
    return [...list].sort((a, b) => { const x = key ? a[key] : (c.f ? c.f(a) : ''), y = key ? b[key] : (c.f ? c.f(b) : ''); if (x == null) return 1; if (y == null) return -1; return (typeof x === 'number' && typeof y === 'number') ? dir * (x - y) : dir * String(x).localeCompare(String(y), undefined, { numeric: true }); });
  };
  const bodyOf = (list) => list.map(r => '<tr>' + cols.map(c => `<td class="${c.num ? 'num' : ''} ${c.cls || ''}">${c.f ? c.f(r) : FS.esc(r[c.k])}</td>`).join('') + '</tr>').join('');
  const all = st.i >= 0 ? order(rows, st.i, st.dir) : rows;
  // Long tables are paged; the reader can switch to continuous scrolling,
  // which is remembered for every table in this browser.
  const pageSize = opts.pageSize || 100;
  if (st.shown == null) st.shown = pageSize;
  if (FS.infiniteScroll) st.shown = Math.max(st.shown, all.length);
  const shown = all.slice(0, Math.max(pageSize, st.shown));
  const head = cols.map((c, i) => `<th data-i="${i}" class="${c.num ? 'num' : ''} ${i === st.i ? 'sorted' + (st.dir > 0 ? ' asc' : '') : ''}" ${c.w ? `style="width:${c.w}"` : ''}>${FS.esc(c.t)}</th>`).join('');
  const more = all.length - shown.length;
  const foot = all.length > pageSize
    ? `<div class="tfoot"><span class="muted">${FS.num(shown.length)} of ${FS.num(all.length)}</span>${more > 0 ? `<button class="btn small" data-more="1">Show ${FS.num(Math.min(pageSize, more))} more</button><button class="btn small" data-all="1">Show all</button>` : ''}<label class="check inline"><input type="checkbox" data-inf="1" ${FS.infiniteScroll ? 'checked' : ''}><span>Infinite scroll</span></label></div>`
    : '';
  const html = `<div class="tablewrap" id="${id}" data-sig="${FS.esc(sig)}"><table><thead><tr>${head}</tr></thead><tbody>${bodyOf(shown)}</tbody></table></div>${foot}`;
  setTimeout(() => {
    const wrap = document.getElementById(id); if (!wrap) return;
    if (st.top) wrap.scrollTop = st.top;
    const box = wrap.parentNode;
    const grow = (n) => { st.shown = Math.min(all.length, (st.shown || pageSize) + n); const keep = wrap.scrollTop; FS.$('tbody', wrap).innerHTML = bodyOf(all.slice(0, st.shown)); wrap.scrollTop = keep; FS.enrichIn(wrap); const lbl = FS.$('.tfoot .muted', box); if (lbl) lbl.textContent = `${FS.num(st.shown)} of ${FS.num(all.length)}`; if (st.shown >= all.length) FS.$$('.tfoot .btn', box).forEach(b => b.remove()); };
    wrap.addEventListener('scroll', () => {
      st.top = wrap.scrollTop;
      if (FS.infiniteScroll && st.shown < all.length && wrap.scrollTop + wrap.clientHeight > wrap.scrollHeight - 200) grow(pageSize);
    }, { passive: true });
    const mb = FS.$('[data-more]', box); if (mb) mb.onclick = () => grow(pageSize);
    const ab = FS.$('[data-all]', box); if (ab) ab.onclick = () => grow(all.length);
    const inf = FS.$('[data-inf]', box); if (inf) inf.onchange = () => { FS.setInfinite(inf.checked); if (inf.checked) grow(all.length); };
    FS.$$('th', wrap).forEach(th => th.onclick = () => {
      const i = Number(th.dataset.i); const c = cols[i];
      if (st.i === i) st.dir = -st.dir; else { st.i = i; st.dir = c.num ? -1 : 1; }
      FS.$('tbody', wrap).innerHTML = bodyOf(order(rows, st.i, st.dir));
      FS.$$('th', wrap).forEach(t => t.classList.remove('sorted', 'asc')); th.classList.add('sorted'); if (st.dir > 0) th.classList.add('asc');
      FS.enrichIn(wrap);
    });
  }, 0);
  return html;
};

// --------------------------------------------------------------- charts (inline SVG)
FS.palette = ['#2f6fed', '#1f9d55', '#d97706', '#dc2626', '#7c3aed', '#0891b2', '#db2777', '#65a30d'];
// series: [{name, points:[[t,v],...], color}]; opts {fmt, stacked, height, area}
FS.chart = (series, opts) => {
  opts = opts || {};
  // The plot fills its box; a fixed pixel gutter (CSS) holds the axis labels.
  const W = 600, H = opts.height || 130, P = { l: 2, r: 2, t: 6, b: 2 };
  const all = series.flatMap(s => s.points || []);
  if (!all.length) return `<svg class="chart ${opts.tall ? 'tall' : ''}" viewBox="0 0 ${W} ${H}"><text x="${W / 2}" y="${H / 2}" text-anchor="middle" fill="var(--muted)" font-size="12">no data</text></svg>`;
  const xs = all.map(p => p[0]); const x0 = Math.min(...xs), x1 = Math.max(...xs) || x0 + 1;
  let ymax = 0;
  if (opts.stacked) { const sums = {}; series.forEach(s => (s.points || []).forEach(p => sums[p[0]] = (sums[p[0]] || 0) + Number(p[1] || 0))); ymax = Math.max(...Object.values(sums)); }
  else ymax = Math.max(...all.map(p => Number(p[1]) || 0));
  ymax = ymax || 1;
  const sx = t => P.l + (W - P.l - P.r) * (t - x0) / (x1 - x0 || 1);
  const sy = v => P.t + (H - P.t - P.b) * (1 - v / ymax);
  const fmt = opts.fmt || FS.num;
  // The SVG holds only lines and areas and stretches to its box; axis text is
  // HTML placed by percentage, so it stays crisp at any width or height.
  let labels = '';
  let out = `<svg class="chart ${opts.tall ? 'tall' : ''}" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">`;
  for (let i = 0; i <= 3; i++) { const v = ymax * i / 3; out += `<line x1="${P.l}" x2="${W - P.r}" y1="${sy(v)}" y2="${sy(v)}" stroke="var(--line)" stroke-width="1" vector-effect="non-scaling-stroke"/>`; labels += `<span class="yl" style="top:${(100 * sy(v) / H).toFixed(2)}%">${FS.esc(fmt(v))}</span>`; }
  const base = {};
  series.forEach((s, si) => {
    const color = s.color || FS.palette[si % FS.palette.length];
    const pts = (s.points || []).slice().sort((a, b) => a[0] - b[0]);
    if (!pts.length) return;
    let d = '', dArea = '';
    pts.forEach((p, i) => { const b = opts.stacked ? (base[p[0]] || 0) : 0; const y = sy(b + Number(p[1] || 0)); d += (i ? 'L' : 'M') + sx(p[0]).toFixed(1) + ',' + y.toFixed(1); if (opts.stacked) base[p[0]] = b + Number(p[1] || 0); });
    if (opts.area || opts.stacked) { dArea = d + `L${sx(pts[pts.length - 1][0]).toFixed(1)},${sy(0)}L${sx(pts[0][0]).toFixed(1)},${sy(0)}Z`; out += `<path d="${dArea}" fill="${color}" fill-opacity="${opts.stacked ? .55 : .12}" stroke="none"/>`; }
    out += `<path d="${d}" fill="none" stroke="${color}" stroke-width="1.6" vector-effect="non-scaling-stroke"/>`;
  });
  const t0 = new Date(x0 * 1000), t1 = new Date(x1 * 1000); const span = x1 - x0;
  const lab = (t) => span > 86400 * 2 ? t.toISOString().slice(5, 10) : t.toTimeString().slice(0, 5);
  out += '</svg>';
  labels += `<span class="xl">${lab(t0)}</span><span class="xl right">${lab(t1)}</span>`;
  return `<div class="chartbox ${opts.tall ? 'tall' : ''}">${out}<div class="chartlabels">${labels}</div></div>`;
};
FS.legend = (names) => `<div class="legend">${names.map((n, i) => `<span><i style="background:${FS.palette[i % FS.palette.length]}"></i>${FS.esc(n)}</span>`).join('')}</div>`;
// donut: rows [{label, value}]
FS.donut = (rows, fmt) => {
  rows = (rows || []).filter(r => Number(r.value) > 0).slice(0, 8);
  const total = rows.reduce((a, r) => a + Number(r.value), 0);
  if (!total) return FS.empty();
  let a0 = -Math.PI / 2, paths = '';
  rows.forEach((r, i) => { const a1 = a0 + 2 * Math.PI * Number(r.value) / total; const big = a1 - a0 > Math.PI ? 1 : 0; const x0 = 50 + 40 * Math.cos(a0), y0 = 50 + 40 * Math.sin(a0), x1 = 50 + 40 * Math.cos(a1), y1 = 50 + 40 * Math.sin(a1); paths += `<path d="M${x0},${y0}A40,40,0,${big},1,${x1},${y1}" fill="none" stroke="${FS.palette[i % 8]}" stroke-width="14"><title>${FS.esc(r.label)}: ${FS.esc((fmt || FS.num)(r.value))}</title></path>`; a0 = a1; });
  return `<div style="display:flex;gap:16px;align-items:center"><svg viewBox="0 0 100 100" style="width:110px;height:110px;flex:none">${paths}</svg><div class="small" style="min-width:0">${rows.map((r, i) => `<div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><i class="dot" style="background:${FS.palette[i % 8]}"></i>${FS.esc(r.label)} <span class="muted">${FS.esc((fmt || FS.num)(r.value))} · ${FS.pct(r.value, total)}</span></div>`).join('')}</div></div>`;
};

// --------------------------------------------------------------- state
FS.state = { hours: Number(localStorage.getItem('fs.hours') || 24), page: '', params: {} };
FS.setHours = (h) => { FS.state.hours = h; try { localStorage.setItem('fs.hours', h); } catch (e) {} FS.render(); };
FS.since = () => `hours=${FS.state.hours}`;
FS.pages = {};
FS.registerPage = (id, def) => { FS.pages[id] = def; };

// Query helpers for hash routes: #flows?ip=1.2.3.4
FS.parseHash = () => { const h = location.hash.replace(/^#/, '') || 'overview'; const [pathPart, q] = h.split('?'); const parts = pathPart.split('/'); const params = {}; (q || '').split('&').forEach(kv => { if (!kv) return; const [k, v] = kv.split('='); params[decodeURIComponent(k)] = decodeURIComponent(v || ''); }); return { page: parts[0], arg: parts.slice(1).map(decodeURIComponent).join('/'), params }; };
FS.go = (hash) => { location.hash = hash; };

// Settings form renderer for module schemas.
FS.settingsForm = (mod) => {
  const s = mod.settings || {};
  const eff = mod.effective || {};
  const empty = (v) => v == null || v === '' || (Array.isArray(v) && v.length === 0);
  const using = (f) => {
    const v = s[f.key]; if (!empty(v) || eff[f.key] == null || eff[f.key] === '') return '';
    const e = Array.isArray(eff[f.key]) ? eff[f.key].join(', ') : String(eff[f.key]);
    return `<div class="help using">Using: <span class="mono">${FS.esc(e)}</span></div>`;
  };
  const field = (f) => {
    const v = s[f.key];
    let input;
    switch (f.type) {
      case 'bool': input = `<div class="check"><input type="checkbox" name="${f.key}" ${v ? 'checked' : ''}><span>${FS.esc(f.label)}</span></div>`; return `<div>${input}${f.help ? `<div class="help">${FS.esc(f.help)}</div>` : ''}</div>`;
      case 'int': input = `<input type="number" name="${f.key}" value="${FS.esc(v)}">`; break;
      case 'choice': input = `<select name="${f.key}">${(f.choices || []).map(c => `<option ${c === v ? 'selected' : ''}>${FS.esc(c)}</option>`).join('')}</select>`; break;
      case 'list': input = `<textarea name="${f.key}" data-type="list" placeholder="one per line">${FS.esc((v || []).join('\n'))}</textarea>`; break;
      case 'text': input = `<textarea name="${f.key}">${FS.esc(v)}</textarea>`; break;
      case 'secret': input = `<input type="text" name="${f.key}" value="${FS.esc(v)}" autocomplete="off">`; break;
      default: input = `<input type="text" name="${f.key}" value="${FS.esc(v == null ? '' : v)}" placeholder="${FS.esc(f.placeholder || '')}">`;
    }
    return `<label>${FS.esc(f.label)}${f.restart ? ' <span class="muted">(restart)</span>' : ''}</label>${input}${f.help ? `<div class="help">${FS.esc(f.help)}</div>` : ''}${using(f)}`;
  };
  return `<form class="f" data-module="${FS.esc(mod.name)}">${(mod.schema || []).map(field).join('')}<div class="actions"><button class="btn primary" type="submit">Save</button></div></form>`;
};
FS.readForm = (form, schema) => {
  const out = {};
  (schema || []).forEach(f => {
    const el = form.elements[f.key]; if (!el) return;
    if (f.type === 'bool') out[f.key] = el.checked;
    else if (f.type === 'int') out[f.key] = Number(el.value);
    else if (f.type === 'list') out[f.key] = el.value.split(/\n|,/).map(x => x.trim()).filter(Boolean);
    else out[f.key] = el.value;
  });
  return out;
};
FS.diffHtml = (d) => FS.esc(d || '').split('\n').map(l => l.startsWith('+') ? `<span class="add">${l}</span>` : l.startsWith('-') ? `<span class="del">${l}</span>` : l).join('\n');
