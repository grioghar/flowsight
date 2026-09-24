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
// An address cell: the address itself, with whatever host or device name
// FlowSight knows beneath it. The Web page shows the name first and the
// address beneath; here it is the other way round, which is what the
// address-led tables want.
FS.addrCell = (ip, name) => {
  if (!ip) return '';
  const known = name || (FS.enrichCache[ip] || {}).name || '';
  return `<a href="#host/${encodeURIComponent(ip)}" class="mono" ${known ? '' : `data-ip="${FS.esc(ip)}"`}>${FS.esc(ip)}</a>` +
    (known ? `<div class="muted small">${FS.esc(known)}</div>` : '<div class="muted small ipname" data-name-for="' + FS.esc(ip) + '"></div>');
};
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
    // Fill the small name line under an address cell when one is known.
    FS.$$(`[data-name-for="${CSS.escape(ip)}"]`).forEach(s => { if (h.name) s.textContent = h.name; });
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
FS.modal = (html, onMount) => { const m = FS.$('#modal'); FS.$('#modal-body').innerHTML = html; m.hidden = false; FS.placeModal(); m.onclick = (e) => { if (e.target === m) FS.closeModal(); }; if (onMount) onMount(FS.$('#modal-body')); };
FS.closeModal = () => { FS.$('#modal').hidden = true; FS.$('#modal-body').innerHTML = ''; };
// Inside the OPNsense panel this document has no scrollbar of its own and can
// be many screens tall, so a dialog pinned to its top opens far above whatever
// the reader was looking at, and they have to scroll up to find it. The host
// page reports which slice of the frame is on screen; put the dialog over that
// slice instead, and keep it there while they scroll.
FS.placeModal = () => {
  const m = FS.$('#modal'); if (!m || m.hidden) return;
  if (!FS.embedded || !FS.hostView) { m.style.transform = ''; m.style.bottom = ''; m.style.height = ''; return; }
  // It stays position:fixed, which keeps it out of this document's height:
  // the host sizes the frame from that, and an overlay that counted would
  // make the frame grow every time a dialog opened. Sliding it is enough.
  m.style.transform = 'translateY(' + Math.max(0, FS.hostView.top) + 'px)';
  m.style.bottom = 'auto';
  m.style.height = FS.hostView.height + 'px';
};
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
  return rows.map(r => `<div class="barrow"><span class="lab" title="${FS.esc(r.title || r.label)}">${r.href ? `<a href="${r.href}">${FS.esc(r.label)}</a>` : FS.esc(r.label)}${r.sub ? ` <span class="muted small">${FS.esc(r.sub)}</span>` : ''}</span><span class="num">${fmt(r.value)}</span><span class="bar"><i style="width:${Math.max(1, 100 * (Number(r.value) || 0) / max)}%"></i></span></div>`).join('');
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
  // opts.rowAttr(row) lets a page mark rows it wants to react to; paging
  // rebuilds the body from the same function, so the marks survive.
  const bodyOf = (list) => list.map(r => `<tr ${opts.rowAttr ? opts.rowAttr(r) : ''}>` + cols.map(c => `<td class="${c.num ? 'num' : ''} ${c.cls || ''}">${c.f ? c.f(r) : FS.esc(r[c.k])}</td>`).join('') + '</tr>').join('');
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
    // No scroller of its own (inside a host GUI): follow the page instead.
    if (FS.onScroll) FS.onScroll((bottom) => {
      if (!document.body.contains(wrap)) return false; // drop the watcher with the table
      if (!FS.infiniteScroll || st.shown >= all.length) return true;
      if (wrap.scrollHeight > wrap.clientHeight + 4) return true; // it scrolls itself
      const end = wrap.getBoundingClientRect().bottom + (window.scrollY || 0);
      if (end - 300 < bottom) grow(pageSize);
      return true;
    });
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

// strip: one stacked bar with an inline legend. Two donuts side by side cost
// a third of a screen to say "almost everything is TLS 1.3"; this says the
// same in two lines, and the exact numbers are in the tooltips.
FS.strip = (rows, fmt) => {
  rows = (rows || []).filter(r => Number(r.value) > 0).sort((a, b) => b.value - a.value).slice(0, 8);
  const total = rows.reduce((a, r) => a + Number(r.value), 0);
  if (!total) return FS.empty();
  const seg = rows.map((r, i) => `<span class="seg" style="width:${(100 * r.value / total).toFixed(2)}%;background:${FS.palette[i % 8]}" title="${FS.esc(r.label)}: ${FS.esc((fmt || FS.num)(r.value))} (${FS.pct(r.value, total)})"></span>`).join('');
  const leg = rows.map((r, i) => `<span class="lg"><i class="dot" style="background:${FS.palette[i % 8]}"></i>${FS.esc(r.label)} <span class="muted">${FS.pct(r.value, total)}</span></span>`).join('');
  return `<div class="strip">${seg}</div><div class="striplegend small">${leg}</div>`;
};

// Equirectangular projection: longitude straight onto x, latitude onto y.
// It distorts area badly towards the poles and that is fine here, because
// the coordinates being plotted are themselves approximate and the point is
// relative position, not cartography.
FS.project = (lat, lon, w, h) => [(Number(lon) + 180) / 360 * w, (90 - Number(lat)) / 180 * h];

// A graticule, not a map of land. Drawing coastlines would imply the points
// are accurate to a coastline, and for router addresses they are not.
FS.graticule = (w, h, step) => {
  step = step || 30;
  let out = '';
  for (let lon = -180; lon <= 180; lon += step) {
    const x = (lon + 180) / 360 * w;
    out += `<line x1="${x.toFixed(1)}" y1="0" x2="${x.toFixed(1)}" y2="${h}" class="grat"/>`;
    if (lon > -180 && lon < 180) out += `<text x="${x.toFixed(1)}" y="${h - 3}" class="gratlabel">${lon}&deg;</text>`;
  }
  for (let lat = -90; lat <= 90; lat += step) {
    const y = (90 - lat) / 180 * h;
    out += `<line x1="0" y1="${y.toFixed(1)}" x2="${w}" y2="${y.toFixed(1)}" class="grat"/>`;
    if (lat > -90 && lat < 90) out += `<text x="3" y="${(y - 3).toFixed(1)}" class="gratlabel">${lat}&deg;</text>`;
  }
  return out;
};

// Wheel to zoom, drag to pan, by rewriting the viewBox. Kept here because
// more than one page will want it.
//
// Rewriting the viewBox scales everything inside it, which is right for the
// geography and wrong for everything drawn on top of it. Zoomed in four times,
// a one-pixel coastline becomes four and a three-pixel dot becomes twelve, so
// the detail you zoomed in to see is covered by the markers pointing at it.
// The scale is therefore published two ways: as --z on the element, for stroke
// widths and type to divide by, and to an onZoom callback for anything that
// has to be set as an attribute. Callers that ignore both get the old
// behaviour.
FS.panZoom = (svg, w, h, opts) => {
  if (!svg) return;
  if (typeof opts === 'function') opts = { onZoom: opts };
  opts = opts || {};
  const onZoom = opts.onZoom;
  const view = { x: 0, y: 0, w: w, h: h };
  // The viewBox has to match the shape of the box it is drawn in.
  //
  // With preserveAspectRatio="meet", a viewBox narrower than its container is
  // fitted by height, and the extra width comes from outside the viewBox --
  // which on a map drawn three times for wrapping is the neighbouring copy of
  // the world. Widen the window and the same continent appears twice. Taking
  // the height from the element rather than from the world's proportions
  // keeps the two in step, so what is on screen is exactly what the viewBox
  // asked for.
  const aspect = () => {
    const r = svg.getBoundingClientRect();
    return r.width > 0 && r.height > 0 ? r.height / r.width : h / w;
  };
  // A world map is a cylinder: pan far enough east and you arrive back in the
  // west. The caller says so with wrapX, and draws its content three times, a
  // world apart, so there is always something either side of the edge. All
  // this has to do is keep the view near the middle copy, which it can do by
  // whole worlds at a time -- a shift of exactly one world is invisible,
  // because the copy it lands on is identical to the one it left.
  const rewrap = () => {
    if (!opts.wrapX) return;
    while (view.x + view.w / 2 < 0) view.x += w;
    while (view.x + view.w / 2 >= w) view.x -= w;
  };
  const apply = () => {
    if (opts.wrapX) {
      // Wider than one world: there is nothing either side to pan to, so the
      // world is centred and the copies are taken away.
      const whole = view.w > w + 0.5;
      if (whole) {
        view.x = (w - view.w) / 2;
        view.y = (h - view.h) / 2;
      }
      svg.classList.toggle('whole', whole);
    }
    svg.setAttribute('viewBox', `${view.x} ${view.y} ${view.w} ${view.h}`);
    const z = w / view.w;
    svg.style.setProperty('--z', z);
    if (onZoom) onZoom(z);
  };
  // How far out you may zoom.
  //
  // Far enough to see the whole thing, and no further. On a wide window that
  // is wider than one world -- a two-to-one map cannot show pole to pole in a
  // three-to-one box without it -- so past one world the repeated copies are
  // hidden and the extra width is empty space. Blank margins are honest;
  // the same continent at both edges is not.
  const maxOut = () => opts.wrapX ? Math.max(w, h / aspect()) : w * 4;
  const clampW = (x) => Math.min(maxOut(), Math.max(w / 40, x));
  // Where a point on screen falls in the drawing, as a fraction of each side.
  const frac = (cx, cy) => {
    const r = svg.getBoundingClientRect();
    return [(cx - r.left) / r.width, (cy - r.top) / r.height];
  };
  // Zoom about a point, leaving whatever is under it where it is.
  const zoomAt = (nw, fx, fy) => {
    nw = clampW(nw);
    const nh = nw * aspect();
    view.x += (view.w - nw) * fx; view.y += (view.h - nh) * fy;
    view.w = nw; view.h = nh; apply();
  };

  svg.addEventListener('wheel', (e) => {
    e.preventDefault();
    const [fx, fy] = frac(e.clientX, e.clientY);
    zoomAt(view.w * (e.deltaY > 0 ? 1.15 : 1 / 1.15), fx, fy);
  }, { passive: false });

  // Touch and pen go through pointer events, which carry mouse too, so there
  // is one path rather than two that have to agree. One finger pans; two
  // pinch, and because the midpoint is tracked as well as the spread, a
  // two-finger drag pans at the same time -- which is what people do, rather
  // than pinching and dragging as separate motions.
  //
  // The gesture is re-based every time a finger lands or lifts. Without that,
  // lifting one finger of a pinch leaves the remaining one anchored to a
  // position it no longer has, and the map jumps.
  if (typeof window !== 'undefined' && window.PointerEvent) {
    const pts = new Map();
    let g = null;
    const spread = (a, b) => Math.hypot(a.x - b.x, a.y - b.y) || 1;
    const rebase = () => {
      const ps = [...pts.values()];
      if (ps.length === 1) {
        g = { mode: 'pan', x: ps[0].x, y: ps[0].y, vx: view.x, vy: view.y };
      } else if (ps.length > 1) {
        const [a, b] = ps;
        const [fx, fy] = frac((a.x + b.x) / 2, (a.y + b.y) / 2);
        g = {
          mode: 'pinch', d: spread(a, b),
          // The content under the midpoint when the pinch began. It has to
          // stay under the midpoint however the fingers move.
          cx: view.x + fx * view.w, cy: view.y + fy * view.h,
          w: view.w
        };
      } else {
        g = null;
      }
    };
    // Capture is taken only once a gesture is clearly a drag, never on the
    // way down. A captured pointer makes the browser retarget the click that
    // follows to the element holding the capture, so capturing every touch
    // would send every tap to the map instead of to the hop under the finger
    // -- and on a touchscreen there is no hover to fall back on, so the hop
    // cards would simply stop opening.
    const SLOP = 4;
    const grab = (id) => {
      if (svg.setPointerCapture && !(svg.hasPointerCapture && svg.hasPointerCapture(id))) {
        svg.setPointerCapture(id);
      }
    };
    svg.addEventListener('pointerdown', (e) => {
      pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      rebase();
      if (pts.size > 1) {
        // Two fingers is never a tap, so there is nothing to protect.
        pts.forEach((_, id) => grab(id));
        svg.style.cursor = 'grabbing';
      }
    });
    const release = (e) => {
      pts.delete(e.pointerId);
      if (svg.releasePointerCapture && svg.hasPointerCapture && svg.hasPointerCapture(e.pointerId)) {
        svg.releasePointerCapture(e.pointerId);
      }
      rebase();
      if (!pts.size) svg.style.cursor = 'grab';
    };
    svg.addEventListener('pointerup', release);
    svg.addEventListener('pointercancel', release);
    svg.addEventListener('pointermove', (e) => {
      if (!pts.has(e.pointerId)) return;
      pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (!g) return;
      if (g.mode === 'pan') {
        // Below the slop this is a tap that wobbled, and moving the map under
        // it would both jitter the view and cost the reader their tap.
        if (!g.dragging && Math.hypot(e.clientX - g.x, e.clientY - g.y) < SLOP) return;
        if (!g.dragging) { g.dragging = true; grab(e.pointerId); svg.style.cursor = 'grabbing'; }
        const r = svg.getBoundingClientRect();
        view.x = g.vx - (e.clientX - g.x) * (view.w / r.width);
        view.y = g.vy - (e.clientY - g.y) * (view.h / r.height);
        apply();
        return;
      }
      const ps = [...pts.values()];
      if (ps.length < 2) return;
      const [a, b] = ps;
      const nw = clampW(g.w * (g.d / spread(a, b)));
      const nh = nw * aspect();
      const [fx, fy] = frac((a.x + b.x) / 2, (a.y + b.y) / 2);
      view.w = nw; view.h = nh;
      view.x = g.cx - fx * nw; view.y = g.cy - fy * nh;
      apply();
    });
  } else {
    // No pointer events: mouse only, as before.
    let drag = null;
    svg.addEventListener('mousedown', (e) => { drag = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }; });
    window.addEventListener('mouseup', () => { drag = null; });
    svg.addEventListener('mousemove', (e) => {
      if (!drag) return;
      const r = svg.getBoundingClientRect();
      view.x = drag.vx - (e.clientX - drag.x) * (view.w / r.width);
      view.y = drag.vy - (e.clientY - drag.y) * (view.h / r.height);
      apply();
    });
  }

  // Set while a move is in flight, so nothing else moves the view under it.
  let frame = null;

  // Where a full view sits when the box is not the shape of the world.
  //
  // A short, wide window cannot show a two-to-one world whole without either
  // repeating it sideways or letterboxing it, and repeating is what this map
  // must never do. So it crops top and bottom -- but centred on the equator,
  // not anchored to the north pole. Anchored, a wide window lost the whole
  // southern hemisphere: South America and Australia simply were not there.
  // The whole world, pole to pole, letterboxed rather than cropped.
  const home = () => {
    const a = aspect();
    view.w = Math.max(w, h / a);
    view.h = view.w * a;
    view.x = (w - view.w) / 2;
    view.y = (h - view.h) / 2;
  };
  svg.style.cursor = 'grab';
  home();
  apply();
  // A window that changes shape changes the answer, so the viewBox is put
  // back in step rather than left to drift into the copy next door.
  //
  // Both a ResizeObserver and a window listener, because the observer was
  // seen not to fire on a pane that resized: the element's box changed, the
  // viewBox kept the shape it had, and the map went back to showing more than
  // one world. One of the two will always catch it, and reshape() does
  // nothing when nothing has changed.
  {
    let last = 0;
    const reshape = () => {
      // Never while a move is in flight. The observer fires after layout,
      // which on a fresh page is a moment after the first click may already
      // have started travelling somewhere -- and putting the view back to the
      // whole world mid-flight left the animation interpolating towards a
      // target from a position that no longer existed, landing nowhere near
      // the hop that was clicked.
      if (frame) return;
      const a = aspect();
      if (a <= 0 || Math.abs(a - last) < 0.0005) return;
      const first = last === 0;
      last = a;
      if (first || view.w > w + 0.5) {
        home(); // still showing everything; keep showing everything
      } else {
        // Keep what is in the middle in the middle as the shape changes.
        const cy = view.y + view.h / 2;
        view.h = view.w * a;
        view.y = cy - view.h / 2;
      }
      apply();
    };
    if (typeof ResizeObserver === 'function') new ResizeObserver(reshape).observe(svg);
    if (typeof window !== 'undefined' && window.addEventListener) {
      window.addEventListener('resize', reshape);
    }
  }

  // Going somewhere, visibly.
  //
  // A jump cut leaves the reader to work out what moved and which way, which
  // on a map that wraps is exactly the thing they cannot work out. Travelling
  // there shows the direction, and on a cylinder the direction is the whole
  // point: a route from Kansas to Tokyo goes west across the Pacific, and a
  // map that snapped eastward across Europe to get there would be showing the
  // long way round as though it were the short one.
  const stop = () => { if (frame && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(frame); frame = null; };
  const centre = () => [view.x + view.w / 2, view.y + view.h / 2];
  const moveTo = (cx, cy, nw, ms) => {
    stop();
    nw = clampW(nw == null ? view.w : nw);
    const nh = nw * aspect();
    const from = { x: view.x, y: view.y, w: view.w, h: view.h };
    const to = { x: cx - nw / 2, y: cy - nh / 2, w: nw, h: nh };
    const dur = ms == null ? 420 : ms;
    if (!dur || typeof requestAnimationFrame !== 'function') {
      view.x = to.x; view.y = to.y; view.w = to.w; view.h = to.h; rewrap(); apply(); return;
    }
    const t0 = (typeof performance === 'object' && performance.now) ? performance.now() : Date.now();
    const step = (now) => {
      const p = Math.min(1, (now - t0) / dur);
      // Ease out: quick to set off, unhurried to arrive, so the direction
      // registers and the landing does not overshoot the eye.
      const k = 1 - Math.pow(1 - p, 3);
      view.x = from.x + (to.x - from.x) * k;
      view.y = from.y + (to.y - from.y) * k;
      view.w = from.w + (to.w - from.w) * k;
      view.h = from.h + (to.h - from.h) * k;
      apply();
      if (p < 1) { frame = requestAnimationFrame(step); }
      else { frame = null; rewrap(); apply(); }
    };
    frame = requestAnimationFrame(step);
  };

  // The nearest copy of a point on a wrapping map. Going west to a place that
  // is nominally east of you is the short way round, and this is what says so.
  const nearest = (x, from) => {
    if (!opts.wrapX) return x;
    const ref = from == null ? centre()[0] : from;
    let best = x, bestD = Math.abs(x - ref);
    for (let k = -2; k <= 2; k++) {
      const c = x + k * w, d = Math.abs(c - ref);
      if (d < bestD) { best = c; bestD = d; }
    }
    return best;
  };

  return {
    reset: () => { stop(); home(); apply(); },
    centre, moveTo, nearest,
    // Frame a box, keeping its aspect honest and leaving room round the edge.
    fit: (x0, y0, x1, y1, pad, ms) => {
      pad = pad == null ? 1.35 : pad;
      const bw = Math.max(Math.abs(x1 - x0), 1e-6), bh = Math.max(Math.abs(y1 - y0), 1e-6);
      // Whichever side is tighter decides the zoom, or the box spills out of
      // the side that was not measured.
      const nw = clampW(Math.max(bw, bh / aspect()) * pad);
      moveTo((x0 + x1) / 2, (y0 + y1) / 2, nw, ms);
    }
  };
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
