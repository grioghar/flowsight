/* Flowsight application shell: navigation, routing, refresh, login. */
'use strict';
(function () {
  const { $, $$, esc, get } = FS;
  const ICONS = { license: '◈', overview: '◉', hosts: '▣', flows: '⇄', apps: '◇', web: '◍', dns: '◎', threats: '⚠', tls: '🔒', policy: '☰', groups: '⦿', categories: '▤', firewall: '▦', enroll: '⌂', reports: '▥', alerts: '🔔', system: '⚙', findings: '✓', events: '≡', modules: '⚙', audit: '≡' };
  const ORDER = { Visibility: 1, Security: 2, Policy: 3, Operations: 4 };
  let timer = null;

  FS.setTitle = (t) => { $('#title').textContent = t; document.title = t + ' · Flowsight'; };

  async function buildMenu() {
    const [p, info] = await Promise.all([get('/api/system/panels'), get('/api/system/info')]);
    if (p.error && p.error.includes('authentication')) return;
    const panels = (p.panels || []).filter(x => !x.detail);
    // Panels the core always offers, in the Operations group.
    panels.push({ id: 'findings', title: 'Findings', group: 'Operations', order: 200 }, { id: 'events', title: 'Events', group: 'Operations', order: 210 },
      { id: 'system', title: 'System', group: 'Operations', order: 220 }, { id: 'modules', title: 'Settings', group: 'Operations', order: 230 });
    const groups = {};
    panels.forEach(x => { (groups[x.group || 'Other'] = groups[x.group || 'Other'] || []).push(x); });
    const html = Object.keys(groups).sort((a, b) => (ORDER[a] || 9) - (ORDER[b] || 9)).map(g => `<div class="group">${esc(g)}</div>` + groups[g].sort((a, b) => a.order - b.order).map(x => `<a href="#${esc(x.id)}" data-page="${esc(x.id)}" ${x.locked ? 'title="Requires the ' + esc(x.required) + ' tier"' : ''}><span class="ico">${ICONS[x.icon || x.id] || '•'}</span>${esc(x.title)}${x.locked ? '<span class="lock">🔒</span>' : ''}</a>`).join('')).join('');
    $('#menu').innerHTML = html;
    $('#site').textContent = info.site || '';
    $('#version').textContent = 'v' + (info.version || '') + (p.tier && p.tier !== 'community' ? ' · ' + FS.tierName(p.tier) : '');
    if (info.read_only) $('#version').textContent += ' · read-only';
  }

  async function healthPill() {
    const h = await get('/api/system/health');
    const el = $('#health-pill'); if (!el) return;
    if (h.error) { el.className = 'pill bad'; el.textContent = 'offline'; return; }
    const bad = Object.values(h.modules || {}).filter(m => !m.ok).length;
    el.className = 'pill ' + (bad ? 'warn' : 'ok'); el.textContent = bad ? `${bad} module issue${bad > 1 ? 's' : ''}` : 'healthy';
    el.onclick = () => FS.go('#system');
  }

  function rangeBar() {
    const el = $('#range');
    const opts = [[1, '1h'], [6, '6h'], [24, '24h'], [168, '7d'], [720, '30d']];
    el.innerHTML = opts.map(([h, l]) => `<button data-h="${h}" class="${FS.state.hours === h ? 'on' : ''}">${l}</button>`).join('');
    $$('button', el).forEach(b => b.onclick = () => { FS.setHours(Number(b.dataset.h)); rangeBar(); });
  }

  FS.needLogin = function () {
    if ($('#login')) return;
    $('#view').innerHTML = `<div class="card login" id="login"><h2>Sign in</h2><p class="small muted">This Flowsight instance requires its API token.</p><form class="f"><label>API token</label><input type="text" name="token" autocomplete="off" autofocus><div class="actions"><button class="btn primary">Sign in</button></div></form></div>`;
    $('#login form').onsubmit = async (e) => { e.preventDefault(); const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'Flowsight' }, body: JSON.stringify({ token: e.target.token.value }) }); if (r.ok) { location.reload(); } else FS.toast('Invalid token', true); };
  };

  FS.render = async function () {
    const { page, arg, params } = FS.parseHash();
    const def = FS.pages[page] || FS.pages.overview;
    FS.state.page = page; FS.state.params = params;
    $$('#menu a').forEach(a => a.classList.toggle('active', a.dataset.page === page || (page === 'host' && a.dataset.page === 'hosts') || (page === 'modules' && a.dataset.page === 'modules')));
    FS.setTitle(def.title);
    $('#nav').classList.remove('open');
    const view = $('#view');
    if (!view.dataset.page || view.dataset.page !== page + '/' + arg) { view.innerHTML = '<div class="empty">Loading…</div>'; view.dataset.page = page + '/' + arg; }
    try { await def.render(view, { arg, params }); } catch (e) { view.innerHTML = FS.err('Page failed: ' + e.message); console.error(e); }
    clearTimeout(timer);
    if (def.refresh && document.visibilityState === 'visible') timer = setTimeout(() => { if (FS.parseHash().page === page) FS.render(); }, def.refresh * 1000);
  };

  window.addEventListener('hashchange', FS.render);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') FS.render(); });
  $('#navtoggle').onclick = () => $('#nav').classList.toggle('open');
  $('#search').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const q = e.target.value.trim(); if (!q) return;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(q) || q.includes(':') && !q.includes('.')) FS.go('#host/' + encodeURIComponent(q));
    else if (q.includes('.')) FS.go('#flows?domain=' + encodeURIComponent(q));
    else FS.go('#hosts?q=' + encodeURIComponent(q));
    e.target.value = '';
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') FS.closeModal(); });

  (async () => {
    rangeBar();
    await buildMenu();
    healthPill(); setInterval(healthPill, 30000);
    FS.render();
  })();
})();
