'use strict';

const API_BASE = 'http://localhost:8000'; //remove during production

// ══════════════════════════════════════════
//  AUTH GUARD
//  Runs immediately — redirects to login if
//  no valid token is found in localStorage.
// ══════════════════════════════════════════
(function authGuard() {
  const token     = localStorage.getItem('pp_token');
  const expiresAt = localStorage.getItem('pp_expires_at');

  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  // Check expiry client-side as a fast gate
  // (server also validates on every request)
  if (expiresAt && new Date(expiresAt) < new Date()) {
    localStorage.removeItem('pp_token');
    localStorage.removeItem('pp_operator_id');
    localStorage.removeItem('pp_display_name');
    localStorage.removeItem('pp_expires_at');
    window.location.href = 'login.html';
  }
})();

// ══════════════════════════════════════════
//  API HELPER
//  Wraps fetch — automatically adds the
//  Bearer token to every request.
//  On 401, clears storage and redirects.
// ══════════════════════════════════════════
async function apiFetch(url, options = {}) {
  const token = localStorage.getItem('pp_token');
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  //const resp = await fetch(url, { ...options, headers }); //for production

  const fullUrl = url.startsWith('http') ? url : API_BASE + url; //for dev only
  const resp = await fetch(fullUrl, { ...options, headers });    //for dev only

  if (resp.status === 401) {
    // Token expired or revoked — send back to login
    localStorage.removeItem('pp_token');
    localStorage.removeItem('pp_operator_id');
    localStorage.removeItem('pp_display_name');
    localStorage.removeItem('pp_expires_at');
    window.location.href = 'login.html';
    return null;
  }

  return resp;
}

// ══════════════════════════════════════════
//  SIGNOUT
// ══════════════════════════════════════════
async function signOut() {
  try {
    await apiFetch('/api/auth/signout', { method: 'POST' });
  } catch (e) {
    // Proceed even if request fails
  }
  localStorage.removeItem('pp_token');
  localStorage.removeItem('pp_operator_id');
  localStorage.removeItem('pp_display_name');
  localStorage.removeItem('pp_expires_at');
  window.location.href = 'login.html';
}

const CATEGORIES = {
  remote:   { label:'Remote Access', color:'#92400e', bg:'#fef3c7', border:'#f59e0b' },
  web:      { label:'Web',           color:'#1e40af', bg:'#eff6ff', border:'#3b82f6' },
  file:     { label:'File Transfer', color:'#5b21b6', bg:'#f5f3ff', border:'#8b5cf6' },
  database: { label:'Database',      color:'#991b1b', bg:'#fef2f2', border:'#ef4444' },
  mail:     { label:'Mail',          color:'#065f46', bg:'#ecfdf5', border:'#10b981' },
  infra:    { label:'Infrastructure',color:'#1e3a8a', bg:'#eff6ff', border:'#2563eb' },
  devops:   { label:'DevOps',        color:'#7c2d12', bg:'#fff7ed', border:'#f97316' },
  proxy:    { label:'Proxy / VPN',   color:'#581c87', bg:'#faf5ff', border:'#a855f7' },
  danger:   { label:'⚠ Danger',      color:'#7f1d1d', bg:'#fef2f2', border:'#dc2626' },
};

let activeCats  = new Set(Object.keys(CATEGORIES));
let lastResults = [];
let isDark      = false;
let scanTimer   = null;

// ══════════════════════════════════════════
//  SIDEBAR — COLLAPSE & RESIZE
// ══════════════════════════════════════════
const SIDEBAR_MIN     = 200;
const SIDEBAR_MAX     = 520;
const SIDEBAR_DEFAULT = 280;
const SIDEBAR_COLLAPSED_W = 56;

let sidebarCollapsed = false;
let sidebarWidth     = SIDEBAR_DEFAULT;

function applySidebarWidth(w, animate) {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  if (animate) {
    sidebar.style.transition = 'width 0.28s cubic-bezier(.4,0,.2,1), background 0.3s';
  } else {
    sidebar.style.transition = 'background 0.3s';
  }
  sidebar.style.width = w + 'px';
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const btn     = document.getElementById('collapse-btn');
  if (!sidebar) return;

  sidebarCollapsed = !sidebarCollapsed;
  sidebar.classList.toggle('collapsed', sidebarCollapsed);

  if (sidebarCollapsed) {
    applySidebarWidth(SIDEBAR_COLLAPSED_W, true);
    if (btn) {
      btn.querySelector('.cb-label').textContent = '';
      btn.querySelector('.cb-icon').textContent  = '›';
      btn.title = 'Expand sidebar';
    }
  } else {
    applySidebarWidth(sidebarWidth, true);
    if (btn) {
      btn.querySelector('.cb-label').textContent = 'Collapse';
      btn.querySelector('.cb-icon').textContent  = '‹';
      btn.title = 'Collapse sidebar';
    }
  }

  try { localStorage.setItem('pp-sidebar-collapsed', sidebarCollapsed ? '1' : '0'); } catch(e) {}
}

function initSidebarResize() {
  const handle  = document.getElementById('resize-handle');
  const sidebar = document.getElementById('sidebar');
  if (!handle || !sidebar) return;

  let dragging  = false;
  let startX    = 0;
  let startW    = 0;

  handle.addEventListener('mousedown', e => {
    if (sidebarCollapsed) return;
    dragging = true;
    startX   = e.clientX;
    startW   = sidebar.getBoundingClientRect().width;
    handle.classList.add('dragging');
    document.body.style.cursor    = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });

  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    const delta = e.clientX - startX;
    const newW  = Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, startW + delta));
    sidebarWidth = newW;
    applySidebarWidth(newW, false);
  });

  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove('dragging');
    document.body.style.cursor    = '';
    document.body.style.userSelect = '';
    try { localStorage.setItem('pp-sidebar-width', sidebarWidth); } catch(e) {}
  });

  // Touch support
  handle.addEventListener('touchstart', e => {
    if (sidebarCollapsed) return;
    dragging = true;
    startX   = e.touches[0].clientX;
    startW   = sidebar.getBoundingClientRect().width;
    handle.classList.add('dragging');
    e.preventDefault();
  }, { passive: false });

  document.addEventListener('touchmove', e => {
    if (!dragging) return;
    const delta = e.touches[0].clientX - startX;
    const newW  = Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, startW + delta));
    sidebarWidth = newW;
    applySidebarWidth(newW, false);
  });

  document.addEventListener('touchend', () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove('dragging');
    try { localStorage.setItem('pp-sidebar-width', sidebarWidth); } catch(e) {}
  });
}

function restoreSidebarState() {
  try {
    const savedW = parseInt(localStorage.getItem('pp-sidebar-width'));
    if (savedW && savedW >= SIDEBAR_MIN && savedW <= SIDEBAR_MAX) sidebarWidth = savedW;

    const wasCollapsed = localStorage.getItem('pp-sidebar-collapsed') === '1';
    if (wasCollapsed) {
      // Apply collapsed immediately, no animation on load
      const sidebar = document.getElementById('sidebar');
      const btn     = document.getElementById('collapse-btn');
      sidebarCollapsed = true;
      if (sidebar) {
        sidebar.classList.add('collapsed');
        sidebar.style.width = SIDEBAR_COLLAPSED_W + 'px';
      }
      if (btn) {
        btn.querySelector('.cb-label').textContent = '';
        btn.querySelector('.cb-icon').textContent  = '›';
        btn.title = 'Expand sidebar';
      }
    } else {
      applySidebarWidth(sidebarWidth, false);
    }
  } catch(e) {}
}

// ══════════════════════════════════════════
//  THEME
// ══════════════════════════════════════════
function toggleTheme() {
  isDark = !isDark;
  document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  document.getElementById('theme-icon').textContent  = isDark ? '☀' : '☾';
  document.getElementById('theme-label').textContent = isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode';
  try { localStorage.setItem('pp-theme', isDark ? 'dark' : 'light'); } catch(e) {}
}

(function restoreTheme() {
  try {
    if (localStorage.getItem('pp-theme') === 'dark') {
      isDark = true;
      document.documentElement.setAttribute('data-theme', 'dark');
      document.getElementById('theme-icon').textContent  = '☀';
      document.getElementById('theme-label').textContent = 'Switch to Light Mode';
    }
  } catch(e) {}
})();

// ══════════════════════════════════════════
//  CLOCK
// ══════════════════════════════════════════
function startClock() {
  function tick() {
    const el = document.getElementById('s-time');
    if (el) el.textContent = new Date().toLocaleTimeString();
  }
  tick();
  setInterval(tick, 1000);
}

// ══════════════════════════════════════════
//  INIT
// ══════════════════════════════════════════
async function init() {
  restoreSidebarState();
  initSidebarResize();
  startClock();

  // Show operator name in UI if element exists
  const displayName = localStorage.getItem('pp_display_name') ||
                      localStorage.getItem('pp_operator_id')  || 'Operator';
  setText('operator-name', displayName);

  try {
    const r = await apiFetch('/api/scan/init');
    if (!r) return; // redirected to login
    const body = await r.json();
    const d = body.data || {};
    setText('lip', d.local_ip);
    setText('pip', d.public_ip);
    document.getElementById('subnet').value = d.subnet_prefix || '';
  } catch(e) { console.error('Init failed:', e); }
}

// ══════════════════════════════════════════
//  CATEGORY CHIPS
// ══════════════════════════════════════════
document.querySelectorAll('.cat-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    const cat = chip.dataset.cat;
    activeCats.has(cat) ? activeCats.delete(cat) : activeCats.add(cat);
    chip.classList.toggle('active', activeCats.has(cat));
    if (lastResults.length) renderResults(lastResults);
  });
});

// ══════════════════════════════════════════
//  PROGRESS HELPERS
// ══════════════════════════════════════════
function setProgress(pct, msg) {
  const fill = document.getElementById('progress-fill');
  const pctEl = document.getElementById('progress-pct');
  const msgEl = document.getElementById('progress-msg');
  if (fill)  fill.style.width  = pct + '%';
  if (pctEl) pctEl.textContent = Math.round(pct) + '%';
  if (msgEl) msgEl.textContent = msg;
}

function setPhase(num) {
  // num = 1, 2, or 3
  for (let i = 1; i <= 3; i++) {
    const el = document.getElementById(`phase-${i}`);
    if (!el) continue;
    el.classList.remove('active', 'done');
    if (i < num)  el.classList.add('done');
    if (i === num) el.classList.add('active');
  }
}

function showProgress(show) {
  const card = document.getElementById('progress-card');
  if (card) card.classList.toggle('hidden', !show);
}

function showExportBanner(show, aliveCount, portCount) {
  const banner = document.getElementById('export-banner');
  if (!banner) return;
  banner.classList.toggle('hidden', !show);
  if (show) {
    const sub = document.getElementById('export-sub');
    if (sub) sub.textContent = `${aliveCount} host${aliveCount !== 1 ? 's' : ''}, ${portCount} open port${portCount !== 1 ? 's' : ''} found — save your results`;
  }
}

function setStatus(state, label) {
  const dot   = document.getElementById('s-dot');
  const lbl   = document.getElementById('s-label');
  if (dot) dot.className = `s-dot ${state}`;
  if (lbl) lbl.textContent = label;
}

// ══════════════════════════════════════════
//  SCAN
// ══════════════════════════════════════════
async function runScan() {
  const subnet = document.getElementById('subnet').value.trim();
  const start  = document.getElementById('range-start').value;
  const end    = document.getElementById('range-end').value;
  if (!subnet) { alert('Enter a subnet prefix first (e.g. 192.168.1)'); return; }

  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="18" height="18"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Scanning…`;

  setStatus('scanning', 'Scanning…');
  showProgress(true);
  showExportBanner(false);
  setPhase(1);
  setProgress(0, 'Phase 1 — Discovering live hosts…');
  document.getElementById('phase-1-desc').textContent = `Sweeping ${parseInt(end) - parseInt(start) + 1} addresses…`;
  document.getElementById('phase-2-desc').textContent = 'Waiting…';
  setText('results-meta', '');
  setText('alive-count', '—');
  setText('port-count',  '—');
  document.getElementById('results').innerHTML = '';

  // Animated progress: 0→45% during phase 1, 45→92% during phase 2
  let prog  = 0;
  let speed = 0.8;
  let phase = 1;

  if (scanTimer) clearInterval(scanTimer);
  scanTimer = setInterval(() => {
    const cap = phase === 1 ? 44 : 91;
    if (prog < cap) { prog += speed; setProgress(prog, phase === 1 ? 'Phase 1 — Discovering live hosts…' : 'Phase 2 — Scanning open ports…'); }
  }, 200);

  // Transition to phase 2 after estimated discovery time
  const phaseSwitch = setTimeout(() => {
    phase = 2;
    speed = 0.5;
    setPhase(2);
    document.getElementById('phase-2-desc').textContent = 'Probing ports on live hosts…';
    setProgress(45, 'Phase 2 — Scanning open ports…');
  }, Math.max(3000, (parseInt(end) - parseInt(start) + 1) * 12));

  try {
    const resp = await apiFetch('/api/scan/run', {
      method: 'POST',
      body: JSON.stringify({ subnet, start: parseInt(start), end: parseInt(end) }),
    });
    if (!resp) return; // redirected to login

    const body = await resp.json();

    if (!resp.ok) {
      throw new Error(body.error || 'Scan failed.');
    }

    const data = body.data;
    // Normalise to the shape the rest of app.js expects
    lastResults = data.results || [];

    clearInterval(scanTimer);
    clearTimeout(phaseSwitch);

    // Complete all phases
    setPhase(3);
    setProgress(100, 'Scan complete!');
    document.getElementById('phase-3-desc').textContent = 'All results loaded';

    renderResults(lastResults);

    const alive = lastResults.filter(h => h.is_up);
    const totalPorts = alive.reduce((s,h) => s + h.ports.length, 0);
    showExportBanner(true, alive.length, totalPorts);
    setStatus('online', 'Online');

  } catch(e) {
    clearInterval(scanTimer);
    clearTimeout(phaseSwitch);
    setStatus('error', 'Error');
    setProgress(100, 'Scan failed — check server console');
    document.getElementById('results').innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">⚠</div>
        <div class="empty-title">Scan failed</div>
        <div class="empty-sub">Check the server console for details.</div>
      </div>`;
    console.error('Scan error:', e);
  }

  btn.disabled = false;
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="18" height="18"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> Run Scan`;

  // Hide progress after delay
  setTimeout(() => showProgress(false), 2500);
}

// ══════════════════════════════════════════
//  RENDER
// ══════════════════════════════════════════
function renderResults(data) {
  const resDiv = document.getElementById('results');
  const alive  = data.filter(h => h.is_up);

  const filtered = alive.map(h => ({
    ...h,
    ports: h.ports.filter(p => activeCats.has(p.category))
  }));

  const totalPorts = filtered.reduce((s, h) => s + h.ports.length, 0);
  setText('alive-count', alive.length);
  setText('port-count',  totalPorts);
  setText('results-meta', `${alive.length} host${alive.length !== 1 ? 's' : ''} responded`);

  if (!alive.length) {
    resDiv.innerHTML = `<div class="empty-state">
      <div class="empty-icon">📡</div>
      <div class="empty-title">No hosts responded</div>
      <div class="empty-sub">Try a narrower range, or check if the subnet is correct.</div>
    </div>`;
    return;
  }

  resDiv.innerHTML = '';
  filtered.forEach((host, idx) => {
    resDiv.appendChild(buildCard(host, idx));
  });
}

function buildCard(host, idx) {
  const card = document.createElement('div');
  card.className = 'host-card';
  card.style.animationDelay = (idx * 30) + 'ms';

  const did  = `d-${idx}`;
  const cid  = `c-${idx}`;

  const tags = host.ports.length
    ? host.ports.slice(0, 8).map(p => {
        const c = CATEGORIES[p.category] || { color:'#555', bg:'#eee', border:'#aaa' };
        return `<span class="ptag" style="color:${c.color};background:${c.bg};border-color:${c.border}">${p.port}&thinsp;${esc(p.label)}</span>`;
      }).join('') + (host.ports.length > 8 ? `<span class="ptag" style="color:#9ca3af;background:var(--surface3);border-color:var(--bdr)">+${host.ports.length - 8}</span>` : '')
    : `<span class="no-ports">No open ports in selected categories</span>`;

  const rows = host.ports.length
    ? host.ports.map(p => {
        const c = CATEGORIES[p.category] || { label:p.category, color:'#555', bg:'#eee', border:'#aaa' };
        const ban = p.banner
          ? `<td class="td-banner">${esc(p.banner)}</td>`
          : `<td class="td-banner empty">No banner</td>`;
        return `<tr>
          <td class="td-port">${p.port}</td>
          <td class="td-svc">${esc(p.label)}</td>
          <td class="td-cat"><span class="cat-tag" style="color:${c.color};background:${c.bg};border-color:${c.border}">${c.label}</span></td>
          ${ban}
        </tr>`;
      }).join('')
    : `<tr><td colspan="4" style="padding:14px 0;color:var(--text4);font-style:italic;font-size:0.85rem">No ports in selected categories</td></tr>`;

  card.innerHTML = `
    <div class="host-row" id="${cid}" onclick="toggle('${did}','${cid}')"
         role="button" tabindex="0" aria-expanded="false"
         onkeydown="if(event.key==='Enter'||event.key===' ')toggle('${did}','${cid}')">
      <div class="live-pip"></div>
      <div class="host-meta">
        <div class="host-ip">${esc(host.ip)}</div>
        ${host.hostname ? `<div class="host-name">${esc(host.hostname)}</div>` : ''}
      </div>
      <div class="port-tags">${tags}</div>
      <span class="chevron" id="ch-${idx}">&#9660;</span>
    </div>
    <div class="host-detail" id="${did}">
      <div class="detail-table-wrap">
        <table class="detail-table">
          <thead><tr><th>Port</th><th>Service</th><th>Category</th><th>Banner / Version</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  return card;
}

function toggle(did, cid) {
  const detail  = document.getElementById(did);
  const row     = document.getElementById(cid);
  const isOpen  = detail.classList.toggle('open');
  // find chevron inside row
  const chev    = row.querySelector('.chevron');
  if (chev) chev.classList.toggle('open', isOpen);
  row.setAttribute('aria-expanded', isOpen);
}

// ══════════════════════════════════════════
//  EXPORT
// ══════════════════════════════════════════
function exportCSV() {
  const alive = lastResults.filter(h => h.is_up);
  if (!alive.length) return;
  const rows = [['IP Address','Hostname','Port','Service','Category','Banner']];
  alive.forEach(h => {
    if (!h.ports.length) { rows.push([h.ip, h.hostname||'','','','','']); return; }
    h.ports.forEach(p => rows.push([h.ip, h.hostname||'', p.port, p.label, p.category, p.banner||'']));
  });
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\r\n');
  download('packetpulse-scan.csv', csv, 'text/csv');
}

function exportJSON() {
  const alive = lastResults.filter(h => h.is_up);
  if (!alive.length) return;
  const payload = {
    exported_at:          new Date().toISOString(),
    total_hosts_scanned:  lastResults.length,
    hosts_alive:          alive.length,
    total_open_ports:     alive.reduce((s,h) => s + h.ports.length, 0),
    hosts:                alive
  };
  download('packetpulse-scan.json', JSON.stringify(payload, null, 2), 'application/json');
}

function download(name, content, mime) {
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(new Blob([content], {type: mime}));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// ══════════════════════════════════════════
//  UTILS
// ══════════════════════════════════════════
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

init();