const actionLabels = ['ALLOW', 'BLOCK_AD', 'MALWARE', 'PHISHING', 'CUSTOM'];
const actionTags = ['tag-allow', 'tag-tracker', 'tag-malware', 'tag-phishing', 'tag-custom'];

let eventCount = 0, logCount = 0, prevStats = { allowed: 0, blocked: 0, inspected: 0 };
let chartData = { allowed: [], blocked: [] };
let topBlocked = {};

// ── Chart ─────────────────────────────────
function initChart() {
  const canvas = document.getElementById('traffic-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = 2;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    canvas.style.width = rect.width + 'px';
    canvas.style.height = rect.height + 'px';
    ctx.scale(dpr, dpr);
  }
  resize();
  window.addEventListener('resize', resize);

  function draw() {
    const w = canvas.width / 2;
    const h = canvas.height / 2;
    ctx.clearRect(0, 0, w, h);
    if (chartData.allowed.length < 2) return;

    const max = Math.max(1, ...chartData.allowed, ...chartData.blocked);
    const pad = { top: 8, bottom: 4, left: 0, right: 0 };
    const cw = w - pad.left - pad.right;
    const ch = h - pad.top - pad.bottom;

    function line(data, color, glow) {
      if (data.length < 2) return;
      const step = cw / (data.length - 1);
      ctx.beginPath();
      data.forEach((v, i) => {
        const x = pad.left + i * step;
        const y = pad.top + ch - (v / max) * ch;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = 'round';
      ctx.shadowColor = glow;
      ctx.shadowBlur = 12;
      ctx.stroke();
      ctx.shadowBlur = 0;

      const lastX = pad.left + (data.length - 1) * step;
      ctx.lineTo(lastX, pad.top + ch);
      ctx.lineTo(pad.left, pad.top + ch);
      ctx.closePath();
      const g = ctx.createLinearGradient(0, pad.top, 0, pad.top + ch);
      g.addColorStop(0, color.replace(')', ',0.1)').replace('rgb', 'rgba'));
      g.addColorStop(1, color.replace(')', ',0)').replace('rgb', 'rgba'));
      ctx.fillStyle = g;
      ctx.fill();
    }

    line(chartData.allowed, 'rgb(255,107,157)', 'rgba(255,107,157,0.3)');
    line(chartData.blocked, 'rgb(0,229,255)', 'rgba(0,229,255,0.25)');
  }

  setInterval(draw, 1000);
}

// ── Threat Map ────────────────────────────
const particles = [];
function initThreatMap() {
  const canvas = document.getElementById('threat-map');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
  }
  resize();
  window.addEventListener('resize', resize);

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i];
      p.x += p.vx; p.y += p.vy;
      p.life -= 0.02;
      if (p.life <= 0) { particles.splice(i, 1); continue; }
      
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.globalAlpha = p.life;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 10;
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.shadowBlur = 0;
    }
    requestAnimationFrame(draw);
  }
  draw();
}

function spawnThreat(action) {
  const canvas = document.getElementById('threat-map');
  if (!canvas) return;
  let color = '#34d399';
  if (action === 1) color = '#00e5ff';
  else if (action === 2) color = '#fbbf24';
  else if (action >= 3) color = '#fb7185';

  particles.push({
    x: Math.random() * (canvas.width * 0.2) + (action === 0 ? 0 : canvas.width * 0.8),
    y: canvas.height + 10,
    vx: (Math.random() - 0.5) * 2,
    vy: -Math.random() * 3 - 2,
    size: Math.random() * 3 + 2,
    color,
    life: 1
  });
}

// ── Animated counter ──────────────────────
function animateCounter(el, target) {
  if (!el) return;
  const cur = parseInt(el.textContent.replace(/,/g, '')) || 0;
  if (cur === target) return;
  const steps = Math.min(20, Math.abs(target - cur));
  const step = (target - cur) / steps;
  let i = 0;
  function tick() {
    i++;
    el.textContent = Math.round(cur + step * i).toLocaleString();
    if (i < steps) requestAnimationFrame(tick);
    else el.textContent = target.toLocaleString();
  }
  tick();
}

// ── Stats ─────────────────────────────────
function updateStats(data) {
  animateCounter($('stat-allowed'), data.packets_allowed || 0);
  animateCounter($('stat-blocked'), data.packets_blocked || 0);
  animateCounter($('stat-inspected'), data.packets_inspected || 0);
  animateCounter($('stat-rules'), data.active_rules || 0);

  const dAllowed = (data.packets_allowed || 0) - prevStats.allowed;
  const dBlocked = (data.packets_blocked || 0) - prevStats.blocked;
  const dInspected = (data.packets_inspected || 0) - prevStats.inspected;
  prevStats = { allowed: data.packets_allowed || 0, blocked: data.packets_blocked || 0, inspected: data.packets_inspected || 0 };

  const r1 = $('stat-allowed-rate'), r2 = $('stat-blocked-rate'), r3 = $('stat-inspected-rate');
  if (r1) r1.innerHTML = '&#8593; +' + dAllowed + '/2s';
  if (r2) r2.innerHTML = '&#8593; +' + dBlocked + '/2s';
  if (r3) r3.innerHTML = '&#8593; +' + dInspected + '/2s';

  chartData.allowed.push(data.packets_allowed || 0);
  chartData.blocked.push(data.packets_blocked || 0);
  if (chartData.allowed.length > 60) { chartData.allowed.shift(); chartData.blocked.shift(); }
}

// ── Events ────────────────────────────────
function addEventRow(ev) {
  const body = $('event-body');
  if (!body) return;
  const time = new Date(ev.time).toLocaleTimeString();
  const tagCls = actionTags[ev.action] || 'tag-tracker';
  const label = actionLabels[ev.action] || 'BLOCKED';
  const empty = body.querySelector('.event-empty');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className = 'event-item';
  div.innerHTML = `
    <span class="event-time">${time}</span>
    <span class="event-domain">${ev.domain}</span>
    <span class="event-tag ${tagCls}">${label}</span>
    <span class="event-client">${ev.client || '-'}</span>`;
  body.prepend(div);
  eventCount++;
  const badge = $('event-count');
  if (badge) badge.textContent = eventCount;
  while (body.children.length > 100) body.removeChild(body.lastChild);

  topBlocked[ev.domain] = (topBlocked[ev.domain] || 0) + 1;
  renderTopBlocked();
  
  if (particles.length < 50) spawnThreat(ev.action);
}

function renderTopBlocked() {
  const body = $('top-blocked-body');
  if (!body) return;
  const sorted = Object.entries(topBlocked).sort((a, b) => b[1] - a[1]).slice(0, 20);
  body.innerHTML = '';
  if (sorted.length === 0) {
    body.innerHTML = '<div class="event-empty">No blocked domains</div>';
    return;
  }
  const maxC = sorted[0][1] || 1;
  for (const [domain, count] of sorted) {
    const pct = (count / maxC) * 100;
    const div = document.createElement('div');
    div.className = 'event-item';
    div.innerHTML = `
      <span class="event-domain" style="position:relative">
        <span style="position:absolute;left:0;bottom:0;height:2px;width:${pct}%;background:linear-gradient(90deg,var(--cyan),transparent);border-radius:1px;opacity:0.4"></span>
        ${domain}
      </span>
      <span style="font-weight:700;color:var(--cyan);font-variant-numeric:tabular-nums;text-shadow:0 0 8px rgba(0,229,255,0.2);flex-shrink:0">${count}</span>`;
    body.appendChild(div);
  }
}

async function loadEvents() {
  try {
    const data = await api('/traffic/events?limit=50');
    if (!data || data.length === 0) return;
    for (const ev of data.reverse()) addEventRow(ev);
  } catch (_) {}
}

// ── Logs (dashboard feed) ─────────────────
function addLogLine(data) {
  const feed = $('log-feed');
  if (!feed) return;
  const empty = feed.querySelector('.event-empty');
  if (empty) empty.remove();

  const time = new Date().toLocaleTimeString();
  const label = actionLabels[data.action] || 'ALLOW';
  const tagCls = actionTags[data.action] || 'tag-allow';
  const isBlock = data.blocked;
  const div = document.createElement('div');
  div.style.cssText = 'display:flex;align-items:center;gap:8px;white-space:nowrap';
  div.innerHTML = `
    <span style="color:var(--text3);flex-shrink:0">${time}</span>
    <span style="flex-shrink:0;color:${isBlock ? 'var(--cyan)' : '#34d399'}">${isBlock ? '⛔' : '✓'}</span>
    <span style="flex:1;overflow:hidden;text-overflow:ellipsis;color:${isBlock ? 'var(--cyan)' : 'var(--text)'}">${data.domain}</span>
    <span class="event-tag ${tagCls}" style="flex-shrink:0">${label}</span>`;
  feed.appendChild(div);
  logCount++;
  const lc = $('log-count');
  if (lc) lc.textContent = logCount + ' queries';
  feed.scrollTop = feed.scrollHeight;
  while (feed.children.length > 150) {
    if (feed.firstChild) feed.firstChild.remove();
  }
}

// ── Logs (full page) ──────────────────────
function addLogViewerLine(data) {
  const viewer = $('log-viewer');
  if (!viewer) return;
  const time = new Date().toLocaleTimeString();
  const label = actionLabels[data.action] || 'ALLOW';
  const tagCls = actionTags[data.action] || 'tag-allow';
  const isBlock = data.blocked;
  const line = `<span style="color:var(--text3)">${time}</span> <span style="color:${isBlock ? 'var(--cyan)' : '#34d399'}">${isBlock ? '⛔' : '✓'}</span> <span style="color:${isBlock ? 'var(--cyan)' : 'var(--text)'}">${data.domain}</span><span class="event-tag ${tagCls}" style="margin-left:8px">${label}</span>`;
  viewer.insertAdjacentHTML('beforeend', `<div style="line-height:2">${line}</div>`);
  logCount++;
  const lc2 = $('log-count2');
  if (lc2) lc2.textContent = logCount + ' queries';
  viewer.scrollTop = viewer.scrollHeight;
  if (viewer.children.length > 500) {
    const children = viewer.children;
    for (let i = 0; i < 250; i++) {
      if (children[0]) children[0].remove();
    }
  }
}

// ── Init ──────────────────────────────────
(async function init() {
  try {
    const stats = await api('/traffic/stats');
    updateStats(stats);
  } catch (_) {}

  loadEvents();
  loadRules();
  loadFilters();
  loadCustomDNS();
  initChart();
  initThreatMap();

  window.handleEvent = function(msg) {
    if (msg.event === 'stats') updateStats(msg.data);
    if (msg.event === 'blocked') { addEventRow(msg.data); spawnThreat(msg.data.action); }
    if (msg.event === 'query') {
      addLogLine(msg.data);
      addLogViewerLine(msg.data);
      if (Math.random() < 0.1) spawnThreat(msg.data.action);
    }
  };
})();

// ── Rules ─────────────────────────────────
async function loadRules() {
  try {
    const search = ($('rules-search')?.value || '').toLowerCase();
    const data = await api('/rules' + (search ? '?search=' + encodeURIComponent(search) : ''));
    
    const tbody = $('rules-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    // We only render the returned rules (backend limits to 100)
    for (const rule of (data.rules || [])) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="color:var(--text3)">${rule.id}</td>
        <td class="event-domain">${rule.pattern}</td>
        <td><span class="event-tag ${actionTags[rule.action] || 'tag-tracker'}">${actionLabels[rule.action] || 'UNKNOWN'}</span></td>
        <td><button class="btn btn-ghost" style="padding:2px 10px;font-size:10px" onclick="deleteRule(${rule.id})">Delete</button></td>`;
      tbody.appendChild(tr);
    }
  } catch (_) {}
}

async function loadFilters() {
  try {
    const data = await api('/config');
    const tbody = $('filters-body');
    tbody.innerHTML = '';
    for (const src of data.filters?.sources || []) {
      const tr = document.createElement('tr');
      const sc = src.enabled ? 'tag-allow' : '';
      const st = src.enabled ? 'Active' : 'Disabled';
      tr.innerHTML = `
        <td style="font-weight:500">${src.name}</td>
        <td style="color:var(--text3);font-size:11px">${src.url.replace(/https?:\/\//, '')}</td>
        <td><span class="event-tag" style="background:rgba(255,255,255,0.03);color:var(--text3)">${src.format}</span></td>
        <td><span class="event-tag ${sc}">${st}</span></td>`;
      tbody.appendChild(tr);
    }
  } catch (_) {}
}

async function addRule() {
  const pattern = $('rule-pattern').value;
  const action = parseInt($('rule-action').value);
  if (!pattern) return;
  await api('/rules', { method: 'POST', body: JSON.stringify({ pattern, action }) });
  closeModal('add-rule-modal');
  $('rule-pattern').value = '';
  loadRules();
}

async function deleteRule(id) {
  await fetch(`${API_BASE}/rules/${id}`, { method: 'DELETE' });
  loadRules();
}

async function clearRules() {
  if (!confirm('Clear all rules?')) return;
  await api('/rules/clear', { method: 'POST' });
  loadRules();
}

async function saveDNSConfig() {
  const dohUrl = $('doh-url').value;
  await api('/config/dns', { method: 'PUT', body: JSON.stringify({ primary_doh_url: dohUrl, enable_doh: true }) });
}

async function updateFilters() {
  const btn = document.querySelector('#page-filters .btn-primary');
  btn.textContent = 'Updating...';
  btn.disabled = true;
  try {
    await api('/filters/update', { method: 'POST' });
    await loadFilters();
    alert('Filter lists updated');
  } catch (_) { alert('Failed to update filters'); }
  btn.textContent = 'Refresh Lists';
  btn.disabled = false;
}

// ── Custom DNS & Profiles ─────────────────
async function loadCustomDNS() {
  try {
    const data = await api('/custom-dns');
    const tbody = $('custom-dns-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    for (const rec of data) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="event-domain">${rec.domain}</td>
        <td style="color:var(--cyan);font-family:monospace">${rec.ip}</td>
        <td><button class="btn btn-ghost" style="padding:2px 10px;font-size:10px" onclick="deleteCustomDNS('${rec.domain}')">Delete</button></td>`;
      tbody.appendChild(tr);
    }
  } catch (_) {}
}

function showAddCustomDNSModal() { $('add-dns-modal').classList.add('active'); }

async function addCustomDNS() {
  const domain = $('dns-domain').value;
  const ip = $('dns-ip').value;
  if (!domain || !ip) return;
  await api('/custom-dns', { method: 'POST', body: JSON.stringify({ domain, ip }) });
  closeModal('add-dns-modal');
  $('dns-domain').value = '';
  $('dns-ip').value = '';
  loadCustomDNS();
}

async function deleteCustomDNS(domain) {
  await fetch(`${API_BASE}/custom-dns/${domain}`, { method: 'DELETE' });
  loadCustomDNS();
}

function showAddProfileModal() {
  const ip = prompt("Enter Client IP Address (e.g. 192.168.1.15):");
  if (!ip) return;
  const profile = prompt("Enter Profile Name (e.g. kids, strict):");
  if (!profile) return;
  addDeviceProfile(ip, profile);
}

async function addDeviceProfile(ip, profile) {
  await api('/device-profile', { method: 'POST', body: JSON.stringify({ ip, profile }) });
  const tbody = $('profiles-body');
  const empty = tbody.querySelector('.event-empty');
  if (empty) empty.remove();
  const tr = document.createElement('tr');
  tr.innerHTML = `<td style="color:var(--cyan);font-family:monospace">${ip}</td><td class="event-tag tag-allow">${profile}</td>`;
  tbody.appendChild(tr);
}

async function saveSettings() {
  const enableHeuristics = $('enable-heuristics')?.checked;
  const enableSafeSearch = $('enable-safesearch')?.checked;
  const enableRebindingProtection = $('enable-rebinding')?.checked;
  await api('/settings', { method: 'POST', body: JSON.stringify({
    enableHeuristics, enableSafeSearch, enableRebindingProtection
  })});
}

