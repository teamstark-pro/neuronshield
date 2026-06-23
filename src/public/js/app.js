const API_BASE = '/api/v1';
function $(id) { return document.getElementById(id); }

// Tab navigation
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    if (tab.classList.contains('active')) return;
    document.querySelector('.tab.active')?.classList.remove('active');
    tab.classList.add('active');
    document.querySelector('.page.active')?.classList.remove('active');
    const page = $(`page-${tab.dataset.page}`);
    if (page) page.classList.add('active');
    document.title = `${tab.textContent.trim()} — Neuron Shield`;
  });
});

// Close modals on overlay click
window.addEventListener('click', e => {
  if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('active');
});

// API helper
async function api(path, opts = {}) {
  const resp = await fetch(API_BASE + path, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts
  });
  return resp.json();
}

// WebSocket
let ws;
function connectWS() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${location.host}`);
  ws.onmessage = e => {
    try {
      const msg = JSON.parse(e.data);
      if (window.handleEvent) window.handleEvent(msg);
    } catch (_) {}
  };
  ws.onclose = () => setTimeout(connectWS, 3000);
}
connectWS();

// Status polling
async function checkStatus() {
  try {
    await api('/health');
    const s = document.getElementById('kernel-status');
    if (s) {
      s.innerHTML = '<span class="top-dot pulse"></span><span>Online</span>';
    }
  } catch (e) {
    const s = document.getElementById('kernel-status');
    if (s) {
      s.innerHTML = '<span class="top-dot" style="background:#fb7185"></span><span>Offline</span>';
    }
  }
}
setInterval(checkStatus, 5000);
checkStatus();

function showAddRuleModal() { $('add-rule-modal').classList.add('active'); }
function closeModal(id) { $(id).classList.remove('active'); }
