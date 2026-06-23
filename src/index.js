const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const path = require('path');
const fs = require('fs');

const FilterEngine = require('./filter-engine');
const DNSServer = require('./dns-server');
const ListsLoader = require('./lists-loader');
const config = require('./config');
const createAPI = require('./api');

// ── Init ────────────────────────────────────────────
const engine = new FilterEngine();
const listsLoader = new ListsLoader();
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const clients = new Set();

function broadcast(event, data) {
  const msg = JSON.stringify({ event, data, timestamp: Date.now() });
  for (const c of clients) {
    if (c.readyState === 1) c.send(msg);
  }
}

// ── Load filter lists ──────────────────────────────
async function loadFilterLists() {
  console.log('[BNFW] Loading filter lists...');
  let total = 0;

  for (const list of listsLoader.getLists()) {
    if (!list.enabled) continue;
    const filePath = listsLoader.getListPath(list.file);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf-8');
    let count;
    if (list.format === 'hosts') {
      count = engine.loadFromHosts(content, list.name);
    } else {
      count = engine.loadFromText(content, list.name);
    }
    total += count;
    console.log(`  [LOAD] ${list.name}: ${count} rules`);
  }

  console.log(`[BNFW] Total: ${total} rules loaded`);
  broadcast('filters_updated', { rules: total });
}

// ── API ────────────────────────────────────────────
const { router: apiRouter, pushEvent } = createAPI(engine, null, listsLoader, broadcast);

// Stats recording every 2s
let statsInterval;
function startStatsRecording() {
  statsInterval = setInterval(() => {
    const s = engine.stats;
    broadcast('stats', {
      packets_allowed: s.allowed || 0,
      packets_blocked: s.blocked || 0,
      packets_inspected: s.total || 0,
      active_rules: engine.ruleCount,
    });
  }, 2000);
}

// ── Express setup ─────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/v1', apiRouter);

app.get('/api/v1/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', rules: engine.ruleCount });
});

// ── WebSocket ──────────────────────────────────────
wss.on('connection', (ws) => {
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));
});

// ── DNS Server ────────────────────────────────────
const dnsPort = config.get('dns.port');
const dnsAddr = config.get('dns.address');

const dnsServer = new DNSServer(engine, {
  port: dnsPort,
  address: dnsAddr,
  dohUrl: config.get('dns.dohUrl'),
  sinkhole: config.get('dns.sinkhole'),
  blockTTL: config.get('dns.blockTTL'),
  onBlock: (info) => {
    broadcast('blocked', info);
    pushEvent(info);
  },
  onQuery: (info) => {
    broadcast('query', info);
  },
});

// ── Start ──────────────────────────────────────────
const PORT = config.get('dashboard.port');

async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║    Brave Network Shield v1.0.0           ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log('');

  // Auto-download lists on first run
  const hasLists = listsLoader.getLists().some(l => {
    return l.enabled && fs.existsSync(listsLoader.getListPath(l.file));
  });

  if (!hasLists) {
    console.log('[BNFW] No filter lists found. Downloading...\n');
    await listsLoader.fetchAll((name, status, extra) => {
      const icon = status === 'done' ? 'OK' : status === 'downloading' ? '..' : 'FAIL';
      const extraStr = extra ? ` (${extra})` : '';
      console.log(`  [${icon}] ${name}${extraStr}`);
    });
    console.log('');
  }

  await loadFilterLists();

  // Start DNS server (auto-fallbacks to next port if taken)
  dnsServer.start();

  // Start dashboard
  const dashPort = config.get('dashboard.port');
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`[BNFW] Dashboard port ${dashPort} in use. Change in config.json`);
    }
  });
  server.listen(dashPort, config.get('dashboard.address'), () => {
    const actualDnsPort = dnsServer.actualPort || dnsPort;
    console.log(`[BNFW] Dashboard: http://${config.get('dashboard.address')}:${dashPort}`);
    console.log(`[BNFW] DNS proxy: ${dnsAddr}:${actualDnsPort} → ${config.get('dns.dohUrl')}`);
    console.log('');
    if (actualDnsPort === 53) {
      console.log('  Configure your system to use this DNS:');
      console.log(`    netsh interface ip set dns "Wi-Fi" static ${dnsAddr}`);
      console.log('  Open the dashboard at http://127.0.0.1:' + dashPort);
    } else {
      console.log(`  DNS running on port ${actualDnsPort} (not 53).`);
      console.log('  Windows always sends DNS to port 53. To fix this:');
      console.log('    1. Run as Administrator to auto-bind port 53');
      console.log('       (stops the Windows DNS Client service if needed)');
      console.log('  Or configure your apps to use DNS at 127.0.0.1:' + actualDnsPort);
    }
    console.log('');
  });

  startStatsRecording();
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[BNFW] Shutting down...');
  dnsServer.stop();
  clearInterval(statsInterval);
  server.close();
  process.exit(0);
});
