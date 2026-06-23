const express = require('express');
const config = require('./config');

function createAPI(filterEngine, dnsServer, listsLoader, broadcast) {
  const router = express.Router();
  router.use(express.json());

  // Stats
  router.get('/stats', (req, res) => {
    const stats = filterEngine.stats;
    res.json({
      packets_allowed: stats.allowed || 0,
      packets_blocked: stats.blocked || 0,
      packets_inspected: stats.total || 0,
      active_rules: filterEngine.ruleCount,
    });
  });

  router.get('/traffic/stats', (req, res) => {
    const stats = filterEngine.stats;
    res.json({
      packets_allowed: stats.allowed || 0,
      packets_blocked: stats.blocked || 0,
      packets_inspected: stats.total || 0,
      active_rules: filterEngine.ruleCount,
    });
  });

  // Rules
  router.get('/rules', (req, res) => {
    const search = (req.query.search || '').toLowerCase();
    const rules = [];
    let id = 1;
    let totalCount = 0;

    const addRule = (action, domain) => {
      totalCount++;
      if (rules.length < 100) {
        if (!search || domain.toLowerCase().includes(search)) {
          rules.push({ id: id++, pattern: domain, action });
        }
      } else if (search) {
        // If searching, we still need to scan for matches up to 100
        if (domain.toLowerCase().includes(search)) {
          rules.push({ id: id++, pattern: domain, action });
        }
      }
    };

    filterEngine._exact.forEach(addRule);
    filterEngine._suffix.forEach(addRule);

    // If searching, cap the results array to 100 after scanning
    const limitedRules = search ? rules.slice(0, 100) : rules;
    
    res.json({ count: filterEngine.ruleCount || totalCount, rules: limitedRules });
  });

  router.post('/rules', (req, res) => {
    const { pattern, action } = req.body;
    if (!pattern) return res.status(400).json({ error: 'pattern required' });
    filterEngine._addRule(pattern, action || 1);
    if (broadcast) broadcast('rule_added', { pattern, action });
    res.status(201).json({ status: 'created' });
  });

  router.delete('/rules/:id', (req, res) => {
    // Basic implementation since we don't store real IDs yet
    res.json({ status: 'ok' });
  });

  router.post('/rules/clear', (req, res) => {
    filterEngine.clear();
    res.json({ status: 'cleared' });
  });

  // Custom DNS
  router.get('/custom-dns', (req, res) => {
    res.json(filterEngine.getCustomDNS());
  });
  
  router.post('/custom-dns', (req, res) => {
    const { domain, ip } = req.body;
    if (domain && ip) filterEngine.setCustomDNS(domain, ip);
    res.json({ status: 'ok' });
  });

  router.delete('/custom-dns/:domain', (req, res) => {
    filterEngine.removeCustomDNS(req.params.domain);
    res.json({ status: 'ok' });
  });

  // Device Profiles
  router.post('/device-profile', (req, res) => {
    const { ip, profile } = req.body;
    if (ip && profile) filterEngine.setDeviceProfile(ip, profile);
    res.json({ status: 'ok' });
  });

  // Settings Toggles
  router.post('/settings', (req, res) => {
    const s = req.body;
    if (dnsServer) {
      if (s.enableSafeSearch !== undefined) dnsServer.enableSafeSearch = s.enableSafeSearch;
      if (s.enableRebindingProtection !== undefined) dnsServer.enableRebindingProtection = s.enableRebindingProtection;
      if (s.enableHeuristics !== undefined && dnsServer.heuristics) dnsServer.heuristics.enabled = s.enableHeuristics;
    }
    res.json({ status: 'ok' });
  });

  // Filter lists
  router.get('/filters', (req, res) => {
    const lists = listsLoader.getLists();
    const activeCount = filterEngine.ruleCount;
    const perList = Math.round(activeCount / Math.max(1, lists.filter(l => l.enabled).length));
    res.json({
      sources: lists.map(l => ({
        name: l.name,
        url: l.url,
        enabled: l.enabled,
        format: l.format,
        rule_count: l.enabled ? perList : 0,
      }))
    });
  });

  router.post('/filters/update', async (req, res) => {
    try {
      await listsLoader.fetchAll();
      const engine = filterEngine;
      engine.clear();
      const ListsLoader = require('./lists-loader');
      const loader = new ListsLoader();
      const fs = require('fs');
      for (const list of loader.getLists()) {
        if (!list.enabled) continue;
        const filePath = loader.getListPath(list.file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf-8');
          if (list.format === 'hosts') {
            engine.loadFromHosts(content, list.name);
          } else {
            engine.loadFromText(content, list.name);
          }
        }
      }
      if (broadcast) broadcast('filters_updated', { rules: engine.ruleCount });
      res.json({ status: 'ok', rules: engine.ruleCount });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Config (combined)
  router.get('/config', (req, res) => {
    const lists = listsLoader.getLists();
    res.json({
      dns: {
        primary_doh_url: config.get('dns.dohUrl'),
        enable_doh: true,
        block_port_53: true,
      },
      filters: {
        sources: lists.map(l => ({
          name: l.name,
          url: l.url,
          enabled: l.enabled,
          format: l.format,
        })),
      },
    });
  });

  router.put('/config/dns', (req, res) => {
    if (req.body.primary_doh_url) {
      config.set('dns.dohUrl', req.body.primary_doh_url);
    }
    res.json({ status: 'saved' });
  });

  // DNS config
  router.get('/dns/config', (req, res) => {
    res.json({
      primary_doh_url: config.get('dns.dohUrl'),
      enable_doh: true,
      block_port_53: true,
    });
  });

  router.put('/dns/config', (req, res) => {
    if (req.body.primary_doh_url) {
      config.set('dns.dohUrl', req.body.primary_doh_url);
    }
    res.json({ status: 'saved' });
  });

  // Kernel status (always connected in userspace mode)
  router.get('/kernel/enable', (req, res) => res.json({ status: 'enabled' }));
  router.get('/kernel/disable', (req, res) => res.json({ status: 'disabled' }));

  // Event log
  const events = [];
  router.get('/traffic/events', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    res.json(events.slice(-limit));
  });

  function pushEvent(info) {
    events.push({
      time: Date.now(),
      domain: info.domain,
      action: info.action,
      rule: info.rule,
      client: info.client,
    });
    if (events.length > 500) events.shift();
  }

  // Stats history
  const statsHistory = [];
  router.get('/traffic/history', (req, res) => {
    res.json(statsHistory.slice(-120));
  });

  function recordStats() {
    const s = filterEngine.stats;
    statsHistory.push({ time: Date.now(), ...s });
    if (statsHistory.length > 200) statsHistory.shift();
  }

  return { router, recordStats, pushEvent };
}

module.exports = createAPI;
