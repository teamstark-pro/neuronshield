class FilterEngine {
  constructor() {
    this._exact = new Map();       // domain -> action
    this._suffix = new Map();      // .domain -> action (wildcard subdomains)
    this._customDNS = new Map();   // domain -> ip
    this._deviceProfiles = new Map(); // ip -> profileName (e.g. 'kids')
    this._profileRules = new Map(); // profileName -> { exact: Map, suffix: Map }
    this._regex = [];              // regex patterns
    this._count = 0;
    this._hits = { allowed: 0, blocked: 0, total: 0 };
  }

  get ruleCount() { return this._count; }
  get stats() { return { ...this._hits }; }

  loadFromText(text, source = 'unknown') {
    let added = 0;
    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('!') || line.startsWith('[') || line.startsWith('#')) continue;

      const rule = this._parseLine(line);
      if (rule) {
        this._addRule(rule.domain, rule.action);
        added++;
      }
    }
    this._count += added;
    return added;
  }

  loadFromHosts(text, source = 'unknown') {
    let added = 0;
    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      const parts = line.split(/\s+/);
      if (parts.length >= 2) {
        const ip = parts[0];
        const domain = parts[1];
        if ((ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '::1') && domain) {
          this._addRule(domain, 1);
          added++;
        }
      }
    }
    this._count += added;
    return added;
  }

  // Returns { action, rule, ip? } or null if allowed
  match(domain, clientIP = null) {
    this._hits.total++;
    const d = domain.toLowerCase();

    // 0. Custom DNS
    if (this._customDNS.has(d)) {
      return { action: 4, rule: 'CUSTOM_DNS', ip: this._customDNS.get(d) }; // action 4 = custom A record
    }

    // Determine profiles to check
    const profilesToCheck = [{ exact: this._exact, suffix: this._suffix }];
    if (clientIP && this._deviceProfiles.has(clientIP)) {
      const profileName = this._deviceProfiles.get(clientIP);
      if (this._profileRules.has(profileName)) {
        profilesToCheck.unshift(this._profileRules.get(profileName)); // Check device profile first
      }
    }

    for (const profile of profilesToCheck) {
      // 1. Exact match
      if (profile.exact.has(d)) {
        this._hits.blocked++;
        return { action: profile.exact.get(d), rule: d };
      }
    }

    // 2. Suffix / subdomain match: walk up the domain
    let idx = d.indexOf('.');
    while (idx !== -1) {
      const suffix = d.slice(idx);
      for (const profile of profilesToCheck) {
        if (profile.suffix.has(suffix)) {
          this._hits.blocked++;
          return { action: profile.suffix.get(suffix), rule: suffix };
        }
      }
      idx = d.indexOf('.', idx + 1);
    }

    // 3. Domain without subdomain (e.g. match "example.com" in "sub.example.com")
    const parts = d.split('.');
    if (parts.length >= 2) {
      const base = parts.slice(-2).join('.');
      for (const profile of profilesToCheck) {
        if (profile.exact.has(base)) {
          this._hits.blocked++;
          return { action: profile.exact.get(base), rule: base };
        }
        const suffix = '.' + base;
        if (profile.suffix.has(suffix)) {
          this._hits.blocked++;
          return { action: profile.suffix.get(suffix), rule: suffix };
        }
      }
    }

    // 4. Regex patterns (last resort, slow)
    for (const { re, action } of this._regex) {
      if (re.test(d)) {
        this._hits.blocked++;
        return { action, rule: re.source };
      }
    }

    this._hits.allowed++;
    return null;
  }

  clear() {
    this._exact.clear();
    this._suffix.clear();
    this._regex = [];
    this._count = 0;
    this._hits = { allowed: 0, blocked: 0, total: 0 };
    // We intentionally do not clear customDNS or deviceProfiles on filter list updates
  }

  setCustomDNS(domain, ip) {
    this._customDNS.set(domain.toLowerCase(), ip);
  }

  getCustomDNS() {
    return Array.from(this._customDNS.entries()).map(([domain, ip]) => ({ domain, ip }));
  }

  removeCustomDNS(domain) {
    this._customDNS.delete(domain.toLowerCase());
  }

  setDeviceProfile(ip, profileName) {
    this._deviceProfiles.set(ip, profileName);
    if (!this._profileRules.has(profileName)) {
      this._profileRules.set(profileName, { exact: new Map(), suffix: new Map() });
    }
  }

  addProfileRule(profileName, domain, action) {
    if (!this._profileRules.has(profileName)) {
      this._profileRules.set(profileName, { exact: new Map(), suffix: new Map() });
    }
    const p = this._profileRules.get(profileName);
    if (domain.startsWith('.')) p.suffix.set(domain, action);
    else p.exact.set(domain, action);
  }

  _addRule(domain, action) {
    if (!domain || domain.includes('*') || domain.includes('/')) {
      // Skip patterns with paths or wildcards beyond subdomain
      return;
    }

    if (domain.startsWith('.')) {
      // .example.com → match any subdomain of example.com
      this._suffix.set(domain, action);
    } else {
      this._exact.set(domain, action);
    }
  }

  _parseLine(line) {
    // uBlock Origin format: ||domain.com^
    if (line.startsWith('||')) {
      let domain = line.slice(2);
      const sep = domain.indexOf('^');
      if (sep !== -1) domain = domain.slice(0, sep);
      const dollar = domain.indexOf('$');
      if (dollar !== -1) domain = domain.slice(0, dollar);
      if (domain) {
        const action = this._inferAction(line, domain);
        return { domain, action };
      }
    }

    // |domain|  (exact match)
    if (line.startsWith('|') && line.endsWith('|') && line.length > 2) {
      const domain = line.slice(1, -1);
      if (domain && !domain.includes('/')) {
        return { domain, action: 1 };
      }
    }

    // domain.com (bare domain)
    if (!line.startsWith('|') && !line.startsWith('@') && !line.startsWith('!') &&
        line.includes('.') && !line.includes('/') && !line.includes(' ') &&
        !line.includes('#') && !line.startsWith('~')) {
      return { domain: line, action: this._inferAction(line, line) };
    }

    return null;
  }

  _inferAction(line, domain) {
    const lower = line.toLowerCase();
    if (lower.includes('malware') || lower.includes('ransomware') ||
        lower.includes('c2 ') || lower.includes('botnet') || lower.includes('cryptominer')) {
      return 2; // BLOCK_MALWARE
    }
    if (lower.includes('phish') || lower.includes('fraud') || lower.includes('spoof') ||
        lower.includes('login') || lower.includes('secure-') || lower.includes('bank')) {
      return 3; // BLOCK_PHISHING
    }
    return 1; // BLOCK_AD_TRACKER
  }
}

module.exports = FilterEngine;
