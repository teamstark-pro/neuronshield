const dgram = require('dgram');
const DoHClient = require('./doh-client');
const HeuristicsEngine = require('./heuristics');

// Minimal DNS wire-protocol parser/builder
// Only handles the parts we need for proxying

class DNSServer {
  constructor(filterEngine, options = {}) {
    this.filter = filterEngine;
    this.heuristics = new HeuristicsEngine();
    this.doh = new DoHClient(options.dohUrl || 'https://cloudflare-dns.com/dns-query');
    this.port = options.port || 8053;
    this.address = options.address || '127.0.0.1';
    this.sinkhole = options.sinkhole || '0.0.0.0';
    this.blockTTL = options.blockTTL || 60;
    this.onBlock = options.onBlock || (() => {});
    this.onQuery = options.onQuery || (() => {});
    this.server = null;
    this.actualPort = null;
    
    // Rate Limiting
    this.rateLimits = new Map(); // ip -> { count, expire }
    
    // Safe Search mapping
    this.safeSearch = {
      'google.com': '216.239.38.120',
      'www.google.com': '216.239.38.120',
      'bing.com': '204.79.197.220',
      'www.bing.com': '204.79.197.220',
      'youtube.com': '216.239.38.120',
      'www.youtube.com': '216.239.38.120',
      'm.youtube.com': '216.239.38.120',
    };
    this.enableSafeSearch = true;
    this.enableRebindingProtection = true;
  }

  start() {
    this._tryBind(this.port);
  }

  _tryBind(port) {
    const server = dgram.createSocket('udp4');

    server.on('message', (msg, rinfo) => {
      this._handleQuery(msg, rinfo).catch(err => {
        console.error('[DNS] Error handling query:', err.message);
      });
    });

    server.on('error', (err) => {
      const isConflict = err.code === 'EADDRINUSE' || err.code === 'EACCES';
      if (isConflict && port === 53) {
        server.close();
        console.log('[DNS] Port 53 in use (Windows DNS service). Trying alternate port...');
        this._tryBind(8053);
        return;
      }
      if (isConflict && port < 9090) {
        server.close();
        this._tryBind(port + 1);
        return;
      }
      console.error('[DNS] Server error:', err.message);
    });

    server.bind(port, this.address, () => {
      this.server = server;
      this.actualPort = port;
      console.log(`[DNS] Listening on ${this.address}:${port}`);
    });
  }

  stop() {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }

  async _handleQuery(msg, rinfo) {
    const clientIP = rinfo.address;
    
    // Rate Limiting (max 100 reqs per 10s)
    const now = Date.now();
    let rl = this.rateLimits.get(clientIP);
    if (!rl || rl.expire < now) rl = { count: 0, expire: now + 10000 };
    rl.count++;
    this.rateLimits.set(clientIP, rl);
    if (rl.count > 100) {
      if (rl.count === 101) console.log(`[DNS] Rate limited: ${clientIP}`);
      return; // Drop packet silently
    }

    const domain = this._parseDomain(msg);
    if (!domain) {
      const reply = await this.doh.resolve(msg).catch(() => null);
      if (reply) this._send(reply, rinfo);
      return;
    }

    // 1. Safe Search Enforcement
    if (this.enableSafeSearch && this.safeSearch[domain]) {
      this.onQuery({ domain, action: 0, blocked: false, client: clientIP, tag: 'SAFE_SEARCH' });
      const reply = this._buildA(msg, domain, this.safeSearch[domain]);
      this._send(reply, rinfo);
      return;
    }

    // 2. Filter Engine
    const result = this.filter.match(domain, clientIP); // Pass IP for device profiles
    
    // 3. Heuristics
    let heurResult = null;
    if (!result) {
      heurResult = this.heuristics.check(domain);
    }

    const action = result ? result.action : (heurResult && heurResult.blocked ? heurResult.action : 0);
    const blocked = !!result || (heurResult && heurResult.blocked);
    const rule = result ? result.rule : (heurResult ? heurResult.reason : null);

    this.onQuery({ domain, action, blocked, client: clientIP });

    if (result && result.action === 4) {
      // Custom DNS
      this.onQuery({ domain, action: 4, blocked: false, client: clientIP, tag: 'CUSTOM' });
      const reply = this._buildA(msg, domain, result.ip);
      this._send(reply, rinfo);
      return;
    }

    if (blocked) {
      this.onBlock({ domain, action, rule, client: clientIP });
      const reply = this._buildNX(msg, domain, action);
      this._send(reply, rinfo);
      return;
    }

    try {
      const reply = await this.doh.resolve(msg);
      
      // 4. DNS Rebinding Protection
      if (this.enableRebindingProtection) {
        if (this._hasPrivateIP(reply)) {
          this.onBlock({ domain, action: 2, rule: 'DNS_REBINDING', client: clientIP });
          const nx = this._buildNX(msg, domain, 2);
          this._send(nx, rinfo);
          return;
        }
      }
      
      this._send(reply, rinfo);
    } catch (err) {
      console.error(`[DNS] DoH error for ${domain}:`, err.message);
    }
  }

  _hasPrivateIP(msg) {
    // Basic parser to check answers for private IPs
    try {
      const ancount = msg.readUInt16BE(6);
      if (ancount === 0) return false;
      let off = 12;
      const qdcount = msg.readUInt16BE(4);
      for (let i = 0; i < qdcount; i++) {
        while (msg[off] !== 0) { if ((msg[off] & 0xC0) === 0xC0) { off += 2; break; } else off += msg[off] + 1; }
        if (msg[off] === 0) off++;
        off += 4;
      }
      for (let i = 0; i < ancount; i++) {
        if ((msg[off] & 0xC0) === 0xC0) off += 2; else { while (msg[off] !== 0) off++; off++; }
        const type = msg.readUInt16BE(off); off += 2;
        off += 6; // class + ttl
        const rdlen = msg.readUInt16BE(off); off += 2;
        if (type === 1 && rdlen === 4) {
          const ip = `${msg[off]}.${msg[off+1]}.${msg[off+2]}.${msg[off+3]}`;
          if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('127.') || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) {
            return true;
          }
        }
        off += rdlen;
      }
    } catch (e) {}
    return false;
  }

  _parseDomain(msg) {
    try {
      if (msg.length < 12) return null;
      let idx = 12;
      let domain = '';
      while (idx < msg.length) {
        const len = msg[idx++];
        if (len === 0) break;
        if (len > 63) return null; // DNS compression not supported in parser
        if (domain) domain += '.';
        for (let i = 0; i < len; i++) {
          domain += String.fromCharCode(msg[idx++]);
        }
      }
      return domain || null;
    } catch {
      return null;
    }
  }

  _buildNX(originalMsg, domain, action) {
    const buf = Buffer.alloc(originalMsg.length);
    originalMsg.copy(buf, 0, 0, 12);
    buf[2] = originalMsg[2] & 0x01; // keep RD
    buf[2] |= 0x80; // QR
    buf[3] = 0x83;  // RA + RCODE=3 (NXDOMAIN)
    originalMsg.copy(buf, 12, 12, originalMsg.length);
    buf[4] = 0; buf[5] = 1;
    return buf;
  }

  _buildA(originalMsg, domain, ipStr) {
    // Build a positive A record response
    const qlen = originalMsg.length - 12;
    const buf = Buffer.alloc(12 + qlen + 16);
    originalMsg.copy(buf, 0, 0, 12 + qlen);
    
    buf[2] = originalMsg[2] & 0x01;
    buf[2] |= 0x80;
    buf[3] = 0x80; // No error
    
    // ANCOUNT = 1
    buf[6] = 0; buf[7] = 1;
    
    let off = 12 + qlen;
    // Name pointer to question
    buf[off++] = 0xc0; buf[off++] = 0x0c;
    // Type A
    buf[off++] = 0; buf[off++] = 1;
    // Class IN
    buf[off++] = 0; buf[off++] = 1;
    // TTL 300
    buf.writeUInt32BE(300, off); off += 4;
    // RDLENGTH 4
    buf[off++] = 0; buf[off++] = 4;
    // RDATA
    const parts = ipStr.split('.');
    for (let i=0; i<4; i++) buf[off++] = parseInt(parts[i], 10);
    
    return buf;
  }

  _send(msg, rinfo) {
    if (this.server) {
      this.server.send(msg, rinfo.port, rinfo.address);
    }
  }
}

module.exports = DNSServer;
