const https = require('https');
const dgram = require('dgram');
const { URL } = require('url');

function buildDNSQuery(domain, type = 1) {
  const labels = domain.split('.');
  const buf = Buffer.alloc(17 + domain.length + 1);
  let off = 0;
  buf.writeUInt16BE(0x1234, off); off += 2; // ID
  buf.writeUInt16BE(0x0100, off); off += 2; // flags: recursion desired
  buf.writeUInt16BE(1, off); off += 2;       // questions
  buf.writeUInt16BE(0, off); off += 2;       // answers
  buf.writeUInt16BE(0, off); off += 2;       // authority
  buf.writeUInt16BE(0, off); off += 2;       // additional
  for (const label of labels) {
    buf[off++] = label.length;
    buf.write(label, off, 'ascii');
    off += label.length;
  }
  buf[off++] = 0; // end of labels
  buf.writeUInt16BE(type, off); off += 2;    // type A
  buf.writeUInt16BE(1, off);                 // class IN
  return buf;
}

function parseDNSResponse(msg) {
  const answers = [];
  let off = 12;
  const qdcount = msg.readUInt16BE(4);
  for (let i = 0; i < qdcount; i++) {
    while (off < msg.length && msg[off] !== 0) {
      if ((msg[off] & 0xC0) === 0xC0) { off += 2; break; }
      off += msg[off] + 1;
    }
    off += 5; // null label + type + class
  }
  const ancount = msg.readUInt16BE(6);
  for (let i = 0; i < ancount; i++) {
    // name
    if ((msg[off] & 0xC0) === 0xC0) off += 2;
    else { while (msg[off] !== 0) off++; off++; }
    const type = msg.readUInt16BE(off); off += 2;
    off += 2; // class
    off += 4; // TTL
    const rdlen = msg.readUInt16BE(off); off += 2;
    if (type === 1 && rdlen === 4) {
      const ip = `${msg[off]}.${msg[off+1]}.${msg[off+2]}.${msg[off+3]}`;
      answers.push(ip);
    }
    off += rdlen;
  }
  return answers;
}

function dgramResolve(hostname, resolverIP = '1.1.1.1', timeout = 3000) {
  return new Promise((resolve, reject) => {
    const query = buildDNSQuery(hostname);
    const sock = dgram.createSocket('udp4');
    const timer = setTimeout(() => {
      sock.close();
      reject(new Error(`Bootstrap DNS timeout for ${hostname}`));
    }, timeout);

    sock.on('message', (msg) => {
      clearTimeout(timer);
      sock.close();
      const ips = parseDNSResponse(msg);
      if (ips.length > 0) resolve(ips[0]);
      else reject(new Error(`No A record for ${hostname}`));
    });

    sock.on('error', (err) => {
      clearTimeout(timer);
      sock.close();
      reject(err);
    });

    sock.send(query, 0, query.length, 53, resolverIP);
  });
}

class DoHClient {
  constructor(url = 'https://cloudflare-dns.com/dns-query', bootstrapIP = '1.1.1.1') {
    this.url = url;
    this.bootstrapIP = bootstrapIP;
    this.timeout = 5000;
    this._resolvedIP = null;
  }

  async _getResolvedIP() {
    if (this._resolvedIP) return this._resolvedIP;
    const url = new URL(this.url);
    const ip = await dgramResolve(url.hostname, this.bootstrapIP);
    this._resolvedIP = ip;
    // Re-resolve every 10 minutes in case IP changes
    setTimeout(() => { this._resolvedIP = null; }, 10 * 60 * 1000);
    return ip;
  }

  async resolve(queryBuffer) {
    const url = new URL(this.url);
    const ip = await this._getResolvedIP();

    return new Promise((resolve, reject) => {
      const opts = {
        hostname: ip,
        servername: url.hostname, // TLS SNI
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message',
          'Content-Length': queryBuffer.length,
          'Host': url.hostname,
        },
        timeout: this.timeout,
        rejectUnauthorized: false,
        lookup: (host, options, cb) => cb(null, ip, 4),
      };

      const req = https.request(opts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('DoH timeout')); });
      req.write(queryBuffer);
      req.end();
    });
  }

  async resolveJSON(domain, type = 'A') {
    const url = new URL(this.url);
    url.searchParams.set('name', domain);
    url.searchParams.set('type', type);
    const ip = await this._getResolvedIP();

    return new Promise((resolve, reject) => {
      const opts = {
        hostname: ip,
        servername: url.hostname,
        port: 443,
        path: url.pathname + url.search,
        method: 'GET',
        headers: {
          'Accept': 'application/dns-json',
          'Host': url.hostname,
        },
        rejectUnauthorized: false,
        timeout: this.timeout,
      };

      opts.lookup = (host, options, cb) => cb(null, ip, 4);
      https.get(opts, (res) => {
        let data = '';
        res.on('data', (c) => data += c);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(e); }
        });
      }).on('error', reject);
    });
  }
}

module.exports = DoHClient;
