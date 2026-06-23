const fs = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, '..', 'config.json');

const DEFAULTS = {
  dns: {
    port: 53,
    address: '127.0.0.1',
    dohUrl: 'https://cloudflare-dns.com/dns-query',
    fallbackDohUrl: 'https://dns.google/dns-query',
    sinkhole: '0.0.0.0',
    blockTTL: 60,
  },
  dashboard: {
    port: 3000,
    address: '127.0.0.1',
  },
  lists: {
    autoUpdate: true,
    updateIntervalHours: 24,
  },
};

class Config {
  constructor() {
    this._data = { ...DEFAULTS };
    this._load();
  }

  get data() { return this._data; }

  get(key) {
    const parts = key.split('.');
    let val = this._data;
    for (const p of parts) {
      if (val == null || typeof val !== 'object') return undefined;
      val = val[p];
    }
    return val;
  }

  set(key, value) {
    const parts = key.split('.');
    let obj = this._data;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!obj[parts[i]] || typeof obj[parts[i]] !== 'object') {
        obj[parts[i]] = {};
      }
      obj = obj[parts[i]];
    }
    obj[parts[parts.length - 1]] = value;
    this._save();
  }

  _load() {
    try {
      if (fs.existsSync(CONFIG_PATH)) {
        const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
        const user = JSON.parse(raw);
        this._deepMerge(this._data, user);
      }
    } catch (err) {
      console.error('[Config] Failed to load config:', err.message);
    }
  }

  _save() {
    try {
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(this._data, null, 2), 'utf-8');
    } catch (err) {
      console.error('[Config] Failed to save config:', err.message);
    }
  }

  _deepMerge(target, source) {
    for (const key of Object.keys(source)) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        if (!target[key]) target[key] = {};
        this._deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
}

module.exports = new Config();
