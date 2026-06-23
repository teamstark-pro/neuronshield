const https = require('https');
const fs = require('fs');
const path = require('path');

const DEFAULT_LISTS = [
  {
    name: 'Brave Specific',
    url: 'https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt',
    file: 'brave_specific.txt',
    format: 'ublock',
    enabled: true,
  },
  {
    name: 'Brave Unbreak',
    url: 'https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-unbreak.txt',
    file: 'brave_unbreak.txt',
    format: 'ublock',
    enabled: true,
  },
  {
    name: 'Brave Social',
    url: 'https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-social.txt',
    file: 'brave_social.txt',
    format: 'ublock',
    enabled: true,
  },
  {
    name: 'uBlock Origin EasyList',
    url: 'https://easylist.to/easylist/easylist.txt',
    file: 'easylist.txt',
    format: 'ublock',
    enabled: true,
  },
  {
    name: 'uBlock Origin EasyPrivacy',
    url: 'https://easylist.to/easylist/easyprivacy.txt',
    file: 'easyprivacy.txt',
    format: 'ublock',
    enabled: true,
  },
  {
    name: 'Malware Domain List',
    url: 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt',
    file: 'malware_domains.txt',
    format: 'hosts',
    enabled: true,
  },
  {
    name: 'Peter Lowe\'s List',
    url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext',
    file: 'peters_list.txt',
    format: 'hosts',
    enabled: true,
  },
  {
    name: 'Phishing URL Blocklist',
    url: 'https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/pihole-phishing-adlist.txt',
    file: 'phishing.txt',
    format: 'hosts',
    enabled: true,
  },
  {
    name: 'OISD Big List',
    url: 'https://big.oisd.nl/domainswild2',
    file: 'oisd_big.txt',
    format: 'domains',
    enabled: false,
  },
];

const LIST_DIR = path.join(__dirname, '..', 'data', 'lists');

class ListsLoader {
  constructor() {
    this.listsDir = LIST_DIR;
    this._ensureDir();
  }

  _ensureDir() {
    if (!fs.existsSync(this.listsDir)) {
      fs.mkdirSync(this.listsDir, { recursive: true });
    }
  }

  getLists() { return DEFAULT_LISTS; }

  async fetchAll(onProgress) {
    const results = [];
    for (const list of DEFAULT_LISTS) {
      if (!list.enabled) {
        results.push({ name: list.name, status: 'skipped' });
        continue;
      }
      try {
        if (onProgress) onProgress(list.name, 'downloading');
        const content = await this._fetch(list.url);
        const filePath = path.join(this.listsDir, list.file);
        fs.writeFileSync(filePath, content, 'utf-8');
        const size = Buffer.byteLength(content, 'utf-8');
        if (onProgress) onProgress(list.name, 'done', size);
        results.push({ name: list.name, status: 'ok', size });
      } catch (err) {
        if (onProgress) onProgress(list.name, 'failed', err.message);
        results.push({ name: list.name, status: 'failed', error: err.message });
      }
    }
    return results;
  }

  getListPath(file) {
    return path.join(this.listsDir, file);
  }

  _fetch(url) {
    return new Promise((resolve, reject) => {
      https.get(url, { headers: { 'User-Agent': 'BraveNetworkShield/1.0' } }, (res) => {
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        let data = '';
        res.on('data', (c) => data += c);
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
  }
}

// Run directly to update lists
if (require.main === module) {
  const loader = new ListsLoader();
  console.log('Updating filter lists...\n');
  loader.fetchAll((name, status, extra) => {
    const icon = status === 'done' ? 'OK' : status === 'downloading' ? '..' : 'FAIL';
    const extraStr = extra ? ` (${extra})` : '';
    console.log(`  [${icon}] ${name}${extra ? '' : ''}${extraStr}`);
  }).then(() => console.log('\nDone.'));
}

module.exports = ListsLoader;
