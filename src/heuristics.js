class HeuristicsEngine {
  constructor() {
    this.enabled = true;
    this.topDomains = new Set([
      'google.com', 'youtube.com', 'facebook.com', 'baidu.com', 'wikipedia.org',
      'yahoo.com', 'twitter.com', 'instagram.com', 'whatsapp.com', 'amazon.com',
      'netflix.com', 'linkedin.com', 'reddit.com', 'bing.com', 'office.com',
      'live.com', 'microsoft.com', 'apple.com', 'tiktok.com', 'paypal.com'
    ]);
  }

  // Returns { blocked: boolean, reason: string, action: number }
  check(domain) {
    if (!this.enabled || !domain) return { blocked: false };

    // 1. DGA (Domain Generation Algorithm) Detection via Entropy & Consonant ratios
    const parts = domain.toLowerCase().split('.');
    if (parts.length >= 2) {
      const sld = parts[parts.length - 2]; // Second Level Domain
      if (sld.length > 8) {
        if (this._isDGA(sld)) {
          return { blocked: true, reason: 'DGA / High Entropy', action: 2 }; // action 2 = Malware
        }
      }

      // 2. Typosquatting Detection (Levenshtein distance to top domains)
      const baseDomain = parts.slice(-2).join('.');
      if (!this.topDomains.has(baseDomain)) {
        for (const top of this.topDomains) {
          if (Math.abs(baseDomain.length - top.length) <= 1) {
            const dist = this._levenshtein(baseDomain, top);
            if (dist === 1) {
              return { blocked: true, reason: `Typosquatting (${top})`, action: 3 }; // action 3 = Phishing
            }
          }
        }
      }
    }

    return { blocked: false };
  }

  _isDGA(str) {
    let vowels = 0;
    let consonants = 0;
    let numbers = 0;
    
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      if ('aeiou'.includes(c)) vowels++;
      else if ('bcdfghjklmnpqrstvwxyz'.includes(c)) consonants++;
      else if ('0123456789'.includes(c)) numbers++;
    }

    // High number count in long domain without dashes
    if (numbers > str.length * 0.4 && str.length > 8) return true;

    // Too many consonants in a row
    let maxConsRow = 0;
    let curConsRow = 0;
    for (let i = 0; i < str.length; i++) {
      if ('bcdfghjklmnpqrstvwxyz'.includes(str[i])) {
        curConsRow++;
        if (curConsRow > maxConsRow) maxConsRow = curConsRow;
      } else {
        curConsRow = 0;
      }
    }
    
    if (maxConsRow >= 5) return true;
    
    return false;
  }

  _levenshtein(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1)
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }
}

module.exports = HeuristicsEngine;
