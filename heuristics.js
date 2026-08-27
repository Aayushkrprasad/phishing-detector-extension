/**
 * Phishing Detector Pro - Advanced Heuristics Engine
 * Provides mathematical algorithms (Levenshtein Distance, Shannon Entropy),
 * Homoglyph normalization, brand impersonation detection, and risk evaluation.
 */

const ThreatEngine = (() => {
  // Top High-Value Protected Brands and their canonical domains
  const PROTECTED_BRANDS = [
    { name: "Google", domain: "google.com", keywords: ["google", "g00gle", "gmai1", "gmail", "goog1e", "gogle"] },
    { name: "PayPal", domain: "paypal.com", keywords: ["paypal", "paypa1", "paypai", "pay-pal", "paypal-service"] },
    { name: "Microsoft", domain: "microsoft.com", keywords: ["microsoft", "micros0ft", "m1crosoft", "msft", "office365", "outlook", "live"] },
    { name: "Amazon", domain: "amazon.com", keywords: ["amazon", "amaz0n", "amazn", "amazon-security", "amz"] },
    { name: "Apple", domain: "apple.com", keywords: ["apple", "app1e", "apple-id", "icloud", "icl0ud"] },
    { name: "Netflix", domain: "netflix.com", keywords: ["netflix", "netfl1x", "netflx", "netflix-verify"] },
    { name: "Facebook", domain: "facebook.com", keywords: ["facebook", "faceb00k", "face-book", "fb-login", "meta"] },
    { name: "Instagram", domain: "instagram.com", keywords: ["instagram", "instagr4m", "instgrm", "ig-verify"] },
    { name: "Twitter / X", domain: "x.com", keywords: ["twitter", "tw1tter", "x-login"] },
    { name: "Binance", domain: "binance.com", keywords: ["binance", "b1nance", "binance-verify", "binance-us"] },
    { name: "Coinbase", domain: "coinbase.com", keywords: ["coinbase", "c0inbase", "coin-base", "coinbase-login"] },
    { name: "Metamask", domain: "metamask.io", keywords: ["metamask", "metam4sk", "meta-mask", "metamask-wallet"] },
    { name: "GitHub", domain: "github.com", keywords: ["github", "g1thub", "git-hub", "github-auth"] },
    { name: "Dropbox", domain: "dropbox.com", keywords: ["dropbox", "dr0pbox", "drop-box"] },
    { name: "Chase Bank", domain: "chase.com", keywords: ["chase", "chasebank", "chase-online", "jpmorgan"] },
    { name: "Bank of America", domain: "bankofamerica.com", keywords: ["bankofamerica", "bofa", "bofa-online"] },
    { name: "Wells Fargo", domain: "wellsfargo.com", keywords: ["wellsfargo", "wells-fargo", "wf-online"] },
    { name: "Steam", domain: "steampowered.com", keywords: ["steam", "steampowered", "steamcommunity", "steam-trade"] },
    { name: "Telegram", domain: "telegram.org", keywords: ["telegram", "telegrm", "t-me", "telegram-web"] },
    { name: "WhatsApp", domain: "whatsapp.com", keywords: ["whatsapp", "whatsap", "wa-web"] },
    { name: "Paytm", domain: "paytm.com", keywords: ["paytm", "paytm-pay", "paytm-wallet", "paytm-kyc", "paytm-bank"] },
    { name: "PhonePe", domain: "phonepe.com", keywords: ["phonepe", "phone-pe", "phonepe-pay", "phonepe-reward"] },
    { name: "Google Pay (GPay)", domain: "pay.google.com", keywords: ["gpay", "googlepay", "g-pay", "google-pay"] },
    { name: "HDFC Bank", domain: "hdfcbank.com", keywords: ["hdfcbank", "hdfc-bank", "hdfc-netbanking", "hdfc-online"] },
    { name: "SBI Bank", domain: "onlinesbi.sbi", keywords: ["onlinesbi", "sbi-online", "sbi-card", "sbi-netbanking"] },
    { name: "ICICI Bank", domain: "icicibank.com", keywords: ["icicibank", "icici-bank", "icici-netbanking", "icici-online"] },
    { name: "Axis Bank", domain: "axisbank.com", keywords: ["axisbank", "axis-bank", "axis-netbanking"] },
    { name: "Zerodha", domain: "zerodha.com", keywords: ["zerodha", "kite-zerodha", "zerodha-kite", "zerodha-auth"] },
    { name: "Groww", domain: "groww.in", keywords: ["groww", "groww-app", "groww-in"] },
    { name: "Upstox", domain: "upstox.com", keywords: ["upstox", "upstox-pro", "upstox-login"] },
    { name: "Swiggy", domain: "swiggy.com", keywords: ["swiggy", "swiggy-pay", "swiggy-order"] },
    { name: "Zomato", domain: "zomato.com", keywords: ["zomato", "zomato-pay", "zomato-gold"] },
    { name: "Razorpay", domain: "razorpay.com", keywords: ["razorpay", "razor-pay", "razorpay-checkout"] },
    { name: "Cred", domain: "cred.club", keywords: ["cred", "cred-club", "cred-pay"] }
  ];

  // Top Global Canonical Domains for Dynamic Typosquatting
  const CANONICAL_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "twitter.com", "instagram.com", "linkedin.com", "wikipedia.org",
    "yahoo.com", "netflix.com", "reddit.com", "paypal.com", "github.com",
    "dropbox.com", "spotify.com", "whatsapp.com", "zoom.us", "tiktok.com",
    "pinterest.com", "ebay.com", "adobe.com", "wordpress.org", "salesforce.com",
    "tumblr.com", "flickr.com", "imdb.com", "craigslist.org", "hulu.com",
    "twitch.tv", "quora.com", "medium.com", "vimeo.com", "walmart.com",
    "cnn.com", "nytimes.com", "bbc.co.uk", "espn.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "binance.com", "coinbase.com", "metamask.io",
    "steampowered.com", "roblox.com", "discord.com", "telegram.org", "aliexpress.com",
    "paytm.com", "phonepe.com", "hdfcbank.com", "onlinesbi.sbi", "icicibank.com", "axisbank.com",
    "zerodha.com", "groww.in", "upstox.com", "swiggy.com", "zomato.com", "razorpay.com", "cred.club"
  ];

  // High-Risk TLDs frequently abused by phishing campaigns
  const HIGH_RISK_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".link",
    ".work", ".date", ".party", ".loan", ".download", ".racing", ".cricket",
    ".win", ".bid", ".stream", ".trade", ".accountant", ".science", ".faith",
    ".kim", ".rest", ".country", ".gdn", ".mom", ".lol", ".surf", ".cam"
  ];

  // Common homoglyph replacements
  const HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    'i': 'l',
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '5': 's',
    '$': 's',
    '8': 'b',
    'vv': 'w',
    'rn': 'm',
    'cl': 'd'
  };

  /**
   * Calculate Levenshtein Edit Distance between two strings
   */
  function levenshteinDistance(a, b) {
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
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Calculate Shannon Entropy of a string (measures randomness)
   */
  function calculateShannonEntropy(str) {
    if (!str) return 0;
    const frequencies = {};
    for (let char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (let char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  }

  /**
   * Normalize homoglyphs and leetspeak
   */
  function normalizeHomoglyphs(str) {
    let normalized = str.toLowerCase();
    for (let [leet, standard] of Object.entries(HOMOGLYPH_MAP)) {
      normalized = normalized.split(leet).join(standard);
    }
    return normalized;
  }

  /**
   * Extract base domain (e.g. "sub.example.co.uk" -> "example.co.uk" or "sub.example.com" -> "example.com")
   */
  function getBaseDomain(hostname) {
    if (!hostname) return "";
    hostname = hostname.toLowerCase().trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname; // IP

    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;

    const secondLevelTlds = ["co.uk", "com.au", "co.in", "com.br", "org.uk", "gov.in", "ac.uk"];
    const lastTwo = parts.slice(-2).join(".");
    if (secondLevelTlds.includes(lastTwo) && parts.length > 2) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  /**
   * Comprehensive URL & Hostname Assessment
   */
  function evaluateUrlThreat(rawUrl) {
    let risk = 0;
    const threats = [];
    const metrics = {};

    if (!rawUrl) return { risk: 0, threats: [], metrics: {}, level: "SAFE" };

    let urlObj;
    try {
      urlObj = new URL(rawUrl);
    } catch (e) {
      return {
        risk: 80,
        threats: [{ icon: "⚠️", type: "MALFORMED_URL", text: "Malformed or invalid URL scheme." }],
        metrics: {},
        level: "HIGH_RISK"
      };
    }

    const host = urlObj.hostname.toLowerCase();
    const pathname = urlObj.pathname.toLowerCase();
    const search = urlObj.search.toLowerCase();
    const baseDomain = getBaseDomain(host);
    const mainName = baseDomain.split(".")[0];

    // 1. Insecure Protocol Check
    if (urlObj.protocol === "http:") {
      risk += 25;
      threats.push({ icon: "🔓", type: "INSECURE_HTTP", text: "Insecure unencrypted HTTP connection." });
      metrics.ssl = "Insecure (HTTP)";
    } else if (urlObj.protocol === "https:") {
      metrics.ssl = "Valid SSL/TLS";
    }

    // 2. IP Address in Hostname Check
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      risk += 45;
      threats.push({ icon: "🌐", type: "RAW_IP", text: "Uses direct IP address instead of registered domain." });
      metrics.hostType = "Direct IP";
    } else {
      metrics.hostType = "Domain Name";
    }

    // 3. Punycode / Internationalized Domain Names (IDN Homograph attack)
    if (host.includes("xn--")) {
      risk += 45;
      threats.push({ icon: "🔤", type: "PUNYCODE", text: "Punycode domain detected (High risk of Cyrillic/Greek character spoofing)." });
      metrics.punycode = true;
    }

    // 4. Suspicious TLD Check
    const matchedTLD = HIGH_RISK_TLDS.find(tld => host.endsWith(tld));
    if (matchedTLD) {
      risk += 35;
      threats.push({ icon: "🚩", type: "RISKY_TLD", text: `High-risk top-level domain (${matchedTLD}) frequently used in scam campaigns.` });
      metrics.tld = matchedTLD;
    } else {
      metrics.tld = host.substring(host.lastIndexOf("."));
    }

    // 5. URL Shannon Entropy (DGA / Randomness detection)
    const entropy = calculateShannonEntropy(mainName);
    metrics.entropy = entropy;
    if (entropy > 3.8 && mainName.length > 9) {
      risk += 30;
      threats.push({ icon: "🎲", type: "HIGH_ENTROPY", text: `Domain exhibits high Shannon Entropy (${entropy}), indicating an Algorithmically Generated Domain (DGA).` });
    }

    // 6. Excessive Subdomains Check
    const subdomains = host.split(".");
    if (subdomains.length >= 4) {
      risk += 25;
      threats.push({ icon: "🪜", type: "EXCESSIVE_SUBDOMAINS", text: `Deep subdomain nesting (${subdomains.length} levels) often used to camouflage true target.` });
    }

    // 7. Embedded '@' or Basic Auth Spoofing
    if (rawUrl.includes("@")) {
      risk += 40;
      threats.push({ icon: "📧", type: "AUTH_SPOOFING", text: "URL contains '@' symbol to mislead the browser destination." });
    }

    // 8. Typosquatting via Dynamic Levenshtein Distance against Top 100 Domains
    let typosquattingFound = false;
    for (const canonical of CANONICAL_DOMAINS) {
      const canonicalMain = canonical.split(".")[0];
      if (mainName === canonicalMain) {
        // Exact main match on different TLD/base domain
        if (baseDomain !== canonical && !host.endsWith("." + canonical)) {
          risk += 45;
          threats.push({
            icon: "🎭",
            type: "BRAND_SPOOFING",
            text: `Impersonates '${canonical}' using a rogue domain '${baseDomain}'.`
          });
          typosquattingFound = true;
          metrics.targetBrand = canonical;
          break;
        }
      } else {
        const dist = levenshteinDistance(mainName, canonicalMain);
        if (dist === 1 && mainName.length >= 4 && baseDomain !== canonical) {
          risk += 50;
          threats.push({
            icon: "🎯",
            type: "TYPOSQUATTING",
            text: `Typosquatting detected: '${mainName}' is 1 character away from legitimate '${canonical}'.`
          });
          typosquattingFound = true;
          metrics.targetBrand = canonical;
          break;
        }
      }
    }

    // 9. Protected Brands Impersonation & Keyword Squatting
    if (!typosquattingFound) {
      for (const brand of PROTECTED_BRANDS) {
        const isOfficial = host === brand.domain || host.endsWith("." + brand.domain);
        if (!isOfficial) {
          const normalizedHost = normalizeHomoglyphs(host);
          for (const kw of brand.keywords) {
            if (host.includes(kw) || normalizedHost.includes(kw)) {
              risk += 40;
              threats.push({
                icon: "🛡️",
                type: "BRAND_KEYWORD",
                text: `Unauthorized brand keyword '${kw}' used on unofficial domain (Target: ${brand.name}).`
              });
              metrics.targetBrand = brand.name;
              break;
            }
          }
        }
      }
    }

    // 10. Phishing Target Actions in Path / Query
    const actionKeywords = ["verify", "verification", "secure-login", "account-update", "confirm-identity", "billing-update", "wallet-connect", "claim-reward", "recover-account"];
    const foundAction = actionKeywords.find(k => pathname.includes(k) || search.includes(k));
    if (foundAction && risk > 0) {
      risk += 20;
      threats.push({ icon: "⚡", type: "DECEPTIVE_PATH", text: `Suspicious action path detected ('/${foundAction}').` });
    }

    // Bound risk to 0-100
    risk = Math.min(Math.max(risk, 0), 100);

    let level = "SAFE";
    if (risk >= 60) level = "HIGH_RISK";
    else if (risk >= 25) level = "SUSPICIOUS";

    return {
      risk,
      level,
      threats,
      metrics,
      hostname: host,
      baseDomain
    };
  }

  /**
   * VirusTotal Online Threat Intelligence API Helper
   */
  async function queryVirusTotalThreat(rawUrl, apiKey) {
    if (!rawUrl || !apiKey) return { success: false, reason: "Missing URL or API Key" };
    try {
      const urlId = btoa(rawUrl).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        method: "GET",
        headers: { "x-apikey": apiKey }
      });
      if (!resp.ok) return { success: false, status: resp.status, reason: "VirusTotal API call failed or key invalid" };
      const data = await resp.json();
      const stats = data.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      return {
        success: true,
        malicious,
        suspicious,
        harmless: stats.harmless || 0,
        total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
        threatLevel: malicious > 2 ? "HIGH_RISK" : malicious > 0 || suspicious > 1 ? "SUSPICIOUS" : "SAFE"
      };
    } catch (e) {
      return { success: false, reason: e.message };
    }
  }

  return {
    PROTECTED_BRANDS,
    CANONICAL_DOMAINS,
    HIGH_RISK_TLDS,
    levenshteinDistance,
    calculateShannonEntropy,
    normalizeHomoglyphs,
    getBaseDomain,
    evaluateUrlThreat,
    queryVirusTotalThreat
  };
})();

if (typeof window !== "undefined") {
  window.ThreatEngine = ThreatEngine;
}
if (typeof self !== "undefined") {
  self.ThreatEngine = ThreatEngine;
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = ThreatEngine;
}
