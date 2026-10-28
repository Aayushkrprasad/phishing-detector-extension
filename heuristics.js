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
      const allBrands = [...PROTECTED_BRANDS, ...(ThreatEngine.customBrands || [])];
      for (const brand of allBrands) {
        const isOfficial = host === brand.domain || host.endsWith("." + brand.domain);
        if (!isOfficial) {
          const normalizedHost = normalizeHomoglyphs(host);
          for (const kw of (brand.keywords || [brand.name.toLowerCase()])) {
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
   * Evaluate Email, SMS & Social Engineering Text Content for Phishing Indicators
   */
  function evaluateTextThreat(rawText) {
    if (!rawText || typeof rawText !== "string") {
      return { risk: 0, level: "SAFE", threats: [], urgencyScore: 0, extractedUrls: [], recommendations: [] };
    }

    let risk = 0;
    let urgencyScore = 0;
    const threats = [];
    const recommendations = [];
    const textLower = rawText.toLowerCase();

    // 1. High-Urgency & Panic Triggers
    const urgencyKeywords = [
      { kw: "account will be suspended", risk: 25, urgency: 30, text: "Artificial urgency: Threat of account suspension." },
      { kw: "immediate action required", risk: 20, urgency: 25, text: "High urgency trigger: Requires immediate action." },
      { kw: "unauthorized login attempt", risk: 20, urgency: 20, text: "Scare tactic: Claims unauthorized access occurred." },
      { kw: "within 24 hours", risk: 15, urgency: 25, text: "Time pressure: Imposes 24-hour deadline." },
      { kw: "final notice", risk: 25, urgency: 30, text: "Coercive warning: Uses 'final notice' pressure." },
      { kw: "security breach", risk: 20, urgency: 20, text: "Security scare tactic: Mentions security breach." }
    ];

    for (const item of urgencyKeywords) {
      if (textLower.includes(item.kw)) {
        risk += item.risk;
        urgencyScore += item.urgency;
        threats.push({ icon: "⏳", type: "URGENCY_TRIGGER", text: item.text });
      }
    }

    // 2. Financial & Gift Scam Patterns
    const financialScams = [
      { kw: "claim your gift card", risk: 30, text: "Reward scam: Offers free gift card/prize." },
      { kw: "you have won", risk: 30, text: "Lottery/Winner scam: Claims recipient won a prize." },
      { kw: "wire transfer", risk: 25, text: "Financial request: Asks for wire transfer." },
      { kw: "bitcoin payment", risk: 30, text: "Cryptocurrency demand: Mentions Bitcoin/Crypto payment." },
      { kw: "refund pending", risk: 20, text: "Refund bait: Claims pending money refund." },
      { kw: "kyc update required", risk: 25, text: "Banking scam: Demands immediate KYC update." }
    ];

    for (const item of financialScams) {
      if (textLower.includes(item.kw)) {
        risk += item.risk;
        threats.push({ icon: "💰", type: "FINANCIAL_SCAM", text: item.text });
      }
    }

    // 3. Credential & Sensitive Data Harvesting Demands
    const credentialHarvesters = [
      { kw: "verify your password", risk: 35, text: "Credential harvesting: Demands password verification." },
      { kw: "send your otp", risk: 40, text: "OTP theft: Asks for One-Time Password." },
      { kw: "seed phrase", risk: 45, text: "Crypto theft: Mentions 12/24 word seed phrase." },
      { kw: "social security number", risk: 35, text: "PII harvesting: Requests SSN or government ID." },
      { kw: "confirm credit card", risk: 35, text: "Payment theft: Asks to confirm credit card details." }
    ];

    for (const item of credentialHarvesters) {
      if (textLower.includes(item.kw)) {
        risk += item.risk;
        threats.push({ icon: "🔑", type: "CREDENTIAL_HARVEST", text: item.text });
      }
    }

    // 4. Extract and analyze embedded URLs
    const urlRegex = /(https?:\/\/[^\s<"'>]+)/gi;
    const extractedRawUrls = rawText.match(urlRegex) || [];
    const extractedUrls = [];

    for (const rawUrl of extractedRawUrls) {
      const evalResult = evaluateUrlThreat(rawUrl);
      extractedUrls.push({ url: rawUrl, evaluation: evalResult });
      if (evalResult.risk >= 50) {
        risk += 35;
        threats.push({
          icon: "🔗",
          type: "SUSPICIOUS_EMBEDDED_URL",
          text: `Contains high-risk embedded link: ${evalResult.hostname} (${evalResult.threats[0]?.text || "Flagged link"})`
        });
      } else if (evalResult.risk >= 25) {
        risk += 15;
        threats.push({
          icon: "⚠️",
          type: "WARNED_EMBEDDED_URL",
          text: `Contains suspicious link: ${evalResult.hostname}`
        });
      }
    }

    // Bound risk to 0-100
    risk = Math.min(Math.max(risk, 0), 100);
    urgencyScore = Math.min(Math.max(urgencyScore, 0), 100);

    let level = "SAFE";
    if (risk >= 60) level = "HIGH_RISK";
    else if (risk >= 25) level = "SUSPICIOUS";

    // Build Recommendations
    if (risk >= 60) {
      recommendations.push("Do not click any links or download attachments in this message.");
      recommendations.push("Do not reply with passwords, OTPs, or financial details.");
      recommendations.push("Verify sender by contacting the organization directly via official phone or website.");
    } else if (risk >= 25) {
      recommendations.push("Exercise caution before clicking links in this email.");
      recommendations.push("Check sender domain carefully for typosquatting or homoglyphs.");
    } else {
      recommendations.push("No obvious social engineering flags detected in text.");
    }

    return {
      risk,
      level,
      threats,
      urgencyScore,
      extractedUrls,
      recommendations
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

  const customBrands = [];

  function registerCustomBrand(name, domain) {
    if (!name || !domain) return;
    const kw = name.toLowerCase().replace(/\s+/g, "");
    customBrands.push({ name, domain, keywords: [kw] });
    CANONICAL_DOMAINS.push(domain);
  }

  /**
   * Academic Thesis & Journal Hijacking Integrity Engine
   * Detects:
   * 1. DOI Registry matching & Authority Cross-Referencing
   * 2. Hijacked / Cloned Academic Journals (Predatory mirrors masquerading as legitimate journals)
   * 3. Thesis Link Manipulation & Mirror Spoofing (altering paper hosting to unauthorized clones)
   * 4. Fake / Predatory Publisher Domain permutations
   */
  const ACADEMIC_PUBLISHER_REGISTRY = {
    "10.1109": { name: "IEEE (Institute of Electrical and Electronics Engineers)", domains: ["ieeexplore.ieee.org", "ieee.org"] },
    "10.1145": { name: "ACM (Association for Computing Machinery)", domains: ["dl.acm.org", "acm.org"] },
    "10.1038": { name: "Nature Publishing Group", domains: ["nature.com"] },
    "10.1007": { name: "Springer Nature", domains: ["link.springer.com", "springer.com"] },
    "10.1186": { name: "BioMed Central / SpringerOpen", domains: ["biomedcentral.com", "springeropen.com"] },
    "10.1016": { name: "Elsevier / ScienceDirect", domains: ["sciencedirect.com", "elsevier.com"] },
    "10.1002": { name: "Wiley Online Library", domains: ["onlinelibrary.wiley.com", "wiley.com"] },
    "10.1111": { name: "Wiley Online Library", domains: ["onlinelibrary.wiley.com", "wiley.com"] },
    "10.1126": { name: "Science / AAAS", domains: ["science.org", "sciencemag.org"] },
    "10.48550": { name: "arXiv Repository (Cornell)", domains: ["arxiv.org"] },
    "10.1371": { name: "PLOS (Public Library of Science)", domains: ["journals.plos.org", "plos.org"] },
    "10.1093": { name: "Oxford University Press", domains: ["academic.oup.com", "oup.com"] },
    "10.1017": { name: "Cambridge University Press", domains: ["cambridge.org"] },
    "10.1021": { name: "ACS Publications (American Chemical Society)", domains: ["pubs.acs.org", "acs.org"] },
    "10.1088": { name: "IOP Publishing", domains: ["iopscience.iop.org"] },
    "10.1073": { name: "PNAS (National Academy of Sciences)", domains: ["pnas.org"] },
    "10.3390": { name: "MDPI Open Access", domains: ["mdpi.com"] },
    "10.3389": { name: "Frontiers", domains: ["frontiersin.org"] }
  };

  const VERIFIED_ACADEMIC_REPOSITORIES = [
    "scholar.google.com", "arxiv.org", "researchgate.net", "semanticscholar.org",
    "ncbi.nlm.nih.gov", "pubmed.ncbi.nlm.nih.gov", "jstor.org", "crossref.org",
    "datacite.org", "doi.org", "dx.doi.org", "ssrn.com", "biorxiv.org", "medrxiv.org",
    "core.ac.uk", "citeseerx.ist.psu.edu", "zenodo.org", "osf.io"
  ];

  const ACADEMIC_BRAND_TARGETS = [
    { name: "IEEE Xplore", domain: "ieeexplore.ieee.org", keywords: ["ieee", "ieeexplore", "ieee-explore"] },
    { name: "ScienceDirect", domain: "sciencedirect.com", keywords: ["sciencedirect", "science-direct", "elsevier"] },
    { name: "Springer", domain: "springer.com", keywords: ["springer", "springerlink", "springer-nature"] },
    { name: "Nature", domain: "nature.com", keywords: ["nature-journal", "nature-publishing"] },
    { name: "arXiv", domain: "arxiv.org", keywords: ["arxiv", "ar-xiv", "arxiv-mirror"] },
    { name: "Google Scholar", domain: "scholar.google.com", keywords: ["scholar-google", "googlescholar"] },
    { name: "ResearchGate", domain: "researchgate.net", keywords: ["researchgate", "research-gate"] }
  ];

  function evaluateAcademicPaperIntegrity(inputUrlOrDoi, pageContext = {}) {
    if (!inputUrlOrDoi || typeof inputUrlOrDoi !== "string") {
      return { riskScore: 0, status: "INVALID_INPUT", threats: [], recommendations: [] };
    }

    const trimmed = inputUrlOrDoi.trim();
    let detectedDoi = null;
    let targetUrl = null;
    let hostname = "";

    // 1. Detect DOI pattern: 10.xxxx/yyyy
    const doiMatch = trimmed.match(/\b(10\.\d{4,9}\/[-._;()/:A-Za-z0-9]+)\b/i);
    if (doiMatch) {
      detectedDoi = doiMatch[1];
    }

    // 2. Parse Hostname if URL
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      try {
        const u = new URL(trimmed);
        hostname = u.hostname.toLowerCase();
        targetUrl = trimmed;
      } catch (e) {
        hostname = trimmed.toLowerCase();
      }
    } else if (trimmed.includes(".")) {
      hostname = trimmed.split("/")[0].toLowerCase();
    }

    let riskScore = 0;
    const threats = [];
    const recommendations = [];
    let expectedPublisher = null;
    let officialDomains = [];
    let status = "UNVERIFIED_SOURCE";

    // 3. Inspect DOI Authority Match
    if (detectedDoi) {
      const doiPrefix = detectedDoi.split("/")[0].toLowerCase();
      const registryEntry = ACADEMIC_PUBLISHER_REGISTRY[doiPrefix];

      if (registryEntry) {
        expectedPublisher = registryEntry.name;
        officialDomains = registryEntry.domains;

        const isOfficialHost = officialDomains.some(d => hostname === d || hostname.endsWith("." + d));
        const isVerifiedRepo = VERIFIED_ACADEMIC_REPOSITORIES.some(r => hostname === r || hostname.endsWith("." + r));

        if (isOfficialHost) {
          status = "AUTHENTIC_PUBLISHER";
          riskScore = 0;
        } else if (isVerifiedRepo) {
          status = "VERIFIED_REPOSITORY";
          riskScore = 5;
        } else if (hostname) {
          // MISMATCH: Page hosts or claims an official DOI but on an unauthorized domain!
          status = "HIJACKED_JOURNAL_CLONE";
          riskScore = 85;
          threats.push({
            icon: "🚨",
            type: "JOURNAL_HIJACK_CLONE",
            severity: "CRITICAL",
            text: `Hijacked Journal / Thesis Clone: Paper claims official ${expectedPublisher} DOI (${detectedDoi}) but is hosted on unauthorized domain '${hostname}' instead of '${officialDomains.join(" or ")}'.`
          });
          recommendations.push(`Do not pay any article processing fees or submit manuscripts on '${hostname}'.`);
          recommendations.push(`Access the original verified publication directly at https://doi.org/${detectedDoi}`);
        }
      } else {
        // DOI recognized format, but unknown prefix
        if (hostname && !VERIFIED_ACADEMIC_REPOSITORIES.some(r => hostname.endsWith(r))) {
          riskScore += 25;
          threats.push({
            icon: "⚠️",
            type: "UNVERIFIED_DOI_REGISTRY",
            severity: "MEDIUM",
            text: `Paper has DOI (${detectedDoi}) from an unverified or independent publisher registry.`
          });
        }
      }
    }

    // 4. Academic Typosquatting & Predatory Clone Domain Detection
    if (hostname) {
      for (const brand of ACADEMIC_BRAND_TARGETS) {
        const isMatch = hostname === brand.domain || hostname.endsWith("." + brand.domain);
        if (!isMatch) {
          // Check keywords
          for (const kw of brand.keywords) {
            if (hostname.includes(kw)) {
              riskScore += 60;
              threats.push({
                icon: "🎭",
                type: "PREDATORY_ACADEMIC_TYPOSQUATTING",
                severity: "HIGH",
                text: `Predatory Academic Typosquatting: Domain '${hostname}' mimics legitimate academic portal '${brand.name}' (${brand.domain}).`
              });
              recommendations.push(`Beware of cloned paper mills: This domain is not the official ${brand.name}.`);
              break;
            }
          }
        }
      }

      // High-risk TLD used for thesis clone
      const matchedTld = HIGH_RISK_TLDS.find(tld => hostname.endsWith(tld));
      if (matchedTld) {
        riskScore += 30;
        threats.push({
          icon: "🚩",
          type: "SUSPICIOUS_ACADEMIC_TLD",
          severity: "MEDIUM",
          text: `Paper hosted on high-risk TLD '${matchedTld}' commonly utilized by predatory journals and link cloner proxies.`
        });
      }
    }

    // 5. Check In-Page Context (e.g. predatory paper-mill indicators)
    const contextText = (pageContext.text || "").toLowerCase();
    if (contextText.includes("publication fee") || contextText.includes("processing charge") || contextText.includes("fast-track review")) {
      if (status === "HIJACKED_JOURNAL_CLONE" || riskScore >= 50) {
        riskScore += 15;
        threats.push({
          icon: "💸",
          type: "PREDATORY_PUBLICATION_FEE",
          severity: "HIGH",
          text: "Predatory fee solicitation detected on cloned journal page (Paper Mill monetization scheme)."
        });
      }
    }

    riskScore = Math.min(Math.max(riskScore, 0), 100);

    if (riskScore >= 70 && status !== "AUTHENTIC_PUBLISHER") {
      status = "HIJACKED_JOURNAL_CLONE";
    } else if (riskScore >= 30 && status !== "AUTHENTIC_PUBLISHER") {
      status = "SUSPICIOUS_MIRROR";
    } else if (riskScore === 0 && !status.includes("AUTHENTIC") && !status.includes("VERIFIED")) {
      status = "STANDARD_WEB_SOURCE";
    }

    if (recommendations.length === 0) {
      if (status === "AUTHENTIC_PUBLISHER" || status === "VERIFIED_REPOSITORY") {
        recommendations.push("Verified legitimate academic publisher / indexed repository.");
      } else {
        recommendations.push("Verify author affiliations and cross-check paper title on Google Scholar or CrossRef before citing.");
      }
    }

    return {
      riskScore,
      status,
      doi: detectedDoi,
      expectedPublisher,
      officialDomains,
      actualHost: hostname,
      officialUrl: detectedDoi ? `https://doi.org/${detectedDoi}` : null,
      threats,
      recommendations
    };
  }

  /**
   * AI Code & Output Malicious Payload / Hallucination / Poisoning Sentinel
   * Analyzes AI-generated code snippets or prompts for:
   * 1. Dangerous pipe-to-shell pipelines (curl | bash, iwr | iex)
   * 2. Reverse shells & backdoors (/bin/sh -i, netcat, python socket spawn)
   * 3. AI Package Hallucinations / Slopsquatting (e.g. pip installing python standard libraries)
   * 4. Sensitive Credential & Environment Exfiltration
   * 5. Obfuscated dynamic executions (eval(atob()), exec(bytes.fromhex()))
   * 6. Invisible Unicode Prompt Injections & Jailbreak steganography
   */
  function evaluateAICodeIntegrity(codeOrText) {
    if (!codeOrText || typeof codeOrText !== "string") {
      return { safetyScore: 100, riskLevel: "SAFE", threats: [], recommendations: [] };
    }

    const threats = [];
    let risk = 0;
    const lines = codeOrText.split("\n");

    // 1. Remote Execution Pipes
    const remoteExecPatterns = [
      { regex: /curl\s+[^|\n]+?\|\s*(bash|sh|zsh|python|perl|powershell|pwsh)/i, desc: "Remote pipe execution (curl ... | bash): Downloads and executes uninspected shell code." },
      { regex: /wget\s+[^|\n]+?\|\s*(bash|sh|zsh)/i, desc: "Remote pipe execution (wget ... | bash): Unsafe arbitrary script execution." },
      { regex: /(Invoke-WebRequest|iwr|irm)\s+[^|\n]+?\|\s*(iex|Invoke-Expression)/i, desc: "PowerShell remote payload execution (irm ... | iex)." },
      { regex: /powershell\s+.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/i, desc: "Base64 Encoded PowerShell command execution (hidden malicious payload)." }
    ];

    // 2. Reverse Shells & Socket Backdoors
    const reverseShellPatterns = [
      { regex: /bash\s+-i\s+>\&\s*\/dev\/tcp\//i, desc: "Linux TCP Reverse Shell (/dev/tcp/): Provides remote attacker interactive terminal control." },
      { regex: /nc(?:\.traditional)?\s+-[a-zA-Z]*e\s+\/bin\/(?:ba)?sh/i, desc: "Netcat reverse shell backdoor (-e /bin/sh)." },
      { regex: /python(?:\d)?\s+-c\s+["'].*import\s+socket.*subprocess.*pty\.spawn/i, desc: "Python interactive PTY reverse shell backdoor." },
      { regex: /socket\.socket\(socket\.AF_INET,\s*socket\.SOCK_STREAM\).*connect\(/i, desc: "Direct socket network connection to remote IP: Potential reverse backdoor." }
    ];

    // 3. Credential & Environment Exfiltration Webhooks
    const exfilPatterns = [
      { regex: /(process\.env\.[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|AWS)|os\.environ\[["'].*(?:KEY|SECRET|TOKEN|PASSWORD).*["']\]).*?(fetch|axios|requests\.post|http\.client)/is, desc: "Credential Exfiltration: Script accesses secret API/environment keys and sends them to a network endpoint." },
      { regex: /https?:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/i, desc: "Discord Webhook Exfiltration: Attacker channel used to secretly dump stolen data." },
      { regex: /https?:\/\/api\.telegram\.org\/bot[0-9]+:[A-Za-z0-9_-]+\/sendMessage/i, desc: "Telegram Bot Exfiltration: Secret bot channel used to exfiltrate credentials." },
      { regex: /cat\s+(?:\/etc\/passwd|~\/\.ssh\/id_rsa|~\/\.aws\/credentials|\.env)/i, desc: "Sensitive File Access: Script attempts to read system credentials or SSH private keys." }
    ];

    // 4. Obfuscated Dynamic Execution
    const obfuscatedPatterns = [
      { regex: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)\s*\(/i, desc: "Obfuscated Dynamic Execution: eval() with Base64/URI decoded payload." },
      { regex: /exec\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|zlib\.decompress)\s*\(/i, desc: "Python obfuscated exec() payload unpacking byte streams." },
      { regex: /Function\s*\(\s*(?:["'][^"']+["']\s*,\s*)*(?:atob|base64)\(/i, desc: "Dynamic Function constructor unpacking obfuscated payload." }
    ];

    // 5. AI Package Hallucinations / Slopsquatting
    // Attackers register packages matching standard library modules or hallucinated security libraries
    const stdLibSquatting = [
      "sys", "os", "json", "math", "subprocess", "socket", "http",
      "time", "random", "hashlib", "base64", "shutil", "crypto"
    ];
    const knownSquattedPackages = [
      "requsts", "colourama", "pyttsx4", "beautfulsoup", "lodsh", "cross-env-dev",
      "flask-jwt-security", "openai-token-manager", "react-safe-auth"
    ];

    // Scan line by line for precise forensic line numbers
    lines.forEach((line, idx) => {
      const lineNum = idx + 1;

      // Remote Pipes
      for (const p of remoteExecPatterns) {
        if (p.regex.test(line)) {
          risk += 45;
          threats.push({
            icon: "⚡",
            type: "REMOTE_PIPE_EXECUTION",
            severity: "CRITICAL",
            line: lineNum,
            text: `Line ${lineNum}: ${p.desc}`,
            sample: line.trim()
          });
        }
      }

      // Reverse Shells
      for (const p of reverseShellPatterns) {
        if (p.regex.test(line)) {
          risk += 50;
          threats.push({
            icon: "🚪",
            type: "REVERSE_SHELL_BACKDOOR",
            severity: "CRITICAL",
            line: lineNum,
            text: `Line ${lineNum}: ${p.desc}`,
            sample: line.trim()
          });
        }
      }

      // Exfiltration
      for (const p of exfilPatterns) {
        if (p.regex.test(line)) {
          risk += 40;
          threats.push({
            icon: "📤",
            type: "DATA_EXFILTRATION",
            severity: "HIGH",
            line: lineNum,
            text: `Line ${lineNum}: ${p.desc}`,
            sample: line.trim()
          });
        }
      }

      // Obfuscation
      for (const p of obfuscatedPatterns) {
        if (p.regex.test(line)) {
          risk += 35;
          threats.push({
            icon: "🧬",
            type: "OBFUSCATED_PAYLOAD",
            severity: "HIGH",
            line: lineNum,
            text: `Line ${lineNum}: ${p.desc}`,
            sample: line.trim()
          });
        }
      }

      // Package Hallucination in pip/npm
      const pipMatch = line.match(/(?:pip|pip3)\s+install\s+([a-zA-Z0-9_\-–]+)/i);
      if (pipMatch) {
        const pkg = pipMatch[1].toLowerCase();
        if (stdLibSquatting.includes(pkg)) {
          risk += 40;
          threats.push({
            icon: "📦",
            type: "AI_PACKAGE_HALLUCINATION",
            severity: "CRITICAL",
            line: lineNum,
            text: `Line ${lineNum}: AI Hallucinated Package 'pip install ${pkg}'. In Python, '${pkg}' is a built-in standard library! Installing an external package named '${pkg}' will download malicious supply-chain malware.`,
            sample: line.trim()
          });
        } else if (knownSquattedPackages.includes(pkg)) {
          risk += 45;
          threats.push({
            icon: "📦",
            type: "TYPOSQUATTED_PACKAGE",
            severity: "CRITICAL",
            line: lineNum,
            text: `Line ${lineNum}: Malicious Typosquatted Package detected: '${pkg}'.`,
            sample: line.trim()
          });
        }
      }

      const npmMatch = line.match(/(?:npm|yarn|pnpm)\s+(?:install|add|i)\s+([a-zA-Z0-9_\-–@/]+)/i);
      if (npmMatch) {
        const pkg = npmMatch[1].toLowerCase();
        if (knownSquattedPackages.includes(pkg)) {
          risk += 45;
          threats.push({
            icon: "📦",
            type: "TYPOSQUATTED_PACKAGE",
            severity: "CRITICAL",
            line: lineNum,
            text: `Line ${lineNum}: Malicious npm dependency detected: '${pkg}'.`,
            sample: line.trim()
          });
        }
      }
    });

    // 6. Invisible Unicode Prompt Injection Steganography
    const zeroWidthRegex = /[\u200B\u200C\u200D\uFEFF\u2060]/g;
    const zeroWidthMatches = codeOrText.match(zeroWidthRegex);
    if (zeroWidthMatches && zeroWidthMatches.length >= 3) {
      risk += 40;
      threats.push({
        icon: "🕵️",
        type: "INVISIBLE_PROMPT_INJECTION",
        severity: "HIGH",
        text: `Detected ${zeroWidthMatches.length} hidden zero-width unicode characters (\u200B/\u200C/\uFEFF). Attackers use invisible characters to hide malicious instructions from human code reviewers while influencing AI models.`
      });
    }

    // 7. System Prompt Override / Jailbreak
    const jailbreakKeywords = [
      "ignore all previous instructions",
      "system prompt override",
      "you are now dan",
      "disregard safety guidelines",
      "jailbreak mode enabled"
    ];
    const textLower = codeOrText.toLowerCase();
    for (const jw of jailbreakKeywords) {
      if (textLower.includes(jw)) {
        risk += 35;
        threats.push({
          icon: "🧠",
          type: "PROMPT_INJECTION_OVERRIDE",
          severity: "HIGH",
          text: `Prompt Injection signature detected: '${jw}'. Attempting to override AI system safety instructions.`
        });
        break;
      }
    }

    risk = Math.min(Math.max(risk, 0), 100);
    const safetyScore = 100 - risk;

    let riskLevel = "SAFE";
    if (risk >= 60) riskLevel = "MALICIOUS";
    else if (risk >= 25) riskLevel = "SUSPICIOUS";

    const recommendations = [];
    if (riskLevel === "MALICIOUS") {
      recommendations.push("DO NOT run this code in your terminal, bash, or production environment.");
      recommendations.push("Inspect third-party package dependencies manually on pypi.org or npmjs.com.");
      recommendations.push("Check for hidden webhooks or reverse shell connections before executing.");
    } else if (riskLevel === "SUSPICIOUS") {
      recommendations.push("Review flagged lines carefully before copying or running.");
      recommendations.push("Verify that requested libraries are legitimate and required.");
    } else {
      recommendations.push("Code passed AI security heuristics check. No known supply-chain or execution exploits detected.");
    }

    return {
      riskScore: risk,
      safetyScore,
      riskLevel,
      threats,
      recommendations,
      linesScanned: lines.length
    };
  }

  return {
    PROTECTED_BRANDS,
    CANONICAL_DOMAINS,
    HIGH_RISK_TLDS,
    ACADEMIC_PUBLISHER_REGISTRY,
    VERIFIED_ACADEMIC_REPOSITORIES,
    customBrands,
    registerCustomBrand,
    levenshteinDistance,
    calculateShannonEntropy,
    normalizeHomoglyphs,
    getBaseDomain,
    evaluateUrlThreat,
    evaluateTextThreat,
    evaluateAcademicPaperIntegrity,
    evaluateAICodeIntegrity,
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

