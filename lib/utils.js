// Utilitários compartilhados entre background, content e popup.
// Como o manifest carrega este arquivo no escopo do background e do content,
// expomos as funções em `self` (que é `window` em content e `globalThis` em background).

(function (scope) {
  "use strict";

  // Lista simplificada de TLDs de duas partes para extrair o eTLD+1.
  // Cobre os casos mais comuns sem precisar embutir a Public Suffix List completa.
  const MULTI_PART_TLDS = new Set([
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz", "co.il", "co.th",
    "com.br", "com.au", "com.mx", "com.ar", "com.tr", "com.cn", "com.tw",
    "com.hk", "com.sg", "com.my", "com.ph", "com.co", "com.pe", "com.ve",
    "net.br", "net.au", "org.br", "org.uk", "gov.br", "gov.uk", "gov.au",
    "ne.jp", "or.jp", "ac.jp", "ac.uk", "ac.in", "edu.br", "edu.au", "edu.cn"
  ]);

  function getHostname(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (e) {
      return "";
    }
  }

  // Retorna o "registered domain" (eTLD+1). Para IPs e hosts curtos, devolve o próprio host.
  function getETLD1(hostname) {
    if (!hostname) return "";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname;
    if (/^\[?[0-9a-fA-F:]+\]?$/.test(hostname) && hostname.includes(":")) return hostname;
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    const lastTwo = parts.slice(-2).join(".");
    if (MULTI_PART_TLDS.has(lastTwo)) {
      return parts.slice(-3).join(".");
    }
    return lastTwo;
  }

  function isThirdParty(requestUrl, pageUrl) {
    const a = getETLD1(getHostname(requestUrl));
    const b = getETLD1(getHostname(pageUrl));
    if (!a || !b) return false;
    return a !== b;
  }

  // Padrões heurísticos de domínios "suspeitos" comuns em scripts agressivos / hijacking.
  // Não é uma lista exaustiva; serve como sinal adicional, não como verdade absoluta.
  const SUSPICIOUS_DOMAIN_PATTERNS = [
    /coin-?hive/i, /cryptoloot/i, /webminepool/i, /crypto-loot/i, /minero\./i,
    /malvertising/i, /clickjack/i, /\.tk$/i, /\.gq$/i, /\.ml$/i,
    /pop(ads|cash|under)/i, /adfly/i, /linkbucks/i,
    /pushnotify/i, /pushcrew/i, /pushpushgo/i
  ];

  function isSuspiciousDomain(hostname) {
    return SUSPICIOUS_DOMAIN_PATTERNS.some(p => p.test(hostname));
  }

  // Trackers/analytics conhecidos — usados para penalizar e detectar cookie syncing.
  const KNOWN_TRACKERS = [
    "doubleclick.net", "googlesyndication.com", "google-analytics.com",
    "googletagmanager.com", "googletagservices.com", "googleadservices.com",
    "facebook.net", "facebook.com", "fbcdn.net", "connect.facebook.net",
    "scorecardresearch.com", "quantserve.com", "adnxs.com", "rubiconproject.com",
    "pubmatic.com", "openx.net", "criteo.com", "criteo.net", "taboola.com",
    "outbrain.com", "amazon-adsystem.com", "adsrvr.org", "mathtag.com",
    "bluekai.com", "krxd.net", "rlcdn.com", "demdex.net", "everesttech.net",
    "yieldmo.com", "yieldlab.net", "casalemedia.com", "smartadserver.com",
    "moatads.com", "adsystem.com", "indexww.com", "tpc.googlesyndication.com",
    "hotjar.com", "mouseflow.com", "fullstory.com", "mixpanel.com", "segment.io",
    "segment.com", "amplitude.com", "branch.io", "appsflyer.com", "adjust.com",
    "yandex.ru", "mc.yandex.ru", "ya.ru", "vk.com",
    "linkedin.com", "licdn.com", "twitter.com", "ads-twitter.com", "t.co",
    "tiktok.com", "tiktokcdn.com", "bytedance.com", "pinterest.com"
  ];

  function isKnownTracker(hostname) {
    if (!hostname) return false;
    const etld1 = getETLD1(hostname);
    return KNOWN_TRACKERS.some(t => etld1 === t || hostname.endsWith("." + t));
  }

  // Heurística para identificar valores que parecem identificadores de tracking
  // (UUIDs, hashes hex, base64 longos). Usado na detecção de cookie syncing.
  function looksLikeTrackingId(value) {
    if (typeof value !== "string") return false;
    if (value.length < 12 || value.length > 256) return false;
    // UUID
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return true;
    // Hex puro >= 16 chars
    if (/^[0-9a-f]{16,}$/i.test(value)) return true;
    // Base64-ish (>= 16 chars, sem espaços, alta entropia)
    if (/^[A-Za-z0-9+/=_-]{16,}$/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value)) return true;
    return false;
  }

  function formatBytes(bytes) {
    if (!bytes || bytes < 1024) return (bytes || 0) + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  }

  scope.PGUtils = {
    getHostname,
    getETLD1,
    isThirdParty,
    isSuspiciousDomain,
    isKnownTracker,
    looksLikeTrackingId,
    formatBytes,
    KNOWN_TRACKERS
  };
})(typeof self !== "undefined" ? self : this);
