"use strict";

// =============================================================================
//  Content script — roda em todos os frames, em todas as páginas.
//  Responsabilidades:
//    1) Injeta `inject.js` no contexto da página (page world) para hookar APIs
//       de fingerprinting (Canvas/WebGL/AudioContext) e detectar tentativas de
//       hijacking (overrides de window.location/open, etc.).
//    2) Coleta o estado de localStorage / sessionStorage / IndexedDB e envia
//       para o background.
//    3) Encaminha mensagens postMessage do inject.js para o background via
//       runtime.sendMessage.
// =============================================================================

const ORIGIN = location.origin;

// -----------------------------------------------------------------------------
// 1) Injetar inject.js no page world.
// Necessário porque content scripts vivem em um mundo isolado e não conseguem
// hookar prototypes vistos pelo JS da própria página.
// -----------------------------------------------------------------------------
function injectPageWorldScript() {
  try {
    const s = document.createElement("script");
    s.src = browser.runtime.getURL("content/inject.js");
    s.async = false;
    s.onload = () => s.remove();
    (document.head || document.documentElement || document).appendChild(s);
  } catch (e) {
    // Algumas páginas com CSP estrita podem bloquear — degradamos para
    // detecção limitada e seguimos.
    console.warn("[PrivacyGuardian] Falha ao injetar inject.js:", e);
  }
}

injectPageWorldScript();

// -----------------------------------------------------------------------------
// 2) Bridge de mensagens: inject.js → content → background.
// -----------------------------------------------------------------------------
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.__pg !== true) return;

  if (data.type === "pg-fingerprint") {
    browser.runtime.sendMessage({
      type: "pg-fingerprint",
      api: data.api,
      stack: data.stack
    }).catch(() => {});
  } else if (data.type === "pg-hijacking-signal") {
    browser.runtime.sendMessage({
      type: "pg-hijacking-signal",
      signal: data.signal,
      detail: data.detail
    }).catch(() => {});
  }
});

// -----------------------------------------------------------------------------
// 3) Coleta de Web Storage e IndexedDB.
// -----------------------------------------------------------------------------
function snapshotStorage(storage) {
  const keys = [];
  let totalBytes = 0;
  try {
    for (let i = 0; i < storage.length; i++) {
      const k = storage.key(i);
      const v = storage.getItem(k) || "";
      const size = (k.length + v.length) * 2; // UTF-16 aproximado
      totalBytes += size;
      keys.push({
        key: k,
        size,
        valuePreview: v.length > 60 ? v.slice(0, 60) + "…" : v
      });
    }
  } catch (e) {
    // SecurityError em iframes cross-origin, etc.
  }
  return { keys, totalBytes };
}

async function snapshotIndexedDB() {
  const out = [];
  if (!("indexedDB" in window)) return out;
  let dbs = [];
  try {
    if (typeof indexedDB.databases === "function") {
      dbs = await indexedDB.databases();
    }
  } catch (e) {
    return out;
  }
  for (const info of dbs) {
    if (!info || !info.name) continue;
    const dbInfo = { name: info.name, version: info.version, stores: [] };
    try {
      const req = indexedDB.open(info.name);
      const db = await new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        req.onblocked = () => reject(new Error("blocked"));
      });
      for (const storeName of db.objectStoreNames) {
        const tx = db.transaction(storeName, "readonly");
        const store = tx.objectStore(storeName);
        const countReq = store.count();
        const count = await new Promise((resolve) => {
          countReq.onsuccess = () => resolve(countReq.result);
          countReq.onerror = () => resolve(-1);
        });
        dbInfo.stores.push({ name: storeName, count });
      }
      db.close();
    } catch (e) {
      // ignora bancos protegidos / bloqueados
    }
    out.push(dbInfo);
  }
  return out;
}

async function reportStorage() {
  try {
    const payload = {
      localStorage: snapshotStorage(window.localStorage),
      sessionStorage: snapshotStorage(window.sessionStorage),
      indexedDB: await snapshotIndexedDB()
    };
    await browser.runtime.sendMessage({
      type: "pg-storage-report",
      origin: ORIGIN,
      payload
    });
  } catch (e) {
    // Aba sem background pronto, etc.
  }
}

// Envia uma primeira amostra assim que o DOM ficar pronto, depois a cada 5s
// (para capturar dados gravados após interação do usuário) e em visibilitychange.
function scheduleReports() {
  reportStorage();
  setInterval(reportStorage, 5000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) reportStorage();
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", scheduleReports, { once: true });
} else {
  scheduleReports();
}

// Hook adicional do content world: monitora inserção de <script> com src
// vindos de domínios suspeitos (sinal de hijacking via DOM).
const SUSPICIOUS_PATTERNS = [
  /coin-?hive/i, /cryptoloot/i, /minero\./i,
  /\.tk\//i, /\.gq\//i, /\.ml\//i,
  /pushcrew/i, /pushpushgo/i
];

const mo = new MutationObserver((mutations) => {
  for (const m of mutations) {
    for (const n of m.addedNodes) {
      if (n.nodeType !== 1) continue;
      if (n.tagName === "SCRIPT" && n.src) {
        for (const p of SUSPICIOUS_PATTERNS) {
          if (p.test(n.src)) {
            browser.runtime.sendMessage({
              type: "pg-hijacking-signal",
              signal: "dom_injected_suspicious_script",
              detail: `Script suspeito inserido via DOM: ${n.src}`
            }).catch(() => {});
            break;
          }
        }
      }
      if (n.tagName === "IFRAME" && n.src) {
        // iframes invisíveis em 1x1 podem indicar tracking / clickjacking
        const w = parseInt(n.getAttribute("width") || "0", 10);
        const h = parseInt(n.getAttribute("height") || "0", 10);
        const style = (n.getAttribute("style") || "").toLowerCase();
        const hidden = (w > 0 && w <= 2) || (h > 0 && h <= 2)
                    || style.includes("display:none")
                    || style.includes("visibility:hidden")
                    || style.includes("opacity:0");
        if (hidden) {
          browser.runtime.sendMessage({
            type: "pg-hijacking-signal",
            signal: "invisible_iframe",
            detail: `IFrame invisível detectado: ${n.src}`
          }).catch(() => {});
        }
      }
    }
  }
});
try {
  mo.observe(document.documentElement, { childList: true, subtree: true });
} catch (_) { /* documento sem documentElement (raro) */ }
