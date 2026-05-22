"use strict";

// =============================================================================
//  Privacy Guardian — Background Script
// -----------------------------------------------------------------------------
//  Coordena a coleta de sinais por aba:
//    - Conexões a terceiros (webRequest)
//    - Cookies (cookies API + Set-Cookie headers)
//    - Supercookies (ETag, HSTS)
//    - Redirects e scripts suspeitos (hijacking)
//    - Cookie syncing (cross-domain ID propagation)
//    - Fingerprinting / Web Storage / IndexedDB (recebidos via mensagens)
//  Expõe a função getReport(tabId) usada pelo popup.
// =============================================================================

const { getHostname, getETLD1, isThirdParty, isSuspiciousDomain,
        isKnownTracker, looksLikeTrackingId } = self.PGUtils;

const tabState = new Map();

function freshState(url) {
  return {
    url: url || "",
    hostname: getHostname(url || ""),
    etld1: getETLD1(getHostname(url || "")),
    startedAt: Date.now(),

    // Domínios de terceira parte: Map<etld1, {hostnames:Set, types:Map<type,count>, requests:number, isTracker:boolean, isSuspicious:boolean}>
    thirdParties: new Map(),
    totalRequests: 0,
    thirdPartyRequests: 0,

    // Cookies (preenchido sob demanda no getReport, mas também via Set-Cookie)
    cookiesSeen: new Map(), // name|domain -> {name, domain, value, session, persistent, thirdParty, source}

    // Supercookies detectados
    supercookies: {
      etag: [],   // [{url, etag, thirdParty}]
      hsts: []    // [{url, maxAge, thirdParty}]
    },

    // Sinais de hijacking / hooking
    hijacking: [], // [{type, detail, url}]

    // Cookie syncing detectado
    cookieSyncing: [], // [{id, fromDomain, toDomain, url}]

    // Tabela de IDs vistos em cookies/URLs/headers — para detectar reuso cross-domain
    seenIds: new Map(), // id -> Set<domain>

    // Web Storage e IndexedDB reportados pelos content scripts
    // Map<origin, {localStorage: {keys:[], totalBytes}, sessionStorage: {...}, indexedDB: [...]}>
    storageByOrigin: new Map(),

    // Fingerprinting reportado pelo content/inject
    fingerprinting: [], // [{api, frame, origin, stack, ts}]
    fingerprintingByApi: new Map(),

    // Redirects
    redirects: [] // [{from, to, statusCode}]
  };
}

function getState(tabId, url) {
  let s = tabState.get(tabId);
  if (!s) {
    s = freshState(url);
    tabState.set(tabId, s);
  }
  return s;
}

// ---------------- webRequest: contagem de domínios e tipos ------------------

const REQUEST_TYPES_OF_INTEREST = new Set([
  "main_frame", "sub_frame", "stylesheet", "script", "image",
  "font", "object", "xmlhttprequest", "ping", "media",
  "websocket", "csp_report", "imageset", "other"
]);

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;

    // Em navegação principal (main_frame), reinicializamos o estado da aba.
    if (details.type === "main_frame") {
      tabState.set(details.tabId, freshState(details.url));
      return;
    }

    const state = tabState.get(details.tabId);
    if (!state) return;

    state.totalRequests++;
    const reqHost = getHostname(details.url);
    if (!reqHost) return;

    if (isThirdParty(details.url, state.url)) {
      state.thirdPartyRequests++;
      const etld1 = getETLD1(reqHost);
      let entry = state.thirdParties.get(etld1);
      if (!entry) {
        entry = {
          etld1,
          hostnames: new Set(),
          types: new Map(),
          requests: 0,
          isTracker: isKnownTracker(reqHost),
          isSuspicious: isSuspiciousDomain(reqHost)
        };
        state.thirdParties.set(etld1, entry);
      }
      entry.hostnames.add(reqHost);
      entry.requests++;
      const t = REQUEST_TYPES_OF_INTEREST.has(details.type) ? details.type : "other";
      entry.types.set(t, (entry.types.get(t) || 0) + 1);

      // Hijacking: script externo carregado de domínio suspeito.
      if ((details.type === "script" || details.type === "sub_frame") && entry.isSuspicious) {
        state.hijacking.push({
          type: "suspicious_script",
          detail: `Recurso ${details.type} de domínio suspeito: ${reqHost}`,
          url: details.url
        });
      }

      // Cookie syncing: parâmetros de URL com aparência de tracking ID que
      // já foram vistos em outro domínio.
      try {
        const u = new URL(details.url);
        for (const [, v] of u.searchParams.entries()) {
          if (looksLikeTrackingId(v)) {
            let domains = state.seenIds.get(v);
            if (!domains) {
              domains = new Set();
              state.seenIds.set(v, domains);
            }
            const prev = [...domains];
            domains.add(etld1);
            for (const other of prev) {
              if (other !== etld1) {
                state.cookieSyncing.push({
                  id: v.length > 32 ? v.slice(0, 32) + "…" : v,
                  fromDomain: other,
                  toDomain: etld1,
                  url: details.url
                });
              }
            }
          }
        }
      } catch (_) { /* URL inválida — ignorar */ }
    }
  },
  { urls: ["<all_urls>"] }
);

// ---------------- webRequest: cabeçalhos (ETag, HSTS, Set-Cookie) -----------

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const state = tabState.get(details.tabId);
    if (!state) return;

    const headers = details.responseHeaders || [];
    const reqHost = getHostname(details.url);
    const thirdParty = isThirdParty(details.url, state.url);

    for (const h of headers) {
      const name = (h.name || "").toLowerCase();
      const value = h.value || "";

      if (name === "etag" && value.length >= 8) {
        state.supercookies.etag.push({
          url: details.url,
          host: reqHost,
          etag: value.length > 64 ? value.slice(0, 64) + "…" : value,
          thirdParty
        });
        // Um ETag em si não é cookie — mas é frequentemente usado como
        // identificador persistente para tracking. Marcamos quando é 3P.
      }

      if (name === "strict-transport-security") {
        const m = /max-age\s*=\s*(\d+)/i.exec(value);
        const maxAge = m ? parseInt(m[1], 10) : 0;
        // max-age muito longo + terceiro = sinal clássico de "HSTS supercookie".
        if (maxAge >= 60 * 60 * 24 * 30) {
          state.supercookies.hsts.push({
            url: details.url,
            host: reqHost,
            maxAge,
            thirdParty
          });
        }
      }

      if (name === "set-cookie") {
        // O Set-Cookie pode ser multi-valor; navegadores entregam separado por '\n'.
        const cookieLines = value.split(/\n/);
        for (const line of cookieLines) {
          parseSetCookie(line, reqHost, thirdParty, state);
        }
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

function parseSetCookie(line, host, thirdParty, state) {
  if (!line) return;
  const parts = line.split(";").map(p => p.trim());
  const [nameVal, ...attrs] = parts;
  const eq = nameVal.indexOf("=");
  if (eq < 0) return;
  const cname = nameVal.slice(0, eq).trim();
  const cval = nameVal.slice(eq + 1).trim();
  let domain = host;
  let persistent = false;
  for (const a of attrs) {
    const [k, v] = a.split("=").map(s => (s || "").trim());
    const kl = k.toLowerCase();
    if (kl === "domain" && v) domain = v.replace(/^\./, "").toLowerCase();
    if (kl === "expires" || kl === "max-age") persistent = true;
  }
  const key = `${cname}|${domain}`;
  state.cookiesSeen.set(key, {
    name: cname,
    domain,
    value: cval.length > 80 ? cval.slice(0, 80) + "…" : cval,
    session: !persistent,
    persistent,
    thirdParty,
    source: "set-cookie"
  });

  if (looksLikeTrackingId(cval)) {
    let domains = state.seenIds.get(cval);
    if (!domains) {
      domains = new Set();
      state.seenIds.set(cval, domains);
    }
    domains.add(getETLD1(domain));
  }
}

// ---------------- Redirects (hijacking) ------------------------------------

browser.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const state = tabState.get(details.tabId);
    if (!state) return;

    state.redirects.push({
      from: details.url,
      to: details.redirectUrl,
      statusCode: details.statusCode,
      type: details.type
    });

    // Heurística: redirect de main_frame para domínio diferente do solicitado
    // pelo usuário pode indicar sequestro/typosquatting.
    if (details.type === "main_frame") {
      const fromDomain = getETLD1(getHostname(details.url));
      const toDomain = getETLD1(getHostname(details.redirectUrl));
      if (fromDomain && toDomain && fromDomain !== toDomain) {
        state.hijacking.push({
          type: "cross_domain_redirect",
          detail: `Redirecionamento de ${fromDomain} para ${toDomain}`,
          url: details.redirectUrl
        });
      }
    }

    // Cadeia de redirects muito longa também é sinal de cloaking.
    if (state.redirects.length > 5) {
      state.hijacking.push({
        type: "redirect_chain",
        detail: `Cadeia longa de redirects detectada (${state.redirects.length})`,
        url: details.redirectUrl
      });
    }
  },
  { urls: ["<all_urls>"] }
);

// ---------------- tabs lifecycle -------------------------------------------

browser.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

browser.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading" && info.url) {
    // Reseta no início de uma navegação top-level (caso main_frame não dispare antes).
    const existing = tabState.get(tabId);
    if (!existing || existing.url !== info.url) {
      tabState.set(tabId, freshState(info.url));
    }
  }
});

// ---------------- Mensagens do content script ------------------------------

browser.runtime.onMessage.addListener((msg, sender) => {
  // Mensagens vindas do popup (sem sender.tab) usam tabId explícito.
  if (msg && msg.type === "pg-get-report-by-tab") {
    return Promise.resolve(buildReport(msg.tabId));
  }
  if (msg && msg.type === "pg-rescan-by-tab") {
    const s = tabState.get(msg.tabId);
    if (s) {
      s.storageByOrigin.clear();
      s.fingerprinting.length = 0;
      s.fingerprintingByApi.clear();
    }
    return Promise.resolve({ ok: true });
  }

  if (!sender.tab) return;
  const tabId = sender.tab.id;
  const state = getState(tabId, sender.tab.url);

  switch (msg.type) {
    case "pg-fingerprint": {
      const entry = {
        api: msg.api,
        origin: sender.url || sender.tab.url,
        frame: sender.frameId,
        ts: Date.now()
      };
      state.fingerprinting.push(entry);
      state.fingerprintingByApi.set(msg.api, (state.fingerprintingByApi.get(msg.api) || 0) + 1);
      break;
    }
    case "pg-storage-report": {
      // msg.payload = { localStorage:{keys, totalBytes}, sessionStorage:{...}, indexedDB:[{name, version, stores}] }
      state.storageByOrigin.set(msg.origin, msg.payload);
      break;
    }
    case "pg-hijacking-signal": {
      state.hijacking.push({
        type: msg.signal,
        detail: msg.detail,
        url: sender.url || sender.tab.url
      });
      break;
    }
    case "pg-get-report": {
      return Promise.resolve(buildReport(tabId));
    }
    case "pg-rescan": {
      // Limpa storage e fingerprinting reportados; o content script reenviará.
      state.storageByOrigin.clear();
      state.fingerprinting.length = 0;
      state.fingerprintingByApi.clear();
      return Promise.resolve({ ok: true });
    }
  }
});

// ---------------- Cookies via API ------------------------------------------

async function collectCookies(state) {
  if (!state.url) return [];
  let cookies = [];
  try {
    cookies = await browser.cookies.getAll({ url: state.url });
  } catch (e) {
    return [];
  }
  const out = cookies.map(c => ({
    name: c.name,
    domain: c.domain.replace(/^\./, ""),
    value: (c.value || "").length > 80 ? c.value.slice(0, 80) + "…" : c.value,
    session: c.session,
    persistent: !c.session,
    expirationDate: c.expirationDate || null,
    httpOnly: c.httpOnly,
    secure: c.secure,
    sameSite: c.sameSite,
    thirdParty: getETLD1(c.domain.replace(/^\./, "")) !== state.etld1
  }));

  // Sincroniza valores potencialmente "supercookie-like" no mapa de IDs vistos.
  for (const c of out) {
    if (looksLikeTrackingId(c.value)) {
      let domains = state.seenIds.get(c.value);
      if (!domains) {
        domains = new Set();
        state.seenIds.set(c.value, domains);
      }
      domains.add(getETLD1(c.domain));
    }
  }
  return out;
}

// ---------------- Privacy Score --------------------------------------------
//
//  Metodologia: começamos em 100 pontos e subtraímos com base em sinais
//  ponderados por severidade. Cada categoria tem um teto de penalidade para
//  evitar que um único sinal "estoure" o score (ex.: 200 imagens de terceiros).
//
//    -2  por domínio de terceiro (cap -20)
//    -3  por tracker conhecido (cap -25)
//    -8  por domínio suspeito (cap -16)
//    -3  por cookie de terceiro (cap -20)
//    -1  por cookie persistente de primeira parte (cap -5)
//    -3  por supercookie (ETag/HSTS) em terceiro (cap -15)
//    -5  por API de fingerprinting acessada (cap -20)
//    -8  por evento de hijacking (cap -20)
//    -6  por par de cookie syncing detectado (cap -18)
//    -1  a cada 5 chaves de Web Storage de terceiro (cap -8)
//
//  Score final = max(0, 100 - somatório).
//  Classificações:
//    >=85 Excelente | 70..84 Bom | 50..69 Razoável | 30..49 Ruim | <30 Crítico
// ---------------------------------------------------------------------------

function computeScore(report) {
  const penalties = [];
  let total = 0;
  const add = (label, value, cap) => {
    const v = Math.min(value, cap);
    if (v > 0) {
      penalties.push({ label, value: v, cap });
      total += v;
    }
  };

  add("Domínios de terceira parte",
      report.thirdParties.length * 2, 20);
  add("Trackers conhecidos",
      report.thirdParties.filter(t => t.isTracker).length * 3, 25);
  add("Domínios suspeitos",
      report.thirdParties.filter(t => t.isSuspicious).length * 8, 16);

  const tpCookies = report.cookies.filter(c => c.thirdParty).length;
  const persistent1p = report.cookies.filter(c => !c.thirdParty && c.persistent).length;
  add("Cookies de terceira parte", tpCookies * 3, 20);
  add("Cookies persistentes de 1ª parte", persistent1p * 1, 5);

  const tpSuper = report.supercookies.etag.filter(e => e.thirdParty).length
                + report.supercookies.hsts.filter(h => h.thirdParty).length;
  add("Supercookies (ETag/HSTS) de 3P", tpSuper * 3, 15);

  add("APIs de fingerprinting", report.fingerprinting.byApi.length * 5, 20);
  add("Eventos de hijacking", report.hijacking.length * 8, 20);
  add("Cookie syncing", report.cookieSyncing.length * 6, 18);

  const tpStorageKeys = report.storage
    .filter(s => s.thirdParty)
    .reduce((acc, s) => acc + s.localStorage.keys.length + s.sessionStorage.keys.length, 0);
  add("Web Storage em terceiros", Math.floor(tpStorageKeys / 5) * 1, 8);

  const score = Math.max(0, 100 - total);
  let rating, color;
  if (score >= 85) { rating = "Excelente"; color = "#1a7f37"; }
  else if (score >= 70) { rating = "Bom"; color = "#2da44e"; }
  else if (score >= 50) { rating = "Razoável"; color = "#bf8700"; }
  else if (score >= 30) { rating = "Ruim"; color = "#bc4c00"; }
  else { rating = "Crítico"; color = "#cf222e"; }

  return { score, rating, color, penalties, totalPenalty: total };
}

// ---------------- Construção do relatório ----------------------------------

async function buildReport(tabId) {
  const state = tabState.get(tabId);
  if (!state) return null;

  const cookies = await collectCookies(state);
  // Inclui cookies vistos via Set-Cookie que talvez ainda não estejam no jar.
  const seenKeys = new Set(cookies.map(c => `${c.name}|${c.domain}`));
  for (const [k, v] of state.cookiesSeen.entries()) {
    if (!seenKeys.has(k)) cookies.push(v);
  }

  const thirdParties = [...state.thirdParties.values()].map(e => ({
    etld1: e.etld1,
    hostnames: [...e.hostnames],
    types: Object.fromEntries(e.types.entries()),
    requests: e.requests,
    isTracker: e.isTracker,
    isSuspicious: e.isSuspicious
  })).sort((a, b) => b.requests - a.requests);

  const storage = [...state.storageByOrigin.entries()].map(([origin, payload]) => ({
    origin,
    thirdParty: getETLD1(getHostname(origin)) !== state.etld1,
    ...payload
  }));

  const fingerprinting = {
    total: state.fingerprinting.length,
    byApi: [...state.fingerprintingByApi.entries()].map(([api, count]) => ({ api, count })),
    events: state.fingerprinting.slice(-50)
  };

  const cookieClassification = {
    total: cookies.length,
    firstParty: cookies.filter(c => !c.thirdParty).length,
    thirdParty: cookies.filter(c => c.thirdParty).length,
    session: cookies.filter(c => c.session).length,
    persistent: cookies.filter(c => c.persistent).length
  };

  const report = {
    tabId,
    url: state.url,
    hostname: state.hostname,
    etld1: state.etld1,
    startedAt: state.startedAt,
    totalRequests: state.totalRequests,
    thirdPartyRequests: state.thirdPartyRequests,
    thirdParties,
    cookies,
    cookieClassification,
    supercookies: state.supercookies,
    fingerprinting,
    storage,
    hijacking: state.hijacking,
    cookieSyncing: state.cookieSyncing,
    redirects: state.redirects
  };

  report.privacyScore = computeScore(report);
  return report;
}

// Atualiza o badge do navegador com a quantidade de terceiros — feedback rápido.
async function refreshBadge(tabId) {
  const state = tabState.get(tabId);
  if (!state) return;
  const count = state.thirdParties.size;
  try {
    await browser.browserAction.setBadgeText({
      tabId,
      text: count > 0 ? String(count) : ""
    });
    await browser.browserAction.setBadgeBackgroundColor({
      tabId,
      color: count > 20 ? "#cf222e" : count > 10 ? "#bf8700" : "#1a7f37"
    });
  } catch (_) { /* aba pode ter fechado */ }
}

setInterval(() => {
  for (const tabId of tabState.keys()) refreshBadge(tabId);
}, 2000);
