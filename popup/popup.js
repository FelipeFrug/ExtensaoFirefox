"use strict";

// Popup do Privacy Guardian: solicita o relatório da aba ativa e renderiza.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function escapeHTML(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function formatBytes(bytes) {
  if (!bytes || bytes < 1024) return (bytes || 0) + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

async function getActiveTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// O background expõe `pg-get-report-by-tab` (popup não tem sender.tab).
async function getReportByTab(tabId) {
  return browser.runtime.sendMessage({ type: "pg-get-report-by-tab", tabId });
}

// -----------------------------------------------------------------------------
// Renderização
// -----------------------------------------------------------------------------
function renderScore(report) {
  const s = report.privacyScore;
  $("#score-num").textContent = s.score;
  $("#score-rating").textContent = s.rating;
  const arc = $("#score-arc");
  const C = 2 * Math.PI * 44; // 276.46
  arc.setAttribute("stroke-dasharray", C.toFixed(2));
  arc.setAttribute("stroke-dashoffset", (C * (1 - s.score / 100)).toFixed(2));
  arc.setAttribute("stroke", s.color);

  const list = $("#penalty-list");
  list.innerHTML = "";
  if (!s.penalties.length) {
    list.innerHTML = '<li class="ok">Nenhuma penalidade aplicada ✓</li>';
    return;
  }
  for (const p of s.penalties) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${escapeHTML(p.label)}</span><strong>−${p.value}</strong>`;
    list.appendChild(li);
  }
}

function renderThirdParty(report) {
  $("#tp-count").textContent = report.thirdParties.length;
  $("#tp-requests").textContent = report.thirdPartyRequests;
  $("#tp-trackers").textContent = report.thirdParties.filter(t => t.isTracker).length;

  const list = $("#thirdparty-list");
  list.innerHTML = "";
  if (!report.thirdParties.length) {
    list.innerHTML = '<p class="empty">Nenhuma conexão de terceira parte registrada.</p>';
    return;
  }
  for (const tp of report.thirdParties) {
    const types = Object.entries(tp.types)
      .map(([t, c]) => `<span>${escapeHTML(t)} · ${c}</span>`).join("");
    const badges = [
      tp.isTracker ? '<span class="badge tracker">Tracker</span>' : "",
      tp.isSuspicious ? '<span class="badge suspicious">Suspeito</span>' : "",
      `<span class="badge req">${tp.requests} req</span>`
    ].join("");
    const div = document.createElement("div");
    div.className = "tp-item";
    div.innerHTML = `
      <div class="row1">
        <span class="domain">${escapeHTML(tp.etld1)}</span>
        <span>${badges}</span>
      </div>
      <div class="types">${types}</div>
    `;
    list.appendChild(div);
  }
}

function renderCookies(report) {
  const cc = report.cookieClassification;
  $("#ck-total").textContent = cc.total;
  $("#ck-third").textContent = cc.thirdParty;
  $("#ck-persistent").textContent = cc.persistent;
  $("#ck-session").textContent = cc.session;

  const superList = $("#supercookies-list");
  const etag = report.supercookies.etag;
  const hsts = report.supercookies.hsts;
  if (etag.length === 0 && hsts.length === 0) {
    superList.innerHTML = '<p class="empty">Nenhum sinal de supercookie.</p>';
  } else {
    superList.innerHTML = "";
    for (const e of etag.slice(0, 20)) {
      const row = document.createElement("div");
      row.className = "super-row";
      row.innerHTML = `
        <div>
          <strong>ETag</strong> ${e.thirdParty ? '<span class="flag-3p">3P</span>' : '<span class="flag-1p">1P</span>'}
          <div class="meta">${escapeHTML(e.host)}</div>
        </div>
        <code>${escapeHTML(e.etag)}</code>`;
      superList.appendChild(row);
    }
    for (const h of hsts.slice(0, 20)) {
      const days = Math.round(h.maxAge / 86400);
      const row = document.createElement("div");
      row.className = "super-row";
      row.innerHTML = `
        <div>
          <strong>HSTS</strong> ${h.thirdParty ? '<span class="flag-3p">3P</span>' : '<span class="flag-1p">1P</span>'}
          <div class="meta">${escapeHTML(h.host)} · max-age ≈ ${days}d</div>
        </div>`;
      superList.appendChild(row);
    }
  }

  const list = $("#cookies-list");
  list.innerHTML = "";
  if (!report.cookies.length) {
    list.innerHTML = '<p class="empty">Nenhum cookie observado.</p>';
    return;
  }
  for (const c of report.cookies.slice(0, 200)) {
    const div = document.createElement("div");
    div.className = "cookie-row" + (c.thirdParty ? " third" : "");
    div.innerHTML = `
      <div>
        <div class="name">${escapeHTML(c.name)}
          ${c.thirdParty ? '<span class="flag-3p">3P</span>' : '<span class="flag-1p">1P</span>'}
          ${c.persistent ? "<span>📌</span>" : "<span>⏱</span>"}
        </div>
        <div class="meta">${escapeHTML(c.domain)}</div>
      </div>
      <code>${escapeHTML(c.value || "")}</code>
    `;
    list.appendChild(div);
  }
}

function renderStorage(report) {
  const origins = report.storage;
  $("#st-origins").textContent = origins.length;
  let lsKeys = 0, ssKeys = 0, idbCount = 0;
  for (const o of origins) {
    lsKeys += (o.localStorage?.keys?.length) || 0;
    ssKeys += (o.sessionStorage?.keys?.length) || 0;
    idbCount += (o.indexedDB?.length) || 0;
  }
  $("#st-ls-keys").textContent = lsKeys;
  $("#st-ss-keys").textContent = ssKeys;
  $("#st-idb").textContent = idbCount;

  const list = $("#storage-list");
  list.innerHTML = "";
  if (!origins.length) {
    list.innerHTML = '<p class="empty">Nenhuma origem com dados armazenados.</p>';
    return;
  }
  for (const o of origins) {
    const div = document.createElement("div");
    div.className = "storage-origin";
    const flag = o.thirdParty ? '<span class="flag-3p">3P</span>' : '<span class="flag-1p">1P</span>';
    const lsBytes = o.localStorage?.totalBytes || 0;
    const ssBytes = o.sessionStorage?.totalBytes || 0;
    let html = `<div class="origin"><span>${flag} ${escapeHTML(o.origin)}</span>
                <span>${formatBytes(lsBytes + ssBytes)}</span></div>`;

    const renderKV = (label, store) => {
      if (!store || !store.keys?.length) return "";
      let inner = `<div class="sec-title">${label} (${store.keys.length} chaves · ${formatBytes(store.totalBytes)})</div>`;
      for (const k of store.keys.slice(0, 12)) {
        inner += `<div class="kv"><span>${escapeHTML(k.key)}</span>
                    <code title="${escapeHTML(k.valuePreview)}">${escapeHTML(k.valuePreview)}</code></div>`;
      }
      if (store.keys.length > 12) {
        inner += `<div class="kv"><span>…</span><code>+${store.keys.length - 12} chaves</code></div>`;
      }
      return inner;
    };
    html += renderKV("localStorage", o.localStorage);
    html += renderKV("sessionStorage", o.sessionStorage);
    if (o.indexedDB?.length) {
      html += `<div class="sec-title">IndexedDB</div>`;
      for (const db of o.indexedDB) {
        const storeStr = db.stores.map(s => `${escapeHTML(s.name)} (${s.count})`).join(", ") || "—";
        html += `<div class="kv"><span>${escapeHTML(db.name)} v${db.version || "?"}</span>
                  <code>${storeStr}</code></div>`;
      }
    }
    div.innerHTML = html;
    list.appendChild(div);
  }
}

function renderFingerprint(report) {
  $("#fp-total").textContent = report.fingerprinting.total;
  $("#fp-apis").textContent = report.fingerprinting.byApi.length;

  const list = $("#fingerprint-list");
  list.innerHTML = "";
  if (!report.fingerprinting.total) {
    list.innerHTML = '<p class="empty">Nenhuma chamada de fingerprinting detectada.</p>';
    return;
  }
  for (const a of report.fingerprinting.byApi.sort((x, y) => y.count - x.count)) {
    const row = document.createElement("div");
    row.className = "fp-row";
    row.innerHTML = `<div><strong>${escapeHTML(a.api)}</strong></div>
                     <div class="meta">${a.count} chamadas</div>`;
    list.appendChild(row);
  }
}

function renderHijack(report) {
  const list = $("#hijack-list");
  list.innerHTML = "";
  if (!report.hijacking.length) {
    list.innerHTML = '<p class="empty">Nenhum sinal de hijacking/hooking.</p>';
  } else {
    for (const h of report.hijacking.slice(0, 50)) {
      const row = document.createElement("div");
      row.className = "hijack-row";
      row.innerHTML = `<div><strong>${escapeHTML(h.type)}</strong>
                       <div class="meta">${escapeHTML(h.detail || "")}</div></div>`;
      list.appendChild(row);
    }
  }

  const sync = $("#sync-list");
  sync.innerHTML = "";
  if (!report.cookieSyncing.length) {
    sync.innerHTML = '<p class="empty">Nenhum cookie syncing detectado.</p>';
  } else {
    for (const s of report.cookieSyncing.slice(0, 50)) {
      const row = document.createElement("div");
      row.className = "sync-row";
      row.innerHTML = `<div>
          <strong>${escapeHTML(s.fromDomain)} → ${escapeHTML(s.toDomain)}</strong>
          <div class="meta">id: <code>${escapeHTML(s.id)}</code></div>
        </div>`;
      sync.appendChild(row);
    }
  }
}

function render(report) {
  if (!report) {
    $("#page-host").textContent = "página sem dados (recarregue)";
    return;
  }
  $("#page-host").textContent = report.hostname || report.url || "—";
  renderScore(report);
  renderThirdParty(report);
  renderCookies(report);
  renderStorage(report);
  renderFingerprint(report);
  renderHijack(report);
}

// -----------------------------------------------------------------------------
// Tabs
// -----------------------------------------------------------------------------
$$(".tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tabs button").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    $$(".tab-pane").forEach(p => p.classList.remove("active"));
    $(`#tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// -----------------------------------------------------------------------------
// Eventos
// -----------------------------------------------------------------------------
async function refresh() {
  const tab = await getActiveTab();
  if (!tab) return;
  const report = await getReportByTab(tab.id);
  render(report);
}

$("#rescan").addEventListener("click", async () => {
  const tab = await getActiveTab();
  if (!tab) return;
  await browser.tabs.sendMessage(tab.id, { type: "pg-rescan-trigger" }).catch(() => {});
  await browser.runtime.sendMessage({ type: "pg-rescan-by-tab", tabId: tab.id }).catch(() => {});
  setTimeout(refresh, 400);
});

$("#open-methodology").addEventListener("click", (e) => {
  e.preventDefault();
  browser.tabs.create({ url: browser.runtime.getURL("docs/PRIVACY_SCORE.md") });
});

refresh();
setInterval(refresh, 1500);
