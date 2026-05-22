"use strict";

// =============================================================================
//  inject.js — roda no PAGE WORLD (mesmo escopo do JS da página).
//  Hooks "soft": preservam o comportamento original e apenas notificam via
//  postMessage. Não bloqueamos nada — o objetivo é detecção/observação.
// =============================================================================

(function () {
  if (window.__pgInjected) return;
  Object.defineProperty(window, "__pgInjected", { value: true });

  function notify(api) {
    try {
      window.postMessage({ __pg: true, type: "pg-fingerprint", api }, "*");
    } catch (_) {}
  }

  function notifyHijacking(signal, detail) {
    try {
      window.postMessage({ __pg: true, type: "pg-hijacking-signal", signal, detail }, "*");
    } catch (_) {}
  }

  // --- Canvas API ---------------------------------------------------------
  try {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (...args) {
      notify("Canvas.toDataURL");
      return origToDataURL.apply(this, args);
    };

    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    if (origToBlob) {
      HTMLCanvasElement.prototype.toBlob = function (...args) {
        notify("Canvas.toBlob");
        return origToBlob.apply(this, args);
      };
    }

    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...args) {
      // Apenas reportamos chamadas com área grande (típica de fingerprinting).
      const w = args[2] || 0, h = args[3] || 0;
      if (w * h >= 100) notify("Canvas.getImageData");
      return origGetImageData.apply(this, args);
    };
  } catch (e) { /* canvas indisponível */ }

  // --- WebGL --------------------------------------------------------------
  try {
    const hookGL = (proto, label) => {
      const orig = proto.getParameter;
      proto.getParameter = function (param) {
        // UNMASKED_VENDOR_WEBGL=0x9245, UNMASKED_RENDERER_WEBGL=0x9246
        if (param === 0x9245 || param === 0x9246) {
          notify(label + ".getParameter(UNMASKED_*)");
        } else {
          notify(label + ".getParameter");
        }
        return orig.apply(this, arguments);
      };
      const origGetExt = proto.getExtension;
      proto.getExtension = function (name) {
        if (typeof name === "string" && /WEBGL_debug_renderer_info/i.test(name)) {
          notify(label + ".getExtension(WEBGL_debug_renderer_info)");
        }
        return origGetExt.apply(this, arguments);
      };
    };
    if (window.WebGLRenderingContext) hookGL(WebGLRenderingContext.prototype, "WebGL");
    if (window.WebGL2RenderingContext) hookGL(WebGL2RenderingContext.prototype, "WebGL2");
  } catch (e) {}

  // --- AudioContext -------------------------------------------------------
  try {
    const hookAudio = (Ctor, label) => {
      if (!Ctor) return;
      const origCreateOsc = Ctor.prototype.createOscillator;
      if (origCreateOsc) {
        Ctor.prototype.createOscillator = function () {
          notify(label + ".createOscillator");
          return origCreateOsc.apply(this, arguments);
        };
      }
      const origCreateDyn = Ctor.prototype.createDynamicsCompressor;
      if (origCreateDyn) {
        Ctor.prototype.createDynamicsCompressor = function () {
          notify(label + ".createDynamicsCompressor");
          return origCreateDyn.apply(this, arguments);
        };
      }
      const origCreateAnalyser = Ctor.prototype.createAnalyser;
      if (origCreateAnalyser) {
        Ctor.prototype.createAnalyser = function () {
          notify(label + ".createAnalyser");
          return origCreateAnalyser.apply(this, arguments);
        };
      }
    };
    hookAudio(window.AudioContext, "AudioContext");
    hookAudio(window.OfflineAudioContext, "OfflineAudioContext");
    hookAudio(window.webkitAudioContext, "webkitAudioContext");
  } catch (e) {}

  // --- Outros sinais clássicos de fingerprinting --------------------------
  try {
    const origFonts = Object.getOwnPropertyDescriptor(Document.prototype, "fonts");
    if (origFonts && origFonts.get) {
      Object.defineProperty(Document.prototype, "fonts", {
        get() {
          notify("Document.fonts");
          return origFonts.get.call(this);
        }
      });
    }
  } catch (e) {}

  // navigator.plugins / navigator.mimeTypes enumeração ampla
  try {
    let pluginAccess = 0;
    const np = Object.getOwnPropertyDescriptor(Navigator.prototype, "plugins");
    if (np && np.get) {
      Object.defineProperty(Navigator.prototype, "plugins", {
        get() {
          pluginAccess++;
          if (pluginAccess === 1) notify("Navigator.plugins");
          return np.get.call(this);
        }
      });
    }
  } catch (e) {}

  // --- Sinais de hijacking ------------------------------------------------
  try {
    // Tentativa de redirecionar via window.location = ... logo após o load.
    let loadFired = false;
    window.addEventListener("load", () => { loadFired = true; }, { once: true });

    const wrapLocation = (key) => {
      const orig = Object.getOwnPropertyDescriptor(Location.prototype, key);
      if (!orig || !orig.set) return;
      Object.defineProperty(Location.prototype, key, {
        set(v) {
          if (!loadFired) {
            notifyHijacking("location_set_before_load",
              `location.${key} alterado para ${String(v).slice(0, 100)} antes do load`);
          }
          return orig.set.call(this, v);
        },
        get: orig.get,
        configurable: true
      });
    };
    wrapLocation("href");
  } catch (e) {}

  try {
    // window.open em loop ou logo no load = popup abuse.
    let opens = 0;
    const origOpen = window.open;
    window.open = function (...args) {
      opens++;
      if (opens > 2) {
        notifyHijacking("popup_spam", `window.open chamado ${opens} vezes`);
      }
      return origOpen.apply(this, args);
    };
  } catch (e) {}

  try {
    // document.write após o load é frequentemente usado para injetar scripts
    // após o usuário interagir — sinal de "hooking".
    const origWrite = document.write.bind(document);
    document.write = function (str) {
      if (document.readyState === "complete" && /<script/i.test(String(str))) {
        notifyHijacking("late_document_write",
          "document.write com <script> após page load");
      }
      return origWrite(str);
    };
  } catch (e) {}
})();
