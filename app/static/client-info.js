/* Site security diagnostics. Never requests a permission or reads form contents. */
(() => {
  "use strict";
  if (window.__nethubClientInfo) return;
  window.__nethubClientInfo = true;
  const safe = (fn, fallback = null) => { try { return fn() ?? fallback; } catch { return fallback; } };
  const media = (q) => safe(() => matchMedia(q).matches);
  const timeout = (promise) => Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 1800))]);
  const hash = async (bytes) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map(x => x.toString(16).padStart(2, "0")).join("");
  const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const postProof = async (body) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    try {
      const response = await fetch("/__nethub/client", {method: "POST", credentials: "same-origin",
        headers: {"Content-Type": "application/json"}, body: JSON.stringify(body), signal: controller.signal});
      if (!response.ok) throw new Error("proof_failed");
      return await response.json();
    } finally { clearTimeout(timer); }
  };
  const replicaKey = "nethub_continuity_v1", cacheName = "nethub-continuity-v1";
  const cachePath = "/__nethub/continuity-record"; // Local CacheStorage entry; never fetched over HTTP.
  const uuid = value => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value || "");
  const readReplica = storage => safe(() => JSON.parse(storage.getItem(replicaKey)));
  const bounded = (promise, fallback = null) => new Promise(resolve => {
    const timer = setTimeout(() => resolve(fallback), 1200);
    Promise.resolve(promise).then(value => { clearTimeout(timer); resolve(value); }, () => { clearTimeout(timer); resolve(fallback); });
  });
  function openProofDb(name) {
    return new Promise(resolve => {
      if (!safe(() => window.indexedDB)) return resolve(null);
      let settled = false;
      const finish = value => { if (!settled) { settled = true; clearTimeout(timer); resolve(value); } else value?.close(); };
      const timer = setTimeout(() => finish(null), 1200);
      try {
        const open = indexedDB.open(name, 1);
        open.onupgradeneeded = () => open.result.createObjectStore("keys");
        open.onsuccess = () => { open.result.onversionchange = () => open.result.close(); finish(open.result); };
        open.onerror = open.onblocked = () => finish(null);
      } catch { finish(null); }
    });
  }
  const dbRead = database => bounded(new Promise((resolve, reject) => {
    if (!database) return resolve(null);
    const tx = database.transaction("keys", "readonly"), req = tx.objectStore("keys").get("primary");
    req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error);
  }));
  function dbWrite(database, record, keepExisting = false) {
    return bounded(new Promise((resolve, reject) => {
      if (!database) return resolve(record);
      const tx = database.transaction("keys", "readwrite"), store = tx.objectStore("keys");
      let selected = record;
      if (keepExisting) {
        const req = store.get("primary");
        req.onsuccess = () => { selected = usableKey(req.result) ? req.result : record; store.put(selected, "primary"); };
      } else store.put(record, "primary");
      tx.oncomplete = () => resolve(selected); tx.onerror = tx.onabort = () => reject(tx.error);
    }), record);
  }
  const usableKey = record => record?.privateKey?.type === "private" && record.privateKey.extractable === false &&
    record.privateKey.algorithm?.name === "ECDSA" && record.privateKey.algorithm.namedCurve === "P-256" &&
    record.publicJwk?.kty === "EC" && record.publicJwk.crv === "P-256";
  async function proveAndRepair() {
    const databases = await Promise.all([openProofDb("nethub-device-proof-v1"), openProofDb("nethub-device-proof-backup-v1")]);
    try {
      const keys = await Promise.all(databases.map(dbRead));
      const cache = await bounded(Promise.resolve().then(() => caches.open(cacheName)));
      const cached = cache ? await bounded(cache.match(cachePath).then(response => response?.json())) : null;
      const replicas = [safe(() => readReplica(localStorage)), safe(() => readReplica(sessionStorage)), cached, ...keys].filter(Boolean);
      let stored = keys.find(usableKey);
      let installation = stored?.installation_id || safe(() => localStorage.getItem("nethub_client_v1")) || replicas.find(x => uuid(x.installation_id))?.installation_id;
      if (!uuid(installation)) installation = crypto.randomUUID();
      if (!stored) {
        const pair = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"]);
        stored = {privateKey: pair.privateKey, publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey), installation_id: installation};
      }
      // First working DB is authoritative. Atomic selection also supports browsers without Web Locks.
      const primary = databases.find(Boolean);
      if (primary) stored = await dbWrite(primary, stored, true);
      if (uuid(stored.installation_id)) installation = stored.installation_id;
      const tokens = [...new Set(replicas.map(x => x.recovery_token).filter(x => typeof x === "string" && x.length <= 2048))].slice(0, 8);
      const challenge = await postProof({device_operation: "challenge", public_key: stored.publicJwk,
        installation_id: installation, recovery_tokens: tokens});
      const signature = await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, stored.privateKey, new TextEncoder().encode(challenge.payload));
      const verified = await postProof({device_operation: "verify", challenge: challenge.challenge, signature: base64url(signature)});
      if (!verified.verified || !uuid(verified.installation_id) || typeof verified.recovery_token !== "string") throw new Error("proof_failed");
      const replica = {installation_id: verified.installation_id, recovery_token: verified.recovery_token};
      // Repair only after server validation. Tokens are bearer identifiers, not old-key proofs.
      safe(() => localStorage.setItem("nethub_client_v1", replica.installation_id));
      safe(() => localStorage.setItem(replicaKey, JSON.stringify(replica)));
      safe(() => sessionStorage.setItem(replicaKey, JSON.stringify(replica)));
      await Promise.all(databases.map(database => dbWrite(database, {...stored, ...replica})));
      if (cache) await bounded(cache.put(cachePath, new Response(JSON.stringify(replica), {headers: {"Content-Type": "application/json"}})));
      return "verified";
    } finally { databases.forEach(database => database?.close()); }
  }
  async function deviceProof() {
    if (!window.isSecureContext || !crypto.subtle) return "unsupported";
    // All replicas belong to this origin; no third-party storage or fingerprint reconstruction.
    if (navigator.locks?.request) return navigator.locks.request("nethub-device-continuity", proveAndRepair);
    return proveAndRepair();
  }
  async function collect() {
    const n = navigator, s = screen, c = n.connection;
    const d = {
      schema: 1, page_path: location.pathname, language: n.language, languages: n.languages,
      timezone: safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone), timezone_offset: new Date().getTimezoneOffset(),
      locale: safe(() => Intl.DateTimeFormat().resolvedOptions().locale), calendar: safe(() => Intl.DateTimeFormat().resolvedOptions().calendar),
      numbering_system: safe(() => Intl.NumberFormat().resolvedOptions().numberingSystem),
      user_agent: n.userAgent, platform: n.platform, vendor: n.vendor, cookie_enabled: n.cookieEnabled,
      webdriver: n.webdriver, global_privacy_control: n.globalPrivacyControl ?? null, do_not_track: n.doNotTrack,
      hardware_concurrency: n.hardwareConcurrency, device_memory: n.deviceMemory ?? null, max_touch_points: n.maxTouchPoints,
      screen_width: s.width, screen_height: s.height, screen_avail_width: s.availWidth, screen_avail_height: s.availHeight,
      color_depth: s.colorDepth, pixel_depth: s.pixelDepth, orientation: s.orientation?.type ?? null,
      viewport_width: innerWidth, viewport_height: innerHeight, pixel_ratio: devicePixelRatio,
      visual_viewport_scale: window.visualViewport?.scale ?? null, visibility: document.visibilityState, focused: document.hasFocus(),
      online: n.onLine, connection_type: c?.type ?? null, effective_type: c?.effectiveType ?? null,
      downlink: c?.downlink ?? null, rtt: c?.rtt ?? null, save_data: c?.saveData ?? null,
      dark_mode: media("(prefers-color-scheme: dark)"), reduced_motion: media("(prefers-reduced-motion: reduce)"),
      contrast: media("(prefers-contrast: more)"), forced_colors: media("(forced-colors: active)"),
      hover: media("(hover: hover)"), pointer_coarse: media("(pointer: coarse)"), gamut: media("(color-gamut: p3)"), hdr: media("(dynamic-range: high)"),
      api_support: ["userAgentData", "connection", "deviceMemory", "gpu", "getBattery", "mediaDevices", "permissions", "storage", "webdriver"].filter(k => k in n),
    };
    const tasks = [];
    const job = (name, fn) => tasks.push(timeout(Promise.resolve().then(fn)).then(() => { d[`status_${name}`] = "available"; }, e => { d[`status_${name}`] = e.message === "timeout" ? "timeout" : "restricted_or_failed"; }));
    const unsupported = (name) => { d[`status_${name}`] = "unsupported"; };
    if (n.userAgentData) job("ua", async () => {
      const u = await n.userAgentData.getHighEntropyValues(["architecture", "bitness", "model", "platformVersion", "fullVersionList", "wow64", "formFactors"]);
      Object.assign(d, {ua_brands: u.brands?.map(x => `${x.brand}:${x.version}`), ua_mobile: u.mobile, ua_platform: u.platform,
        ua_architecture: u.architecture ?? null, ua_bitness: u.bitness ?? null, ua_model: u.model ?? null, ua_platform_version: u.platformVersion ?? null,
        ua_full_version_list: u.fullVersionList?.map(x => `${x.brand}:${x.version}`), ua_wow64: u.wow64 ?? null, ua_form_factors: u.formFactors ?? null});
    }); else unsupported("ua");
    if (n.storage?.estimate) job("storage", async () => { const x = await n.storage.estimate(); d.storage_quota = x.quota; d.storage_usage = x.usage; d.storage_persisted = await n.storage.persisted(); }); else unsupported("storage");
    if (n.getBattery) job("battery", async () => { const x = await n.getBattery(); Object.assign(d, {battery_level: x.level, battery_charging: x.charging, battery_charging_time: Number.isFinite(x.chargingTime) ? x.chargingTime : null, battery_discharging_time: Number.isFinite(x.dischargingTime) ? x.dischargingTime : null}); }); else unsupported("battery");
    if (n.gpu) job("gpu", async () => { const a = await n.gpu.requestAdapter(); if (!a) throw new Error("unavailable"); const x = a.info || {}; Object.assign(d, {gpu_vendor: x.vendor, gpu_architecture: x.architecture, gpu_device: x.device, gpu_description: x.description, gpu_features: Array.from(a.features)}); }); else unsupported("gpu");
    if (n.mediaDevices?.enumerateDevices) job("media", async () => { d.media_devices = (await n.mediaDevices.enumerateDevices()).map(x => `${x.kind}:${x.label || "unavailable"}`); }); else unsupported("media");
    if (n.permissions?.query) job("permissions", async () => { d.permissions = await Promise.all(["geolocation", "camera", "microphone", "notifications"].map(async name => { try { return `${name}:${(await n.permissions.query({name})).state}`; } catch { return `${name}:unsupported`; } })); }); else unsupported("permissions");
    safe(() => {
      const v = document.createElement("video"), a = document.createElement("audio");
      d.video_h264 = v.canPlayType('video/mp4; codecs="avc1.42E01E"'); d.video_vp9 = v.canPlayType('video/webm; codecs="vp9"'); d.video_av1 = v.canPlayType('video/mp4; codecs="av01.0.05M.08"');
      d.audio_aac = a.canPlayType('audio/mp4; codecs="mp4a.40.2"'); d.audio_opus = a.canPlayType('audio/ogg; codecs="opus"');
      const canvas = document.createElement("canvas"), gl = canvas.getContext("webgl");
      if (gl) { const ext = gl.getExtension("WEBGL_debug_renderer_info"); Object.assign(d, {
        webgl_vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        webgl_renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
        webgl_version: gl.getParameter(gl.VERSION), webgl_shading_version: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        webgl_max_texture_size: gl.getParameter(gl.MAX_TEXTURE_SIZE), webgl_extensions: gl.getSupportedExtensions()}); gl.getExtension("WEBGL_lose_context")?.loseContext(); }
    });
    job("canvas", async () => {
      const canvas = document.createElement("canvas"); canvas.width = 240; canvas.height = 50;
      const ctx = canvas.getContext("2d"); if (!ctx) throw new Error("unavailable");
      ctx.fillStyle = "#f90"; ctx.fillRect(5, 5, 75, 25); ctx.font = "16px sans-serif"; ctx.fillStyle = "#167"; ctx.fillText("NetHub diagnostics 123 中文", 10, 30);
      d.font_metrics = ["sans-serif", "serif", "monospace"].map(f => {ctx.font = `16px ${f}`; return `${f}:${ctx.measureText("NetHub 中文 123").width}`;});
      d.canvas_hash = await hash(new TextEncoder().encode(canvas.toDataURL()));
    });
    const Offline = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (Offline) job("audio", async () => { const ctx = new Offline(1, 2048, 44100); const osc = ctx.createOscillator(); osc.frequency.value = 1000; osc.type = "triangle"; osc.connect(ctx.destination); osc.start(); const buffer = await ctx.startRendering(); d.audio_sample_rate = buffer.sampleRate; d.audio_hash = await hash(buffer.getChannelData(0).buffer); }); else unsupported("audio");
    tasks.push(Promise.race([deviceProof(), new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 10000))])
      .then(status => { d.status_device = status; }, () => { d.status_device = "restricted_or_failed"; }));
    await Promise.all(tasks);
    const p = performance.getEntriesByType("navigation")[0];
    if (p) Object.assign(d, {navigation_type: p.type, navigation_duration: p.duration, dom_content_loaded: p.domContentLoadedEventEnd, load_duration: p.loadEventEnd});
    await fetch("/__nethub/client", {method: "POST", credentials: "same-origin", headers: {"Content-Type": "application/json"}, body: JSON.stringify(d), keepalive: true});
  }
  const start = () => { collect().catch(() => {}); };
  if (document.readyState === "complete") start(); else window.addEventListener("load", start, {once: true});
})();
