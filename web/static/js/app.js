/**
 * RDPShot — Cyber-Command Center client.
 * Vanilla JS, no build step. Every initializer no-ops when its DOM hook is absent.
 */
(function () {
  'use strict';

  var SEVERITY_COLORS = {
    critical: '#f43f5e', // rose-500
    high: '#f97316',     // orange-500
    medium: '#f59e0b',   // amber-500
    low: '#0ea5e9',      // sky-500
    info: '#94a3b8'      // slate-400
  };

  var SEVERITY_ALIASES = {
    crit: 'critical',
    high: 'high',
    med: 'medium',
    moderate: 'medium',
    warning: 'medium',
    low: 'low',
    info: 'info',
    informational: 'info'
  };

  var SEVERITY_BADGE_CLASS = {
    critical: 'badge badge-rose',
    high: 'badge badge-orange',
    medium: 'badge badge-amber',
    low: 'badge badge-sky',
    info: 'badge badge-slate'
  };

  var THEME_STORAGE_KEY = 'rdpshot-theme';
  var THEME_EVENT = 'rdpshot:themechange';

  var portalState = {
    open: false,
    resolve: null,
    lastFocus: null,
    toastTimer: null
  };

  /* ------------------------------------------------------------------ */
  /* helpers                                                            */
  /* ------------------------------------------------------------------ */

  function toInt(value, fallback) {
    var n = parseInt(value, 10);
    return isNaN(n) ? (fallback || 0) : n;
  }

  function severityColor(severity) {
    var key = String(severity || 'info').toLowerCase();
    return SEVERITY_COLORS[SEVERITY_ALIASES[key] || key] || SEVERITY_COLORS.info;
  }

  function formatElapsed(totalSeconds) {
    var s = Math.max(0, Math.floor(totalSeconds));
    var hours = Math.floor(s / 3600);
    var minutes = Math.floor((s % 3600) / 60);
    var seconds = s % 60;
    if (hours > 0) {
      return hours + 'h ' + minutes + 'm ' + seconds + 's';
    }
    if (minutes > 0) {
      return minutes + 'm ' + seconds + 's';
    }
    return seconds + 's';
  }

  function parseTime(value) {
    if (!value) {
      return null;
    }
    var t = new Date(value).getTime();
    return isNaN(t) ? null : t;
  }

  function themeToken(name, fallback) {
    var value = window.getComputedStyle(document.documentElement).getPropertyValue(name);
    value = value ? value.trim() : '';
    return value || fallback;
  }

  /* ------------------------------------------------------------------ */
  /* in-portal confirm dialog + toast (no browser confirm/alert)          */
  /* ------------------------------------------------------------------ */

  function portalRoot() {
    return document.getElementById('portal-root');
  }

  function closePortal(result) {
    var root = portalRoot();
    if (!root || !portalState.open) {
      return;
    }
    portalState.open = false;
    root.hidden = true;
    var dialog = root.querySelector('.portal-dialog');
    if (dialog) {
      dialog.classList.remove('is-danger');
    }
    document.removeEventListener('keydown', onPortalKeydown, true);
    if (portalState.lastFocus && typeof portalState.lastFocus.focus === 'function') {
      try {
        portalState.lastFocus.focus();
      } catch (err) {
        /* element may have been removed */
      }
    }
    var resolve = portalState.resolve;
    portalState.resolve = null;
    portalState.lastFocus = null;
    if (resolve) {
      resolve(!!result);
    }
  }

  function onPortalKeydown(ev) {
    if (!portalState.open) {
      return;
    }
    if (ev.key === 'Escape') {
      ev.preventDefault();
      closePortal(false);
      return;
    }
    if (ev.key === 'Enter') {
      var active = document.activeElement;
      if (active && active.getAttribute('data-portal-cancel') !== null) {
        return;
      }
      ev.preventDefault();
      closePortal(true);
    }
  }

  function portalConfirm(options) {
    options = options || {};
    var root = portalRoot();
    if (!root) {
      return Promise.resolve(false);
    }
    if (portalState.open) {
      closePortal(false);
    }

    var title = options.title || 'Confirm action';
    var message = options.message || '';
    var confirmLabel = options.confirmLabel || 'Confirm';
    var cancelLabel = options.cancelLabel || 'Cancel';
    var danger = !!options.danger;
    var eyebrow = options.eyebrow || (danger ? 'Destructive' : 'Confirm');

    var titleEl = document.getElementById('portal-title');
    var messageEl = document.getElementById('portal-message');
    var eyebrowEl = document.getElementById('portal-eyebrow');
    var confirmBtn = root.querySelector('[data-portal-confirm]');
    var cancelBtn = root.querySelector('[data-portal-cancel]');
    var dialog = root.querySelector('.portal-dialog');

    if (titleEl) {
      titleEl.textContent = title;
    }
    if (messageEl) {
      messageEl.textContent = message;
    }
    if (eyebrowEl) {
      eyebrowEl.textContent = eyebrow;
    }
    if (confirmBtn) {
      confirmBtn.textContent = confirmLabel;
    }
    if (cancelBtn) {
      cancelBtn.textContent = cancelLabel;
    }
    if (dialog) {
      dialog.classList.toggle('is-danger', danger);
    }

    portalState.lastFocus = document.activeElement;
    portalState.open = true;
    root.hidden = false;
    document.addEventListener('keydown', onPortalKeydown, true);
    window.setTimeout(function () {
      if (confirmBtn) {
        confirmBtn.focus();
      }
    }, 0);

    return new Promise(function (resolve) {
      portalState.resolve = resolve;
    });
  }

  function portalNotify(message, tone) {
    var toast = document.getElementById('portal-toast');
    if (!toast || !message) {
      return;
    }
    toast.textContent = message;
    toast.classList.remove('hidden', 'is-error', 'is-ok');
    if (tone === 'error') {
      toast.classList.add('is-error');
    } else if (tone === 'ok') {
      toast.classList.add('is-ok');
    }
    if (portalState.toastTimer) {
      window.clearTimeout(portalState.toastTimer);
    }
    portalState.toastTimer = window.setTimeout(function () {
      toast.classList.add('hidden');
    }, 4200);
  }

  function initPortal() {
    var root = portalRoot();
    if (!root) {
      return;
    }
    var confirmBtn = root.querySelector('[data-portal-confirm]');
    var cancelBtn = root.querySelector('[data-portal-cancel]');
    var dismiss = root.querySelectorAll('[data-portal-dismiss]');
    if (confirmBtn) {
      confirmBtn.addEventListener('click', function () {
        closePortal(true);
      });
    }
    if (cancelBtn) {
      cancelBtn.addEventListener('click', function () {
        closePortal(false);
      });
    }
    Array.prototype.forEach.call(dismiss, function (el) {
      el.addEventListener('click', function () {
        closePortal(false);
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* theme: light is the default, dark is opt-in and persisted            */
  /* ------------------------------------------------------------------ */

  function isDarkTheme() {
    return document.documentElement.classList.contains('dark');
  }

  function syncThemeToggles() {
    var dark = isDarkTheme();
    var label = dark ? 'Switch to Corporate Clean (Light)' : 'Switch to Command Center (Dark)';
    var toggles = document.querySelectorAll('[data-theme-toggle]');
    Array.prototype.forEach.call(toggles, function (button) {
      button.setAttribute('aria-pressed', dark ? 'true' : 'false');
      button.setAttribute('aria-label', label);
      button.setAttribute('title', label);
    });
  }

  function applyTheme(theme, persist) {
    var dark = theme === 'dark';
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.setAttribute('data-theme', dark ? 'command-center' : 'corporate-clean');
    if (persist) {
      try {
        window.localStorage.setItem(THEME_STORAGE_KEY, dark ? 'dark' : 'light');
      } catch (err) {
        /* storage can be blocked; the theme still applies to this page */
      }
    }
    syncThemeToggles();
    document.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: { theme: dark ? 'dark' : 'light' } }));
  }

  function initTheme() {
    syncThemeToggles();
    var toggles = document.querySelectorAll('[data-theme-toggle]');
    Array.prototype.forEach.call(toggles, function (button) {
      button.addEventListener('click', function () {
        applyTheme(isDarkTheme() ? 'light' : 'dark', true);
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* progress bars: [data-progress] > [data-progress-fill] + label       */
  /* ------------------------------------------------------------------ */

  function applyProgress(el, done, total) {
    if (!el) {
      return;
    }
    var pct = total > 0 ? Math.min(100, (done / total) * 100) : 0;

    el.setAttribute('data-done', String(done));
    el.setAttribute('data-total', String(total));

    var fill = el.querySelector('[data-progress-fill]');
    if (fill) {
      fill.style.width = pct.toFixed(1) + '%';
    }

    var label = el.querySelector('[data-progress-label]');
    if (label) {
      var full = done + '/' + total + ' (' + pct.toFixed(1) + '%)';
      label.setAttribute('title', full);
      // Compact label inside dense tables so the actions column stays visible.
      if (el.classList.contains('progress-cell') && total >= 10000) {
        label.textContent = pct.toFixed(1) + '%';
      } else {
        label.textContent = full;
      }
    }

    if (el.hasAttribute('role') && el.getAttribute('role') === 'progressbar') {
      el.setAttribute('aria-valuenow', String(done));
      el.setAttribute('aria-valuemax', String(total));
    }
  }

  function initProgress() {
    var bars = document.querySelectorAll('[data-progress]');
    Array.prototype.forEach.call(bars, function (el) {
      applyProgress(el, toInt(el.getAttribute('data-done')), toInt(el.getAttribute('data-total')));
    });
  }

  /* ------------------------------------------------------------------ */
  /* animated counters: [data-counter][data-value]                        */
  /* ------------------------------------------------------------------ */

  function animateCounter(el, target) {
    if (!el) {
      return;
    }
    var start = toInt(el.textContent, 0);
    var delta = target - start;
    if (delta === 0 || target < 0) {
      el.textContent = String(target);
      return;
    }

    var duration = 700;
    var startTime = null;

    function step(timestamp) {
      if (startTime === null) {
        startTime = timestamp;
      }
      var progress = Math.min(1, (timestamp - startTime) / duration);
      var eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = String(Math.round(start + delta * eased));
      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        el.textContent = String(target);
      }
    }

    if (window.requestAnimationFrame) {
      window.requestAnimationFrame(step);
    } else {
      el.textContent = String(target);
    }
  }

  function setCounter(name, value) {
    if (!name) {
      return;
    }
    var els = document.querySelectorAll('[data-counter="' + name + '"]');
    Array.prototype.forEach.call(els, function (el) {
      el.setAttribute('data-value', String(value));
      animateCounter(el, toInt(value));
    });
  }

  function initCounters() {
    var els = document.querySelectorAll('[data-counter]');
    Array.prototype.forEach.call(els, function (el) {
      animateCounter(el, toInt(el.getAttribute('data-value')));
    });
  }

  /* ------------------------------------------------------------------ */
  /* live status board + findings (SSE)                                   */
  /* ------------------------------------------------------------------ */

  var liveFindingCount = 0;
  var lastProgressKey = '';

  function flashCounter(name) {
    var els = document.querySelectorAll('[data-counter="' + name + '"]');
    Array.prototype.forEach.call(els, function (el) {
      var card = el.closest('.live-kpi');
      if (!card) {
        return;
      }
      card.classList.remove('is-flash');
      void card.offsetWidth;
      card.classList.add('is-flash');
      window.setTimeout(function () {
        card.classList.remove('is-flash');
      }, 450);
    });
  }

  function setLiveStatus(status) {
    var el = document.querySelector('[data-live-status]');
    if (!el) {
      return;
    }
    var value = String(status || 'idle').toLowerCase();
    el.textContent = value;
    el.className = 'badge';
    if (value === 'running' || value === 'starting') {
      el.classList.add('badge-indigo');
    } else if (value === 'paused') {
      el.classList.add('badge-amber');
    } else if (value === 'completed' || value === 'done') {
      el.classList.add('badge-emerald');
    } else if (value === 'failed') {
      el.classList.add('badge-rose');
    } else if (value === 'cancelled') {
      el.classList.add('badge-slate');
    } else {
      el.classList.add('badge-slate');
    }
  }

  function setLiveScan(scanID) {
    var el = document.querySelector('[data-live-scan]');
    if (!el || !scanID) {
      return;
    }
    el.innerHTML = 'Scan <a class="tone-indigo" href="/scans/' + encodeURIComponent(scanID) + '">' +
      scanID + '</a>';
  }

  function setLatest(text, tone) {
    var wrap = document.querySelector('[data-live-latest]');
    var el = document.querySelector('[data-live-latest-text]');
    if (!el || !text) {
      return;
    }
    el.textContent = text;
    if (wrap) {
      var keepMt = wrap.classList.contains('mt-5');
      wrap.className = 'live-latest' + (keepMt ? ' mt-5' : '');
      if (tone) {
        wrap.classList.add('is-' + tone);
      }
    }
  }

  var audioAlertsEnabled = false;
  try {
    audioAlertsEnabled = localStorage.getItem('rdpshot_audio_alerts') === 'true';
  } catch (e) {}

  function playAudioChime(type) {
    if (!audioAlertsEnabled) return;
    try {
      var ctx = new (window.AudioContext || window.webkitAudioContext)();
      var osc = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      var now = ctx.currentTime;
      if (type === 'critical') {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.setValueAtTime(440, now + 0.12);
        gain.gain.setValueAtTime(0.18, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.35);
        osc.start(now);
        osc.stop(now + 0.35);
      } else {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(523.25, now);
        osc.frequency.setValueAtTime(659.25, now + 0.1);
        osc.frequency.setValueAtTime(783.99, now + 0.2);
        gain.gain.setValueAtTime(0.15, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.45);
        osc.start(now);
        osc.stop(now + 0.45);
      }
    } catch (err) {}
  }

  function triggerVisualPulse(type) {
    var targets = [
      document.querySelector('[data-live-status]'),
      document.getElementById('live-terminal-card'),
      document.querySelector('.page-head')
    ];
    var cls = type === 'critical' ? 'pulse-critical' : 'pulse-success';
    targets.forEach(function (el) {
      if (!el) return;
      el.classList.add(cls);
      setTimeout(function () { el.classList.remove(cls); }, 3500);
    });
  }

  function appendLiveTerminalItem(eventType, title, metaText, badgeText, badgeClass) {
    var list = document.getElementById('live-findings');
    if (!list) return;
    var empty = list.querySelector('[data-live-empty]');
    if (empty && empty.parentNode) {
      empty.parentNode.removeChild(empty);
    }
    var item = document.createElement('li');
    item.className = 'finding-item';
    item.setAttribute('data-event-type', eventType);
    if (eventType === 'finding') {
      item.setAttribute('data-event-sev', String(badgeText).toLowerCase());
    }

    var head = document.createElement('div');
    head.className = 'finding-head';

    var titleEl = document.createElement('p');
    titleEl.className = 'finding-title';
    titleEl.textContent = String(title);

    var badge = document.createElement('span');
    badge.className = badgeClass || 'badge badge-slate';
    badge.textContent = String(badgeText);

    head.appendChild(titleEl);
    head.appendChild(badge);

    var meta = document.createElement('p');
    meta.className = 'finding-meta';
    meta.textContent = metaText || '';

    item.appendChild(head);
    item.appendChild(meta);
    list.insertBefore(item, list.firstChild);

    while (list.children.length > 25) {
      list.removeChild(list.lastChild);
    }

    liveFindingCount += 1;
    var countEl = document.querySelector('[data-live-finding-count]');
    if (countEl) {
      countEl.textContent = String(liveFindingCount);
    }
  }

  function prependFinding(payload) {
    var severity = payload.severity || payload.Severity || 'info';
    var title = payload.title || payload.Title || payload.check_id || payload.CheckID || 'Finding';
    var address = payload.address || payload.Address || payload.host || '';
    var port = payload.port || payload.Port || '';
    var target = address ? address + (port ? ':' + port : '') : 'unknown target';
    var badgeCls = SEVERITY_BADGE_CLASS[SEVERITY_ALIASES[String(severity).toLowerCase()] || String(severity).toLowerCase()] || SEVERITY_BADGE_CLASS.info;

    appendLiveTerminalItem('finding', title, target, severity, badgeCls);
  }

  function updateProgressFromPayload(payload) {
    if (!payload || typeof payload !== 'object') {
      return;
    }
    var done = payload.done !== undefined ? payload.done : payload.Done;
    var total = payload.total !== undefined ? payload.total : payload.Total;
    var progressEl = document.getElementById('scan-progress');

    if (progressEl && done !== undefined && total !== undefined) {
      applyProgress(progressEl, toInt(done), toInt(total));
    }

    var counterMap = {
      total: payload.total !== undefined ? payload.total : payload.Total,
      done: done,
      open: payload.open !== undefined ? payload.open : payload.Open,
      closed: payload.closed !== undefined ? payload.closed : payload.Closed,
      findings: payload.findings !== undefined ? payload.findings : payload.Findings,
      creds: payload.creds !== undefined ? payload.creds : payload.Creds,
      screens: payload.screens !== undefined ? payload.screens : payload.Screens,
      active: payload.active_jobs !== undefined ? payload.active_jobs : payload.ActiveJobs
    };

    Object.keys(counterMap).forEach(function (name) {
      if (counterMap[name] === undefined || counterMap[name] === null) {
        return;
      }
      var next = toInt(counterMap[name]);
      var currentEls = document.querySelectorAll('[data-counter="' + name + '"]');
      var prev = currentEls.length ? toInt(currentEls[0].getAttribute('data-value'), NaN) : NaN;
      setCounter(name, next);
      if (!isNaN(prev) && prev !== next) {
        flashCounter(name);
      }
    });

    var label = document.getElementById('scan-progress-label') ||
      document.querySelector('[data-live-progress-label]');
    if (label && done !== undefined && total !== undefined) {
      var pct = toInt(total) > 0 ? ((toInt(done) / toInt(total)) * 100).toFixed(1) : '0.0';
      label.textContent = done + '/' + total + ' (' + pct + '%)';
    }
  }

  function unwrapLiveEvent(type, rawData) {
    var outer = {};
    if (rawData) {
      try {
        outer = JSON.parse(rawData);
      } catch (err) {
        outer = { message: String(rawData) };
      }
    }
    if (typeof outer !== 'object' || outer === null) {
      outer = { message: String(outer) };
    }
    var effectiveType = String(outer.type || outer.Type || type || 'message').toLowerCase();
    var inner = outer.payload !== undefined ? outer.payload : outer.Payload;
    if (inner === undefined) {
      inner = outer;
    }
    return {
      type: effectiveType,
      payload: inner,
      scanID: outer.scan_id || outer.ScanID || '',
      message: outer.message || outer.Message || ''
    };
  }

  function handleEvent(type, rawData) {
    var ev = unwrapLiveEvent(type, rawData);
    var effectiveType = ev.type;
    var payload = ev.payload;

    if (ev.scanID) {
      setLiveScan(ev.scanID);
    }

    if (effectiveType === 'scan.started' || effectiveType === 'scan.progress' ||
        effectiveType === 'progress' || effectiveType === 'scan_progress' ||
        effectiveType === 'scan.paused' || effectiveType === 'scan.resumed' ||
        effectiveType === 'scan.finished' || effectiveType === 'scan.failed') {
      var key = JSON.stringify(payload);
      if (key !== lastProgressKey) {
        lastProgressKey = key;
        updateProgressFromPayload(payload);
      }
    }

    if (effectiveType === 'scan.started') {
      setLiveStatus('running');
      setLatest('Scan started', 'info');
      return;
    }
    if (effectiveType === 'scan.paused') {
      setLiveStatus('paused');
      setLatest('Scan paused', 'medium');
      return;
    }
    if (effectiveType === 'scan.resumed') {
      setLiveStatus('running');
      setLatest('Scan resumed', 'info');
      return;
    }
    if (effectiveType === 'scan.finished' || effectiveType === 'completed' || effectiveType === 'done') {
      setLiveStatus('completed');
      setLatest('Scan completed', 'ok');
      return;
    }
    if (effectiveType === 'scan.failed' || effectiveType === 'failed' || effectiveType === 'error') {
      setLiveStatus('failed');
      setLatest(ev.message || (payload && (payload.message || payload.Message)) || 'Scan failed', 'high');
      return;
    }
    if (effectiveType === 'scan.progress' || effectiveType === 'progress' || effectiveType === 'scan_progress') {
      if (!document.querySelector('[data-live-status]') ||
          String(document.querySelector('[data-live-status]').textContent).toLowerCase() === 'idle') {
        setLiveStatus('running');
      }
      return;
    }

    if (effectiveType === 'finding' || effectiveType === 'findings') {
      var finding = payload && typeof payload === 'object' ? payload : {};
      prependFinding(finding);
      var sev = String(finding.severity || finding.Severity || 'info').toLowerCase();
      var title = finding.title || finding.Title || finding.check_id || finding.CheckID || 'Finding';
      var address = finding.address || finding.Address || '';
      var port = finding.port || finding.Port || '';
      if (sev === 'critical') {
        triggerVisualPulse('critical');
        playAudioChime('critical');
      } else if (sev === 'high') {
        triggerVisualPulse('critical');
      }
      setLatest(String(sev).toUpperCase() + ' · ' + title + (address ? ' · ' + address + (port ? ':' + port : '') : ''),
        sev === 'critical' || sev === 'high' ? sev : (sev === 'medium' ? 'medium' : 'info'));
      return;
    }

    if (effectiveType === 'credential' || effectiveType === 'cred') {
      var cred = payload && typeof payload === 'object' ? payload : {};
      var user = cred.username || cred.Username || 'user';
      var hostStr = (cred.address || cred.Address || '?') + ':' + (cred.port || cred.Port || '');
      appendLiveTerminalItem('credential', 'Verified credential: ' + user, hostStr, 'verified', 'badge badge-emerald');
      triggerVisualPulse('success');
      playAudioChime('success');
      setLatest('Credential verified · ' + user + '@' + hostStr, 'ok');
      return;
    }

    if (effectiveType === 'screenshot') {
      var shot = payload && typeof payload === 'object' ? payload : {};
      var shotTarget = (shot.address || shot.Address || '') + (shot.port || shot.Port ? ':' + (shot.port || shot.Port) : '');
      appendLiveTerminalItem('screenshot', 'Screenshot captured', shotTarget, 'screen', 'badge badge-amber');
      setLatest('Screenshot captured · ' + shotTarget, 'info');
      return;
    }

    if (effectiveType === 'host.done' || effectiveType === 'host') {
      var host = payload && typeof payload === 'object' ? payload : {};
      var ep = host.endpoint || host.Endpoint || {};
      var addr = ep.address || ep.Address || host.address || host.Address || '';
      var hport = ep.port || ep.Port || host.port || host.Port || '';
      var state = host.state || host.State || '';
      if (addr) {
        setLatest('Host ' + state + ' · ' + addr + (hport ? ':' + hport : ''),
          state === 'open' ? 'ok' : 'info');
      }
      return;
    }

    if (effectiveType === 'log') {
      var log = payload && typeof payload === 'object' ? payload : {};
      var msg = log.message || log.Message || ev.message;
      if (msg) {
        setLatest(String(msg), 'info');
      }
    }
  }

  function initLive() {
    var board = document.querySelector('[data-live-board]');
    var findings = document.getElementById('live-findings');
    var progressEl = document.getElementById('scan-progress');
    var latest = document.querySelector('[data-live-latest]');
    if (!board && !findings && !progressEl && !latest) {
      return;
    }
    if (typeof window.EventSource === 'undefined') {
      setLatest('Live streaming is not supported by this browser', 'high');
      return;
    }

    var statusSeed = document.querySelector('[data-live-status]');
    if (statusSeed && statusSeed.textContent) {
      setLiveStatus(statusSeed.textContent.trim());
    }

    var scanHost = document.querySelector('[data-scan-id]');
    var scanID = scanHost ? (scanHost.getAttribute('data-scan-id') || '') : '';
    if (!scanID) {
      try {
        scanID = new URLSearchParams(window.location.search).get('scan') || '';
      } catch (err) {
        scanID = '';
      }
    }
    if (scanID) {
      setLiveScan(scanID);
    }

    var url = '/api/v1/events' + (scanID ? '?scan=' + encodeURIComponent(scanID) : '');
    var source;
    try {
      source = new EventSource(url);
    } catch (err) {
      setLatest('Unable to open event stream', 'high');
      return;
    }

    var eventTypes = [
      'scan.started', 'scan.progress', 'scan.paused', 'scan.resumed',
      'scan.finished', 'scan.failed', 'host.done', 'finding',
      'credential', 'screenshot', 'log'
    ];

    eventTypes.forEach(function (type) {
      source.addEventListener(type, function (ev) {
        handleEvent(type, ev.data);
      });
    });

    source.addEventListener('error', function () {
      setLatest('Event stream reconnecting…', 'medium');
    });
  }

  /* ------------------------------------------------------------------ */
  /* quick scan form                                                     */
  /* ------------------------------------------------------------------ */

  function parseJSONResponse(resp) {
    return resp.text().then(function (text) {
      var parsed = null;
      try {
        parsed = text ? JSON.parse(text) : {};
      } catch (err) {
        parsed = null;
      }
      return { ok: resp.ok, status: resp.status, body: parsed, text: text };
    });
  }

  function initScanForm() {
    var form = document.getElementById('quick-scan-form');
    if (!form) {
      return;
    }

    var errorBox = document.getElementById('scan-form-error');
    var successBox = document.getElementById('scan-form-success');
    var linkEl = document.getElementById('scan-form-link');

    function showError(message) {
      if (!errorBox) {
        return;
      }
      errorBox.textContent = message;
      errorBox.classList.remove('hidden');
      if (successBox) {
        successBox.classList.add('hidden');
      }
    }

    function showSuccess(scanID) {
      if (errorBox) {
        errorBox.classList.add('hidden');
      }
      if (successBox) {
        successBox.classList.remove('hidden');
      }
      if (linkEl && scanID) {
        linkEl.setAttribute('href', '/scans/' + encodeURIComponent(scanID));
      }
    }

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();

      var targets = form.querySelector('[data-targets-input]');
      var targetsFile = form.querySelector('[data-targets-file]');
      var hasTargetsText = targets && targets.value.trim() !== '';
      var hasTargetsFile = targetsFile && targetsFile.files && targetsFile.files.length > 0;
      if (!hasTargetsText && !hasTargetsFile) {
        showError('Enter targets or load them from a file.');
        return;
      }

      var ack = document.getElementById('ack_authorized');
      if (ack && !ack.checked) {
        showError('Please confirm that you are authorized to test these targets.');
        return;
      }

      fetch(form.getAttribute('action') || '/api/v1/scans', {
        method: 'POST',
        body: prepareWordlistFormData(form)
      })
        .then(parseJSONResponse)
        .then(function (result) {
          if (!result.ok) {
            var message = (result.body && (result.body.error || result.body.message)) || result.text;
            showError('Scan request failed (' + result.status + '): ' + (message || 'unknown error'));
            return;
          }

          var body = result.body || {};
          var scanID = body.id || body.ID || body.scan_id || body.scanID ||
            (body.scan && (body.scan.ID || body.scan.id)) || '';

          showSuccess(scanID);
          if (scanID) {
            window.setTimeout(function () {
              window.location.href = '/scans/' + encodeURIComponent(scanID);
            }, 1200);
          }
        })
        .catch(function (err) {
          showError('Scan request failed: ' + err.message);
        });
    });
  }

  /* ------------------------------------------------------------------ */
  /* scan lifecycle buttons: pause / resume / cancel / delete             */
  /* ------------------------------------------------------------------ */

  function postScanAction(button, path, confirmOptions) {
    var scanID = button.getAttribute(button.hasAttribute('data-cancel-scan') ? 'data-cancel-scan' :
      button.hasAttribute('data-pause-scan') ? 'data-pause-scan' :
      button.hasAttribute('data-resume-scan') ? 'data-resume-scan' :
      'data-delete-scan');
    if (!scanID) {
      return;
    }

    var proceed = confirmOptions
      ? portalConfirm(confirmOptions)
      : Promise.resolve(true);

    proceed.then(function (ok) {
      if (!ok) {
        return;
      }

      button.disabled = true;
      var method = button.hasAttribute('data-delete-scan') ? 'DELETE' : 'POST';
      fetch('/api/v1/scans/' + encodeURIComponent(scanID) + path, { method: method })
        .then(function (resp) {
          if (!resp.ok) {
            return resp.text().then(function (text) {
              throw new Error(text || ('request failed with status ' + resp.status));
            });
          }
          if (button.hasAttribute('data-delete-scan')) {
            window.location.href = '/scans';
            return;
          }
          window.location.reload();
        })
        .catch(function (err) {
          button.disabled = false;
          portalNotify('Unable to update scan: ' + err.message, 'error');
        });
    });
  }

  function initScanLifecycleButtons() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-cancel-scan]'), function (button) {
      button.addEventListener('click', function () {
        var id = button.getAttribute('data-cancel-scan');
        postScanAction(button, '/cancel', {
          title: 'Cancel scan',
          message: 'Cancel scan ' + id + '? Running checks will be stopped.',
          confirmLabel: 'Cancel scan',
          cancelLabel: 'Keep running',
          danger: true,
          eyebrow: 'Scan control'
        });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-pause-scan]'), function (button) {
      button.addEventListener('click', function () {
        postScanAction(button, '/pause', null);
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-resume-scan]'), function (button) {
      button.addEventListener('click', function () {
        postScanAction(button, '/resume', null);
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-delete-scan]'), function (button) {
      button.addEventListener('click', function () {
        var id = button.getAttribute('data-delete-scan');
        postScanAction(button, '', {
          title: 'Delete scan',
          message: 'Delete scan ' + id + ' and its stored artifacts? Active runs are stopped first. This cannot be undone.',
          confirmLabel: 'Delete',
          cancelLabel: 'Keep scan',
          danger: true,
          eyebrow: 'Destructive'
        });
      });
    });
  }

  function initBruteForm() {
    var form = document.getElementById('brute-scan-form');
    if (!form) {
      return;
    }

    var errorBox = document.getElementById('brute-form-error');
    var selectAll = document.querySelector('[data-brute-select-all]');
    if (selectAll) {
      selectAll.addEventListener('click', function () {
        Array.prototype.forEach.call(document.querySelectorAll('[data-brute-host]'), function (box) {
          box.checked = true;
        });
      });
    }

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var selected = form.querySelectorAll('[data-brute-host]:checked');
      if (!selected.length) {
        if (errorBox) {
          errorBox.textContent = 'Select at least one open host.';
          errorBox.classList.remove('hidden');
        }
        return;
      }
      var ack = document.getElementById('brute_ack_authorized');
      if (ack && !ack.checked) {
        if (errorBox) {
          errorBox.textContent = 'Please confirm that you are authorized to test these hosts.';
          errorBox.classList.remove('hidden');
        }
        return;
      }

      fetch(form.getAttribute('action'), {
        method: 'POST',
        body: prepareWordlistFormData(form)
      })
        .then(parseJSONResponse)
        .then(function (result) {
          if (!result.ok) {
            var message = (result.body && (result.body.error || result.body.message)) || result.text;
            if (errorBox) {
              errorBox.textContent = message || ('request failed (' + result.status + ')');
              errorBox.classList.remove('hidden');
            }
            return;
          }
          var body = result.body || {};
          var scanID = body.id || body.ID || '';
          if (scanID) {
            window.location.href = '/scans/' + encodeURIComponent(scanID);
          }
        })
        .catch(function (err) {
          if (errorBox) {
            errorBox.textContent = err.message;
            errorBox.classList.remove('hidden');
          }
        });
    });
  }

  function initFindingToggles() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-finding-toggle]'), function (button) {
      button.addEventListener('click', function () {
        var index = button.getAttribute('data-finding-toggle');
        var row = document.querySelector('[data-finding-details="' + index + '"]');
        if (!row) {
          return;
        }
        var open = row.hasAttribute('hidden');
        if (open) {
          row.removeAttribute('hidden');
          button.setAttribute('aria-expanded', 'true');
        } else {
          row.setAttribute('hidden', '');
          button.setAttribute('aria-expanded', 'false');
        }
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Playbook scripts & 1-click remediation                             */
  /* ------------------------------------------------------------------ */

  var playbookCache = {};

  function loadPlaybookScript(checkID, tab, preEl, downloadLink) {
    if (!checkID || !preEl) return;
    tab = tab || 'powershell';
    function applyData(scripts) {
      var script = scripts[tab] || '# No script template available for ' + tab;
      preEl.textContent = script;
      if (downloadLink) {
        downloadLink.setAttribute('href', '/api/v1/playbooks/' + encodeURIComponent(checkID) + '/script?format=' + encodeURIComponent(tab) + '&download=1');
      }
    }

    if (playbookCache[checkID]) {
      applyData(playbookCache[checkID]);
      return;
    }
    fetch('/api/v1/playbooks/' + encodeURIComponent(checkID))
      .then(function (resp) {
        if (!resp.ok) throw new Error('Failed to load playbook');
        return resp.json();
      })
      .then(function (data) {
        playbookCache[checkID] = data.scripts || {};
        applyData(playbookCache[checkID]);
      })
      .catch(function (err) {
        preEl.textContent = '# Error loading playbook: ' + err.message;
      });
  }

  function initPlaybookScripts() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-playbook-box]'), function (box) {
      var checkID = box.getAttribute('data-playbook-box');
      var preEl = box.querySelector('[data-script-content]');
      var downloadLink = box.querySelector('[data-download-script]');
      loadPlaybookScript(checkID, 'powershell', preEl, downloadLink);

      var tabs = box.querySelectorAll('[data-script-tab]');
      Array.prototype.forEach.call(tabs, function (tabBtn) {
        tabBtn.addEventListener('click', function () {
          var selectedTab = tabBtn.getAttribute('data-script-tab');
          Array.prototype.forEach.call(tabs, function (t) { t.classList.remove('is-active'); });
          tabBtn.classList.add('is-active');
          loadPlaybookScript(checkID, selectedTab, preEl, downloadLink);
        });
      });

      var copyBtn = box.querySelector('[data-copy-script]');
      if (copyBtn) {
        copyBtn.addEventListener('click', function () {
          var label = copyBtn.querySelector('[data-copy-label]') || copyBtn;
          var textToCopy = preEl ? preEl.textContent : '';
          if (!navigator.clipboard) {
            var temp = document.createElement('textarea');
            temp.value = textToCopy;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand('copy');
            document.body.removeChild(temp);
          } else {
            navigator.clipboard.writeText(textToCopy);
          }
          var old = label.textContent;
          label.textContent = 'Copied!';
          setTimeout(function () { label.textContent = old; }, 2000);
        });
      }
    });

    Array.prototype.forEach.call(document.querySelectorAll('[data-quick-remediate]'), function (btn) {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        var index = btn.getAttribute('data-quick-remediate');
        var row = document.querySelector('[data-finding-details="' + index + '"]');
        if (row) {
          row.removeAttribute('hidden');
          var toggleBtn = document.querySelector('[data-finding-toggle="' + index + '"]');
          if (toggleBtn) toggleBtn.setAttribute('aria-expanded', 'true');
          row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Kanban vulnerability triage board                                  */
  /* ------------------------------------------------------------------ */

  function initKanbanBoard() {
    var tableWrap = document.getElementById('findings-table-wrap');
    var kanbanWrap = document.getElementById('findings-kanban-wrap');
    var btnTable = document.getElementById('btn-view-table');
    var btnKanban = document.getElementById('btn-view-kanban');
    var bulkControls = document.getElementById('bulk-triage-controls');
    if (!tableWrap || !kanbanWrap || !btnTable || !btnKanban) return;

    btnTable.addEventListener('click', function () {
      btnTable.classList.add('is-active');
      btnKanban.classList.remove('is-active');
      tableWrap.classList.remove('hidden');
      kanbanWrap.classList.add('hidden');
      if (bulkControls) bulkControls.classList.remove('hidden');
    });

    btnKanban.addEventListener('click', function () {
      btnKanban.classList.add('is-active');
      btnTable.classList.remove('is-active');
      kanbanWrap.classList.remove('hidden');
      tableWrap.classList.add('hidden');
      if (bulkControls) bulkControls.classList.add('hidden');
      renderKanbanCards();
    });

    function getFindingsFromDOM() {
      var rows = document.querySelectorAll('[data-finding-row]');
      var list = [];
      Array.prototype.forEach.call(rows, function (row) {
        var id = row.getAttribute('data-finding-id');
        if (!id) return;
        list.push({
          id: id,
          address: row.getAttribute('data-finding-address') || '',
          port: row.getAttribute('data-finding-port') || '',
          title: row.getAttribute('data-finding-title') || '',
          severity: row.getAttribute('data-finding-severity') || 'info',
          checkID: row.getAttribute('data-finding-check') || '',
          cve: row.getAttribute('data-finding-cve') || '',
          triage: row.getAttribute('data-finding-triage') || 'open',
          rowIndex: row.getAttribute('data-finding-row')
        });
      });
      return list;
    }

    function renderKanbanCards() {
      var findings = getFindingsFromDOM();
      var columns = ['open', 'confirmed', 'false_positive', 'remediated'];
      var counts = { open: 0, confirmed: 0, false_positive: 0, remediated: 0 };

      columns.forEach(function (col) {
        var zone = kanbanWrap.querySelector('[data-kanban-zone="' + col + '"]');
        if (zone) zone.innerHTML = '';
      });

      findings.forEach(function (f) {
        var status = f.triage || 'open';
        if (counts[status] !== undefined) counts[status]++;
        var zone = kanbanWrap.querySelector('[data-kanban-zone="' + status + '"]');
        if (!zone) return;

        var card = document.createElement('div');
        card.className = 'kanban-card p-3 rounded bg-surface-primary border border-subtle shadow-sm space-y-2 cursor-grab active:cursor-grabbing hover:border-indigo-400 transition-colors';
        card.setAttribute('draggable', 'true');
        card.setAttribute('data-card-id', f.id);

        var sevCls = SEVERITY_BADGE_CLASS[f.severity.toLowerCase()] || 'badge badge-slate';
        card.innerHTML =
          '<div class="flex items-center justify-between gap-1">' +
            '<span class="' + sevCls + ' text-xs">' + escapeHtml(f.severity) + '</span>' +
            '<span class="font-mono text-xs text-subtle">' + escapeHtml(f.address) + ':' + escapeHtml(f.port) + '</span>' +
          '</div>' +
          '<p class="font-medium text-xs text-primary leading-snug">' + escapeHtml(f.title) + '</p>' +
          (f.cve ? '<span class="badge badge-outline text-[10px]">' + escapeHtml(f.cve) + '</span>' : '') +
          '<div class="flex items-center justify-between pt-1 border-t border-subtle text-xs gap-1">' +
            '<button type="button" class="btn btn-ghost btn-xs text-[11px] py-0.5 px-1" data-kanban-remediate="' + f.rowIndex + '">Remediate</button>' +
            '<select class="input input-xs text-[11px] py-0.5 px-1 rounded" data-kanban-move="' + f.id + '" aria-label="Change triage status">' +
              '<option value="open"' + (status === 'open' ? ' selected' : '') + '>Open</option>' +
              '<option value="confirmed"' + (status === 'confirmed' ? ' selected' : '') + '>Confirmed</option>' +
              '<option value="false_positive"' + (status === 'false_positive' ? ' selected' : '') + '>False Positive</option>' +
              '<option value="remediated"' + (status === 'remediated' ? ' selected' : '') + '>Remediated</option>' +
            '</select>' +
          '</div>';

        card.addEventListener('dragstart', function (e) {
          e.dataTransfer.setData('text/plain', f.id);
          card.classList.add('opacity-50');
        });
        card.addEventListener('dragend', function () {
          card.classList.remove('opacity-50');
        });

        zone.appendChild(card);
      });

      columns.forEach(function (col) {
        var countEl = kanbanWrap.querySelector('[data-kanban-count="' + col + '"]');
        if (countEl) countEl.textContent = String(counts[col]);
      });

      Array.prototype.forEach.call(kanbanWrap.querySelectorAll('[data-kanban-move]'), function (select) {
        select.addEventListener('change', function () {
          var fid = select.getAttribute('data-kanban-move');
          var newStatus = select.value;
          updateFindingStatus(fid, newStatus);
        });
      });

      Array.prototype.forEach.call(kanbanWrap.querySelectorAll('[data-kanban-remediate]'), function (btn) {
        btn.addEventListener('click', function () {
          var idx = btn.getAttribute('data-kanban-remediate');
          btnTable.click();
          var row = document.querySelector('[data-finding-details="' + idx + '"]');
          if (row) {
            row.removeAttribute('hidden');
            var tBtn = document.querySelector('[data-finding-toggle="' + idx + '"]');
            if (tBtn) tBtn.setAttribute('aria-expanded', 'true');
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
        });
      });

      columns.forEach(function (col) {
        var zone = kanbanWrap.querySelector('[data-kanban-zone="' + col + '"]');
        if (!zone) return;
        zone.addEventListener('dragover', function (e) {
          e.preventDefault();
          zone.classList.add('bg-indigo-500/10', 'rounded');
        });
        zone.addEventListener('dragleave', function () {
          zone.classList.remove('bg-indigo-500/10', 'rounded');
        });
        zone.addEventListener('drop', function (e) {
          e.preventDefault();
          zone.classList.remove('bg-indigo-500/10', 'rounded');
          var fid = e.dataTransfer.getData('text/plain');
          if (fid) {
            updateFindingStatus(fid, col);
          }
        });
      });
    }

    function updateFindingStatus(findingID, newStatus) {
      fetch('/api/v1/findings/' + encodeURIComponent(findingID) + '/triage', {
        method: 'PATCH',
        headers: authHeaders(),
        body: JSON.stringify({ triage_status: newStatus })
      })
      .then(function (resp) {
        if (!resp.ok) throw new Error('Status update failed');
        var row = document.querySelector('[data-finding-id="' + findingID + '"]');
        if (row) {
          row.setAttribute('data-finding-triage', newStatus);
          var select = row.querySelector('[data-triage-finding]');
          if (select) select.value = newStatus;
        }
        portalNotify('Triage status set to ' + newStatus, 'ok');
        renderKanbanCards();
      })
      .catch(function (err) {
        portalNotify(err.message, 'error');
      });
    }
  }

  /* ------------------------------------------------------------------ */
  /* Compliance Posture Radar Chart (Chart.js Spider)                   */
  /* ------------------------------------------------------------------ */

  function initComplianceRadar() {
    if (typeof window.Chart === 'undefined') return;

    var detailCanvas = document.getElementById('compliance-radar-chart');
    if (detailCanvas) {
      var scanID = detailCanvas.getAttribute('data-scan-id');
      if (scanID) {
        fetch('/api/v1/scans/' + encodeURIComponent(scanID) + '/compliance-posture')
          .then(function (resp) { return resp.json(); })
          .then(function (posture) {
            renderRadarChart(detailCanvas, [posture], ['#4f46e5'], ['rgba(79, 70, 229, 0.25)']);
            var overallBadge = document.querySelector('[data-compliance-overall]');
            if (overallBadge) {
              overallBadge.textContent = posture.overall_score + '% (' + posture.grade + ')';
            }
            if (posture.standards) {
              posture.standards.forEach(function (std) {
                var el = document.querySelector('[data-comp-score="' + std.standard + '"]');
                if (el) el.textContent = std.score + '% (' + std.grade + ')';
              });
            }
          })
          .catch(function () {});
      }
    }

    var reportCanvas = document.getElementById('reports-compliance-radar');
    if (reportCanvas) {
      fetch('/api/v1/scans/all/compliance-posture')
        .then(function (resp) { return resp.json(); })
        .then(function (posture) {
          renderRadarChart(reportCanvas, [posture], ['#06b6d4'], ['rgba(6, 182, 212, 0.25)']);
          var badge = document.querySelector('[data-report-radar-badge]');
          if (badge) badge.textContent = 'Overall: ' + posture.overall_score + '% (' + posture.grade + ')';
        })
        .catch(function () {});
    }

    var compareCanvas = document.getElementById('compare-radar-chart');
    if (compareCanvas) {
      var baseID = compareCanvas.getAttribute('data-base-id');
      var againstID = compareCanvas.getAttribute('data-against-id');
      if (baseID && againstID) {
        Promise.all([
          fetch('/api/v1/scans/' + encodeURIComponent(baseID) + '/compliance-posture').then(function (r) { return r.json(); }),
          fetch('/api/v1/scans/' + encodeURIComponent(againstID) + '/compliance-posture').then(function (r) { return r.json(); })
        ])
        .then(function (res) {
          var basePosture = res[0];
          var againstPosture = res[1];
          basePosture.label = 'Base Scan (' + basePosture.overall_score + '%)';
          againstPosture.label = 'Against Scan (' + againstPosture.overall_score + '%)';
          renderRadarChart(compareCanvas, [basePosture, againstPosture], ['#94a3b8', '#10b981'], ['rgba(148, 163, 184, 0.2)', 'rgba(16, 185, 129, 0.3)']);
        })
        .catch(function () {});
      }
    }

    function renderRadarChart(canvas, postures, borderColors, bgColors) {
      var labels = ['CIS Benchmark', 'PCI-DSS 4.0', 'NIST SP 800-53', 'ISO/IEC 27001'];
      var isDark = document.documentElement.classList.contains('dark');
      var gridColor = isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.1)';
      var pointLabelColor = isDark ? '#cbd5e1' : '#334155';

      var datasets = postures.map(function (p, idx) {
        var scores = [100, 100, 100, 100];
        if (p.standards) {
          p.standards.forEach(function (std) {
            if (std.standard === 'CIS') scores[0] = std.score;
            if (std.standard === 'PCI-DSS') scores[1] = std.score;
            if (std.standard === 'NIST') scores[2] = std.score;
            if (std.standard === 'ISO-27001') scores[3] = std.score;
          });
        }
        return {
          label: p.label || 'Posture (%)',
          data: scores,
          borderColor: borderColors[idx] || '#4f46e5',
          backgroundColor: bgColors[idx] || 'rgba(79, 70, 229, 0.25)',
          pointBackgroundColor: borderColors[idx] || '#4f46e5',
          pointBorderColor: '#fff',
          pointHoverBackgroundColor: '#fff',
          pointHoverBorderColor: borderColors[idx] || '#4f46e5',
          borderWidth: 2
        };
      });

      new window.Chart(canvas.getContext('2d'), {
        type: 'radar',
        data: { labels: labels, datasets: datasets },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          scales: {
            r: {
              angleLines: { color: gridColor },
              grid: { color: gridColor },
              pointLabels: { color: pointLabelColor, font: { size: 10, weight: '600' } },
              suggestedMin: 0,
              suggestedMax: 100,
              ticks: { stepSize: 25, backdropColor: 'transparent', color: pointLabelColor }
            }
          },
          plugins: {
            legend: { position: 'bottom', labels: { color: pointLabelColor, boxWidth: 10, font: { size: 11 } } }
          }
        }
      });
    }
  }

  /* ------------------------------------------------------------------ */
  /* Credential Blast Radius & Attack Graph                             */
  /* ------------------------------------------------------------------ */

  function initBlastRadiusGraph() {
    var btnScatter = document.getElementById('btn-estate-scatter');
    var btnBlast = document.getElementById('btn-estate-blast');
    var scatterWrap = document.getElementById('estate-scatter-wrap');
    var blastWrap = document.getElementById('estate-blast-wrap');
    var blastSvg = document.getElementById('blast-graph');
    var tooltip = document.getElementById('blast-tooltip');
    if (!btnScatter || !btnBlast || !scatterWrap || !blastWrap || !blastSvg) return;

    btnScatter.addEventListener('click', function () {
      btnScatter.classList.add('is-active');
      btnBlast.classList.remove('is-active');
      scatterWrap.classList.remove('hidden');
      blastWrap.classList.add('hidden');
    });

    btnBlast.addEventListener('click', function () {
      btnBlast.classList.add('is-active');
      btnScatter.classList.remove('is-active');
      blastWrap.classList.remove('hidden');
      scatterWrap.classList.add('hidden');
      loadBlastRadius();
    });

    var blastLoaded = false;
    function loadBlastRadius() {
      if (blastLoaded) return;
      var params = new URLSearchParams(window.location.search);
      var url = '/api/v1/estate/blast-radius?' + params.toString();
      fetch(url)
        .then(function (r) { return r.json(); })
        .then(function (graph) {
          blastLoaded = true;
          renderBlastTopology(graph);
        })
        .catch(function () {});
    }

    function renderBlastTopology(graph) {
      blastSvg.innerHTML = '';
      if (!graph.nodes || !graph.nodes.length) {
        blastSvg.innerHTML = '<text x="480" y="220" text-anchor="middle" fill="#94a3b8" font-size="14">No open endpoints or blast radius paths found.</text>';
        return;
      }

      var W = 960;
      var H = 440;
      var cx = W / 2;
      var cy = H / 2;

      var credNodes = graph.nodes.filter(function (n) { return n.type === 'credential'; });
      var hostNodes = graph.nodes.filter(function (n) { return n.type === 'host'; });
      var vulnNodes = graph.nodes.filter(function (n) { return n.type === 'vulnerability'; });

      var nodeCoords = {};

      if (credNodes.length > 0) {
        var rCred = Math.min(100, 45 * credNodes.length);
        credNodes.forEach(function (n, i) {
          var angle = (2 * Math.PI * i) / credNodes.length - Math.PI / 2;
          nodeCoords[n.id] = { x: cx + rCred * Math.cos(angle), y: cy + rCred * Math.sin(angle), node: n };
        });
      }

      var rHost = 175;
      hostNodes.forEach(function (n, i) {
        var angle = (2 * Math.PI * i) / (hostNodes.length || 1);
        nodeCoords[n.id] = { x: cx + rHost * Math.cos(angle), y: cy + rHost * Math.sin(angle), node: n };
      });

      var rVuln = 205;
      vulnNodes.forEach(function (n, i) {
        var angle = (2 * Math.PI * i) / (vulnNodes.length || 1) + Math.PI / 4;
        nodeCoords[n.id] = { x: cx + rVuln * Math.cos(angle), y: cy + rVuln * Math.sin(angle), node: n };
      });

      var edgesG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      (graph.edges || []).forEach(function (e) {
        var p1 = nodeCoords[e.source];
        var p2 = nodeCoords[e.target];
        if (!p1 || !p2) return;
        var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', p1.x);
        line.setAttribute('y1', p1.y);
        line.setAttribute('x2', p2.x);
        line.setAttribute('y2', p2.y);
        line.setAttribute('stroke', e.relation === 'compromised_by' ? '#10b981' : (e.relation === 'lateral_pivot' ? '#818cf8' : '#f43f5e'));
        line.setAttribute('stroke-width', e.relation === 'compromised_by' ? '2.5' : '1.5');
        line.setAttribute('stroke-opacity', '0.65');
        if (e.relation === 'lateral_pivot') {
          line.setAttribute('stroke-dasharray', '5,5');
        }
        edgesG.appendChild(line);
      });
      blastSvg.appendChild(edgesG);

      var nodesG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      Object.keys(nodeCoords).forEach(function (id) {
        var item = nodeCoords[id];
        var n = item.node;
        var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'attack-node');
        g.setAttribute('data-node-id', id);

        var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', item.x);
        circle.setAttribute('cy', item.y);
        var radius = n.type === 'credential' ? 18 : (n.type === 'host' ? 14 : 12);
        circle.setAttribute('r', radius);

        var fill = n.type === 'credential' ? '#10b981' : (n.type === 'host' ? '#6366f1' : '#ef4444');
        circle.setAttribute('fill', fill);
        circle.setAttribute('stroke', '#ffffff');
        circle.setAttribute('stroke-width', '2');
        g.appendChild(circle);

        var text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', item.x);
        text.setAttribute('y', item.y + radius + 12);
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', '#e2e8f0');
        text.setAttribute('font-size', '10');
        text.setAttribute('font-weight', '500');
        text.textContent = n.label || id;
        g.appendChild(text);

        g.addEventListener('mouseenter', function (evt) {
          if (!tooltip) return;
          tooltip.innerHTML = '<strong>' + escapeHtml(n.label) + '</strong> (' + escapeHtml(n.type) + ')' +
            (n.domain ? '<br>Domain: ' + escapeHtml(n.domain) : '') +
            (n.address ? '<br>Endpoint: ' + escapeHtml(n.address) + ':' + escapeHtml(n.port) : '') +
            (n.hardening_score ? '<br>Hardening: ' + n.hardening_score + '/100' : '');
          tooltip.style.left = (evt.clientX + 10) + 'px';
          tooltip.style.top = (evt.clientY + 10) + 'px';
          tooltip.classList.remove('hidden');
        });
        g.addEventListener('mouseleave', function () {
          if (tooltip) tooltip.classList.add('hidden');
        });

        g.addEventListener('click', function () {
          Array.prototype.forEach.call(nodesG.querySelectorAll('.attack-node'), function (el) {
            el.classList.remove('is-active');
          });
          g.classList.add('is-active');
        });

        nodesG.appendChild(g);
      });
      blastSvg.appendChild(nodesG);
    }
  }

  /* ------------------------------------------------------------------ */
  /* Live Terminal filters & Audio Chimes                               */
  /* ------------------------------------------------------------------ */

  function initLiveTerminalAndAudio() {
    var audioBtn = document.getElementById('toggle-audio-alerts');
    var iconEl = document.getElementById('audio-alert-icon');
    var labelEl = document.getElementById('audio-alert-label');

    function updateAudioUI() {
      if (!audioBtn) return;
      audioBtn.setAttribute('data-audio-enabled', audioAlertsEnabled ? 'true' : 'false');
      if (iconEl) iconEl.textContent = audioAlertsEnabled ? '🔔' : '🔇';
      if (labelEl) labelEl.textContent = audioAlertsEnabled ? 'Alerts ON' : 'Alerts OFF';
      if (audioAlertsEnabled) {
        audioBtn.classList.add('tone-emerald');
      } else {
        audioBtn.classList.remove('tone-emerald');
      }
    }
    updateAudioUI();

    if (audioBtn) {
      audioBtn.addEventListener('click', function () {
        audioAlertsEnabled = !audioAlertsEnabled;
        try {
          localStorage.setItem('rdpshot_audio_alerts', audioAlertsEnabled ? 'true' : 'false');
        } catch (e) {}
        updateAudioUI();
        if (audioAlertsEnabled) {
          playAudioChime('success');
        }
      });
    }

    var filterBtns = document.querySelectorAll('[data-terminal-filter]');
    var searchInput = document.getElementById('terminal-search');
    var currentFilter = 'all';

    function applyTerminalFilter() {
      var query = searchInput ? searchInput.value.trim().toLowerCase() : '';
      var list = document.getElementById('live-findings');
      if (!list) return;
      var items = list.querySelectorAll('.finding-item');
      Array.prototype.forEach.call(items, function (item) {
        var eventType = item.getAttribute('data-event-type') || 'finding';
        var eventSev = item.getAttribute('data-event-sev') || '';
        var text = item.textContent.toLowerCase();

        var matchesType = (currentFilter === 'all') ||
          (currentFilter === 'critical' && eventSev === 'critical') ||
          (currentFilter === 'credential' && eventType === 'credential') ||
          (currentFilter === 'screenshot' && eventType === 'screenshot');

        var matchesQuery = !query || text.indexOf(query) !== -1;
        item.style.display = matchesType && matchesQuery ? '' : 'none';
      });
    }

    Array.prototype.forEach.call(filterBtns, function (btn) {
      btn.addEventListener('click', function () {
        Array.prototype.forEach.call(filterBtns, function (b) { b.classList.remove('is-active'); });
        btn.classList.add('is-active');
        currentFilter = btn.getAttribute('data-terminal-filter') || 'all';
        applyTerminalFilter();
      });
    });

    if (searchInput) {
      searchInput.addEventListener('input', applyTerminalFilter);
    }
  }

  /* ------------------------------------------------------------------ */
  /* report export buttons: [data-export]                                 */
  /* ------------------------------------------------------------------ */

  function initExports() {
    var buttons = document.querySelectorAll('[data-export]');
    if (!buttons.length) {
      return;
    }

    var errorBox = document.getElementById('export-error');
    var scanSelect = document.querySelector('[data-report-scan]');

    function exportURL(button) {
      var base = button.getAttribute('data-export-base');
      var format = button.getAttribute('data-export-format') || 'bin';
      if (base) {
        var scan = 'all';
        if (scanSelect && scanSelect.value) {
          scan = scanSelect.value;
        }
        return base + '?format=' + encodeURIComponent(format) + '&scan=' + encodeURIComponent(scan);
      }
      return button.getAttribute('data-export-url') || '';
    }

    Array.prototype.forEach.call(buttons, function (button) {
      button.addEventListener('click', function () {
        var url = exportURL(button);
        if (!url || button.disabled) {
          return;
        }

        var format = button.getAttribute('data-export-format') || 'bin';
        var spinner = button.querySelector('[data-export-spinner]');
        var label = button.querySelector('[data-export-label]');
        var originalLabel = label ? label.textContent : '';

        button.disabled = true;
        button.setAttribute('data-loading', 'true');
        if (spinner) {
          spinner.classList.remove('hidden');
        }
        if (label) {
          label.textContent = 'Exporting…';
        }
        if (errorBox) {
          errorBox.classList.add('hidden');
        }

        fetch(url, { method: 'GET' })
          .then(function (resp) {
            if (!resp.ok) {
              throw new Error('export failed with status ' + resp.status);
            }
            return resp.blob().then(function (blob) {
              var disposition = resp.headers.get('Content-Disposition') || '';
              var match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);
              var filename = match ? decodeURIComponent(match[1]) : 'rdpshot-report.' + format;

              var objectUrl = URL.createObjectURL(blob);
              var anchor = document.createElement('a');
              anchor.href = objectUrl;
              anchor.download = filename;
              anchor.style.display = 'none';
              document.body.appendChild(anchor);
              anchor.click();
              document.body.removeChild(anchor);
              window.setTimeout(function () {
                URL.revokeObjectURL(objectUrl);
              }, 1000);
            });
          })
          .catch(function (err) {
            if (errorBox) {
              errorBox.textContent = err.message;
              errorBox.classList.remove('hidden');
            }
          })
          .then(function () {
            button.disabled = false;
            button.removeAttribute('data-loading');
            if (spinner) {
              spinner.classList.add('hidden');
            }
            if (label) {
              label.textContent = originalLabel;
            }
          });
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* risk distribution chart (Chart.js)                                   */
  /* ------------------------------------------------------------------ */

  var riskChart = null;

  function restyleRiskChart() {
    if (!riskChart) {
      return;
    }
    var dataset = riskChart.data.datasets[0];
    dataset.borderColor = themeToken('--surface', '#ffffff');
    riskChart.options.plugins.legend.labels.color = themeToken('--text-muted', '#475569');
    riskChart.update('none');
  }

  function initRiskChart() {
    var canvas = document.getElementById('risk-chart');
    var dataEl = document.getElementById('risk-data');
    if (!canvas || typeof window.Chart === 'undefined') {
      return;
    }

    var rows = [];
    if (dataEl) {
      try {
        rows = JSON.parse(dataEl.textContent || '[]');
      } catch (err) {
        rows = [];
      }
    }
    if (!Array.isArray(rows) || !rows.length) {
      return;
    }

    var labels = [];
    var values = [];
    var colors = [];

    rows.forEach(function (row) {
      labels.push(String(row.severity || 'info'));
      values.push(Number(row.count) || 0);
      colors.push(severityColor(row.severity));
    });

    riskChart = new window.Chart(canvas.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: themeToken('--surface', '#ffffff'),
          borderWidth: 2,
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: themeToken('--text-muted', '#475569'),
              font: { family: 'ui-monospace, Menlo, Consolas, monospace', size: 11 },
              padding: 16
            }
          },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                return ' ' + ctx.label + ': ' + ctx.parsed;
              }
            }
          }
        }
      }
    });

    document.addEventListener(THEME_EVENT, restyleRiskChart);
  }

  /* ------------------------------------------------------------------ */
  /* gallery search fallback: [data-gallery-search]                       */
  /* ------------------------------------------------------------------ */

  /* ------------------------------------------------------------------ */
  /* estate risk map: #estate-graph                                       */
  /* ------------------------------------------------------------------ */

  function initEstateMap() {
    var svg = document.getElementById('estate-graph');
    if (!svg) {
      return;
    }

    var params = new URLSearchParams(window.location.search);
    var engagement = params.get('engagement') || '';
    var scanSelect = document.querySelector('[data-estate-scan]');
    var statusEl = document.querySelector('[data-estate-status]');
    var countEl = document.querySelector('[data-estate-count]');
    var sevLegendEl = document.querySelector('[data-estate-sev-legend]');
    var tbody = document.querySelector('[data-estate-tbody]');
    var filterInput = document.querySelector('[data-estate-filter]');
    var filterSev = document.querySelector('[data-estate-filter-sev]');
    var tooltip = document.querySelector('[data-estate-tooltip]');
    var wrap = document.querySelector('.estate-map-wrap');
    var nodesCache = [];
    var selectedId = '';

    var PAD = { l: 56, r: 24, t: 28, b: 44 };
    var W = 960;
    var H = 420;
    var PLOT_W = W - PAD.l - PAD.r;
    var PLOT_H = H - PAD.t - PAD.b;

    function severityColor(sev) {
      switch ((sev || '').toLowerCase()) {
        case 'critical': return '#e11d48';
        case 'high': return '#f97316';
        case 'medium': return '#ca8a04';
        case 'low': return '#0284c7';
        default: return '#64748b';
      }
    }

    function severityBadge(sev) {
      var s = (sev || '').toLowerCase();
      if (s === 'critical') return 'badge badge-rose';
      if (s === 'high') return 'badge badge-orange';
      if (s === 'medium') return 'badge badge-amber';
      if (s === 'low') return 'badge badge-sky';
      return 'badge badge-slate';
    }

    function svgEl(name, attrs) {
      var el = document.createElementNS('http://www.w3.org/2000/svg', name);
      Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
      return el;
    }

    function jitter(seed, span) {
      var x = Math.sin(seed * 12.9898) * 43758.5453;
      return (x - Math.floor(x) - 0.5) * span;
    }

    function plotXY(n, i) {
      var harden = typeof n.hardening_score === 'number' ? n.hardening_score : 50;
      var risk = n.risk_score || 0;
      var maxRisk = 1;
      nodesCache.forEach(function (o) {
        if ((o.risk_score || 0) > maxRisk) maxRisk = o.risk_score;
      });
      var x = PAD.l + (Math.max(0, Math.min(100, harden)) / 100) * PLOT_W;
      var y = PAD.t + (1 - Math.max(0, Math.min(1, risk / maxRisk))) * PLOT_H;
      x += jitter(i + 1, 10);
      y += jitter(i + 17, 8);
      x = Math.max(PAD.l + 8, Math.min(W - PAD.r - 8, x));
      y = Math.max(PAD.t + 8, Math.min(H - PAD.b - 8, y));
      return { x: x, y: y };
    }

    function bubbleRadius(n) {
      if (!n.open) return 5;
      var f = n.findings || 0;
      return 7 + Math.min(18, f * 2 + (n.risk_score || 0) * 0.6);
    }

    function escapeHtml(s) {
      return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function cssEscape(value) {
      if (window.CSS && typeof window.CSS.escape === 'function') {
        return window.CSS.escape(value);
      }
      return String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
    }

    function showTooltip(n, clientX, clientY) {
      if (!tooltip || !wrap) return;
      tooltip.classList.remove('hidden');
      tooltip.innerHTML =
        '<strong>' + escapeHtml(n.id) + '</strong>' +
        '<span>' + (n.open ? 'open' : 'closed') +
        (n.max_severity ? ' · ' + escapeHtml(n.max_severity) : '') + '</span>' +
        '<span>Risk ' + (n.risk_score || 0) + ' · Harden ' + (n.hardening_score || 0) +
        ' (' + escapeHtml(n.grade || '-') + ')</span>' +
        '<span>Findings ' + (n.findings || 0) +
        (n.tls_version ? ' · ' + escapeHtml(n.tls_version) : '') +
        (n.nla_required ? ' · NLA' : '') + '</span>';
      var rect = wrap.getBoundingClientRect();
      var left = clientX - rect.left + 12;
      var top = clientY - rect.top + 12;
      if (left + 220 > rect.width) left = clientX - rect.left - 230;
      if (top + 100 > rect.height) top = clientY - rect.top - 110;
      tooltip.style.left = Math.max(8, left) + 'px';
      tooltip.style.top = Math.max(8, top) + 'px';
    }

    function hideTooltip() {
      if (tooltip) tooltip.classList.add('hidden');
    }

    function renderAxes() {
      svg.appendChild(svgEl('rect', {
        x: PAD.l, y: PAD.t, width: PLOT_W, height: PLOT_H,
        class: 'estate-plot-bg', rx: '8'
      }));
      for (var g = 0; g <= 4; g++) {
        var gx = PAD.l + (g / 4) * PLOT_W;
        var gy = PAD.t + (g / 4) * PLOT_H;
        svg.appendChild(svgEl('line', {
          x1: gx, y1: PAD.t, x2: gx, y2: PAD.t + PLOT_H, class: 'estate-grid'
        }));
        svg.appendChild(svgEl('line', {
          x1: PAD.l, y1: gy, x2: PAD.l + PLOT_W, y2: gy, class: 'estate-grid'
        }));
      }
      var xLabel = svgEl('text', {
        x: PAD.l + PLOT_W / 2, y: H - 10, 'text-anchor': 'middle', class: 'estate-axis-label'
      });
      xLabel.textContent = 'Hardening score →';
      svg.appendChild(xLabel);
      var yLabel = svgEl('text', {
        x: 16, y: PAD.t + PLOT_H / 2, 'text-anchor': 'middle', class: 'estate-axis-label',
        transform: 'rotate(-90 16 ' + (PAD.t + PLOT_H / 2) + ')'
      });
      yLabel.textContent = '← Higher risk';
      svg.appendChild(yLabel);
    }

    function renderMap(nodes) {
      nodes = (nodes || []).filter(function (n) { return n.open; });
      while (svg.firstChild) svg.removeChild(svg.firstChild);
      renderAxes();
      var ordered = nodes.slice().sort(function (a, b) {
        return (a.risk_score || 0) - (b.risk_score || 0);
      });
      ordered.forEach(function (n, idx) {
        var i = nodes.indexOf(n);
        var pt = plotXY(n, i >= 0 ? i : idx);
        var r = bubbleRadius(n);
        var g = svgEl('g', {
          class: 'estate-node' + (n.id === selectedId ? ' is-selected' : ''),
          'data-node-id': n.id,
          style: 'cursor:pointer'
        });
        var circle = svgEl('circle', {
          cx: pt.x, cy: pt.y, r: r,
          fill: n.open ? severityColor(n.max_severity || 'info') : '#94a3b8',
          opacity: n.open ? '0.88' : '0.45',
          stroke: n.id === selectedId ? 'var(--text)' : 'transparent',
          'stroke-width': n.id === selectedId ? '2.5' : '0'
        });
        g.appendChild(circle);
        g.addEventListener('mouseenter', function (ev) { showTooltip(n, ev.clientX, ev.clientY); });
        g.addEventListener('mousemove', function (ev) { showTooltip(n, ev.clientX, ev.clientY); });
        g.addEventListener('mouseleave', hideTooltip);
        g.addEventListener('click', function () {
          selectedId = n.id;
          renderMap(nodesCache);
          renderTable();
          var row = tbody.querySelector('[data-row-id="' + cssEscape(n.id) + '"]');
          if (row) {
            row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
          }
        });
        svg.appendChild(g);
      });
    }

    function nodeMatchesFilters(n) {
      var q = (filterInput && filterInput.value || '').trim().toLowerCase();
      if (q && String(n.id).toLowerCase().indexOf(q) < 0 &&
          String(n.address).toLowerCase().indexOf(q) < 0) {
        return false;
      }
      var sev = (filterSev && filterSev.value || '').toLowerCase();
      if (!sev) return true;
      if (sev === 'none') return !n.max_severity;
      return (n.max_severity || '').toLowerCase() === sev;
    }

    function renderTable() {
      if (!tbody) return;
      // API already omits closed RDP endpoints; keep a client guard as well.
      var rows = nodesCache.filter(function (n) { return n.open; }).filter(nodeMatchesFilters).sort(function (a, b) {
        return (b.risk_score || 0) - (a.risk_score || 0);
      });
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No open RDP hosts match this filter.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (n) {
        var sev = n.max_severity || '—';
        var cls = n.id === selectedId ? ' is-selected' : '';
        var nlaParam = n.nla_required ? '' : '&nla=0';
        return '<tr class="estate-row' + cls + '" data-row-id="' + escapeHtml(n.id) + '">' +
          '<td class="cell-mono"><button type="button" class="estate-host-btn" data-select="' +
            escapeHtml(n.id) + '">' + escapeHtml(n.id) + '</button></td>' +
          '<td><span class="badge badge-emerald">open</span></td>' +
          '<td><span class="' + severityBadge(n.max_severity) + '">' + escapeHtml(sev) + '</span></td>' +
          '<td class="cell-mono">' + (n.findings || 0) + '</td>' +
          '<td class="cell-mono">' + (n.risk_score || 0) + '</td>' +
          '<td class="cell-mono">' + (n.hardening_score || 0) + ' <span class="text-subtle">(' +
            escapeHtml(n.grade || '-') + ')</span></td>' +
          '<td class="cell-mono text-sm">' +
            (n.nla_required ? 'NLA' : 'no NLA') +
            (n.tls_version ? ' · ' + escapeHtml(n.tls_version) : '') +
          '</td>' +
          '<td class="whitespace-nowrap"><div class="flex items-center gap-1">' +
            '<a href="/api/v1/hosts/connect.rdp?address=' + encodeURIComponent(n.address || '') + '&port=' + encodeURIComponent(n.port || 3389) + nlaParam + '" class="btn btn-ghost btn-xs text-xs py-0.5 px-1.5" title="Download .rdp file">.rdp</a>' +
            '<a href="rdp://' + encodeURIComponent(n.address || '') + ':' + encodeURIComponent(n.port || 3389) + '" class="btn btn-ghost btn-xs text-xs py-0.5 px-1.5" title="Launch default RDP client">RDP</a>' +
          '</div></td>' +
          '</tr>';
      }).join('');
    }

    function renderSevLegend(nodes) {
      if (!sevLegendEl) return;
      var counts = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
      nodes.forEach(function (n) {
        if (!n.open) return;
        var s = (n.max_severity || '').toLowerCase();
        if (counts[s] != null) counts[s]++;
        else counts.none++;
      });
      sevLegendEl.innerHTML = ['critical', 'high', 'medium', 'low', 'none'].map(function (k) {
        var label = k === 'none' ? 'open · no findings' : k;
        return '<li><span class="estate-swatch" style="background:' +
          (k === 'none' ? '#94a3b8' : severityColor(k)) +
          '"></span>' + label + ' <strong>' + counts[k] + '</strong></li>';
      }).join('');
    }

    function render(graph) {
      nodesCache = (graph.nodes || []).filter(function (n) { return n.open; });
      if (countEl) countEl.textContent = nodesCache.length + ' nodes';
      if (!nodesCache.length) {
        if (statusEl) statusEl.textContent = 'No open RDP hosts in this estate yet.';
        while (svg.firstChild) svg.removeChild(svg.firstChild);
        if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No open RDP hosts in this estate yet.</td></tr>';
        if (sevLegendEl) sevLegendEl.innerHTML = '';
        return;
      }
      if (statusEl) {
        statusEl.textContent = (graph.engagement ? 'Engagement: ' + graph.engagement + ' · ' : '') +
          nodesCache.length + ' open RDP hosts · hover bubbles for details · click to select';
      }
      renderSevLegend(nodesCache);
      renderMap(nodesCache);
      renderTable();
    }

    function load() {
      var q = new URLSearchParams();
      if (engagement) q.set('engagement', engagement);
      var scanId = scanSelect && scanSelect.value;
      if (scanId) q.set('scan_id', scanId);
      if (statusEl) statusEl.textContent = 'Loading estate graph…';
      fetch('/api/v1/estate?' + q.toString())
        .then(function (r) {
          if (!r.ok) {
            throw new Error('HTTP ' + r.status);
          }
          return r.json();
        })
        .then(render)
        .catch(function (err) {
          if (statusEl) statusEl.textContent = 'Failed to load estate: ' + err;
          if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="table-empty">Failed to load estate data.</td></tr>';
        });
    }

    if (scanSelect) {
      var preselect = params.get('scan_id') || '';
      if (preselect) scanSelect.value = preselect;
      scanSelect.addEventListener('change', load);
    }
    if (filterInput) filterInput.addEventListener('input', renderTable);
    if (filterSev) filterSev.addEventListener('change', renderTable);
    if (tbody) {
      tbody.addEventListener('click', function (ev) {
        var btn = ev.target.closest('[data-select]');
        if (!btn) return;
        selectedId = btn.getAttribute('data-select');
        renderMap(nodesCache);
        renderTable();
      });
    }
    load();
  }

  function initScansDashboard() {
    var rows = document.querySelectorAll('[data-scan-row]');
    var statusSelect = document.querySelector('[data-scans-status]');
    var searchInput = document.querySelector('[data-scans-search]');
    var countEl = document.querySelector('[data-scans-count]');
    var emptyFilter = document.querySelector('[data-scans-empty-filter]');
    if (!rows.length || (!statusSelect && !searchInput)) {
      return;
    }

    function applyFilter() {
      var status = statusSelect ? statusSelect.value : '';
      var query = searchInput ? searchInput.value.trim().toLowerCase() : '';
      var visible = 0;
      Array.prototype.forEach.call(rows, function (row) {
        var rowStatus = row.getAttribute('data-status') || '';
        var haystack = (row.getAttribute('data-search') || '').toLowerCase();
        var matchStatus = !status || rowStatus === status;
        var matchQuery = !query || haystack.indexOf(query) !== -1;
        var show = matchStatus && matchQuery;
        row.style.display = show ? '' : 'none';
        if (show) {
          visible += 1;
        }
      });
      if (countEl) {
        var total = rows.length;
        if (status || query) {
          countEl.textContent = visible + ' of ' + total + ' scans match';
        } else {
          countEl.textContent = total + ' scan' + (total === 1 ? '' : 's') + ' shown';
        }
      }
      if (emptyFilter) {
        emptyFilter.classList.toggle('hidden', visible > 0 || rows.length === 0);
      }
    }

    if (statusSelect) {
      statusSelect.addEventListener('change', applyFilter);
    }
    if (searchInput) {
      searchInput.addEventListener('input', applyFilter);
    }
  }

  function initGallery() {
    var items = document.querySelectorAll('[data-gallery-item]');
    var input = document.querySelector('[data-gallery-search]');
    var scanSelect = document.querySelector('[data-gallery-scan]');
    var counter = document.getElementById('gallery-count');
    var noMatch = document.getElementById('gallery-no-match');
    var lightbox = document.getElementById('gallery-lightbox');
    var lightboxImage = document.getElementById('gallery-lightbox-image');

    if (scanSelect) {
      scanSelect.addEventListener('change', function () {
        var form = scanSelect.form || document.getElementById('gallery-scan-filter');
        if (form) {
          form.submit();
        }
      });
    }

    function applyFilter() {
      if (!input) {
        return;
      }
      var query = input.value.trim().toLowerCase();
      var visible = 0;

      Array.prototype.forEach.call(items, function (item) {
        var haystack = (
          (item.getAttribute('data-address') || '') + ' ' +
          (item.getAttribute('data-username') || '') + ' ' +
          (item.getAttribute('data-scan-name') || '')
        ).toLowerCase();
        var match = !query || haystack.indexOf(query) !== -1;
        item.style.display = match ? '' : 'none';
        if (match) {
          visible += 1;
        }
      });

      if (counter) {
        counter.textContent = query ?
          visible + ' of ' + items.length + ' items match' :
          items.length + ' items captured';
      }
      if (noMatch) {
        noMatch.classList.toggle('hidden', visible > 0 || items.length === 0);
      }
    }

    if (input) {
      input.addEventListener('input', applyFilter);
      input.addEventListener('search', applyFilter);
    }

    var currentShotID = '';
    var activeInspectData = null;
    var overlay = document.getElementById('lightbox-bbox-overlay');
    var details = document.getElementById('inspector-details');
    var keywordsEl = document.getElementById('inspector-keywords');
    var usersEl = document.getElementById('inspector-users');
    var tagsEl = document.getElementById('inspector-tags');
    var toggleBtn = document.getElementById('toggle-ocr-boxes');

    function closeLightbox() {
      if (!lightbox || !lightboxImage) {
        return;
      }
      lightbox.hidden = true;
      lightboxImage.removeAttribute('src');
      document.body.style.overflow = '';
      if (overlay) {
        overlay.classList.add('hidden');
        overlay.innerHTML = '';
      }
      if (details) details.classList.add('hidden');
      if (tagsEl) tagsEl.innerHTML = '';
      activeInspectData = null;
      currentShotID = '';
    }

    function openLightbox(src, alt, shotID) {
      if (!lightbox || !lightboxImage || !src) {
        return;
      }
      currentShotID = shotID || '';
      activeInspectData = null;
      if (overlay) {
        overlay.classList.add('hidden');
        overlay.innerHTML = '';
      }
      if (details) details.classList.add('hidden');
      if (tagsEl) tagsEl.innerHTML = '';

      lightboxImage.src = src;
      lightboxImage.alt = alt || 'Fullscreen evidence image';
      lightbox.hidden = false;
      document.body.style.overflow = 'hidden';
    }

    if (toggleBtn && overlay) {
      toggleBtn.addEventListener('click', function () {
        if (!currentShotID) {
          portalNotify('No screenshot record attached', 'error');
          return;
        }
        var isHidden = overlay.classList.contains('hidden');
        if (!isHidden) {
          overlay.classList.add('hidden');
          if (details) details.classList.add('hidden');
          return;
        }
        if (activeInspectData) {
          renderBBoxes(activeInspectData);
          return;
        }
        fetch('/api/v1/screenshots/' + encodeURIComponent(currentShotID) + '/inspect')
          .then(function (r) {
            if (!r.ok) throw new Error('Inspection unavailable');
            return r.json();
          })
          .then(function (data) {
            activeInspectData = data;
            renderBBoxes(data);
          })
          .catch(function (err) {
            portalNotify(err.message, 'error');
          });
      });
    }

    function renderBBoxes(data) {
      if (!overlay) return;
      overlay.innerHTML = '';
      overlay.classList.remove('hidden');
      if (details) details.classList.remove('hidden');

      if (keywordsEl) {
        keywordsEl.textContent = (data.keywords && data.keywords.length) ? data.keywords.join(', ') : 'None';
      }
      if (usersEl) {
        usersEl.textContent = (data.detected_users && data.detected_users.length) ? data.detected_users.join(', ') : 'None detected';
      }
      if (tagsEl && data.sensitive_tags) {
        tagsEl.innerHTML = data.sensitive_tags.map(function (t) {
          return '<span class="badge badge-rose text-[10px]">' + escapeHtml(t) + '</span>';
        }).join('');
      }

      (data.bounding_boxes || []).forEach(function (box) {
        var b = document.createElement('div');
        b.className = 'absolute border-2 border-amber-400 bg-amber-400/20 rounded pointer-events-none transition-all';
        b.style.left = (box.x * 100) + '%';
        b.style.top = (box.y * 100) + '%';
        b.style.width = (box.w * 100) + '%';
        b.style.height = (box.h * 100) + '%';

        var label = document.createElement('span');
        label.className = 'absolute top-0 left-0 -translate-y-full bg-amber-500 text-black font-semibold text-[10px] px-1 rounded shadow';
        label.textContent = box.label;
        b.appendChild(label);
        overlay.appendChild(b);
      });
    }

    if (lightbox && lightboxImage) {
      Array.prototype.forEach.call(document.querySelectorAll('[data-lightbox-open]'), function (btn) {
        btn.addEventListener('click', function (ev) {
          ev.preventDefault();
          ev.stopPropagation();
          openLightbox(btn.getAttribute('data-full-src'), btn.getAttribute('data-alt'), btn.getAttribute('data-screenshot-id'));
        });
      });

      Array.prototype.forEach.call(document.querySelectorAll('[data-gallery-image]'), function (img) {
        img.addEventListener('click', function () {
          var btn = img.closest('[data-gallery-item]');
          var opener = btn ? btn.querySelector('[data-lightbox-open]') : null;
          var src = opener ? opener.getAttribute('data-full-src') : img.getAttribute('src');
          var alt = opener ? opener.getAttribute('data-alt') : img.getAttribute('alt');
          var shotID = opener ? opener.getAttribute('data-screenshot-id') : '';
          openLightbox(src, alt, shotID);
        });
        img.style.cursor = 'zoom-in';
      });

      Array.prototype.forEach.call(document.querySelectorAll('[data-lightbox-close]'), function (el) {
        el.addEventListener('click', function (ev) {
          ev.preventDefault();
          closeLightbox();
        });
      });

      document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape' && lightbox && !lightbox.hidden) {
          closeLightbox();
        }
      });
    }
  }

  /* ------------------------------------------------------------------ */
  /* elapsed time ticker: [data-elapsed-start] / [data-elapsed-end]        */
  /* ------------------------------------------------------------------ */

  function initElapsedTicker() {
    var ticker = document.getElementById('elapsed-ticker');
    if (!ticker) {
      return;
    }

    var start = parseTime(ticker.getAttribute('data-elapsed-start'));
    if (start === null) {
      return;
    }
    var end = parseTime(ticker.getAttribute('data-elapsed-end'));
    if (end !== null) {
      ticker.textContent = 'elapsed ' + formatElapsed((end - start) / 1000);
      return;
    }

    function tick() {
      ticker.textContent = 'elapsed ' + formatElapsed((Date.now() - start) / 1000);
    }

    tick();
    window.setInterval(tick, 1000);
  }

  /* ------------------------------------------------------------------ */
  /* boot                                                                */
  /* ------------------------------------------------------------------ */

  function syncWordlistPicker(picker) {
    Array.prototype.forEach.call(['user', 'password'], function (kind) {
      var source = picker.querySelector('[data-wordlist-source="' + kind + '"][data-source="default"]');
      var upload = picker.querySelector('[data-wordlist-source="' + kind + '"][data-source="upload"]');
      var box = picker.querySelector('[data-wordlist-default="' + kind + '"]');
      var file = picker.querySelector('[data-wordlist-file="' + kind + '"]');
      var useDefault = source && source.checked;
      if (box) {
        box.classList.toggle('is-disabled', !useDefault);
        var path = box.querySelector('[data-wordlist-path="' + kind + '"]');
        if (path) {
          path.disabled = !useDefault;
        }
      }
      if (file && useDefault) {
        /* keep the chosen file visible but ignored on submit when default is selected */
      }
      if (upload && file && file.files && file.files.length > 0 && !useDefault) {
        upload.checked = true;
      }
    });
  }

  function prepareWordlistFormData(form) {
    var picker = form.querySelector('[data-wordlist-picker]');
    if (!picker) {
      return new FormData(form);
    }
    Array.prototype.forEach.call(['user', 'password'], function (kind) {
      var defaultRadio = picker.querySelector('[data-wordlist-source="' + kind + '"][data-source="default"]');
      var file = picker.querySelector('[data-wordlist-file="' + kind + '"]');
      var path = picker.querySelector('[data-wordlist-path="' + kind + '"]');
      if (defaultRadio && defaultRadio.checked) {
        if (file) {
          file.value = '';
        }
        if (path) {
          path.disabled = false;
        }
      } else if (path) {
        path.disabled = true;
      }
    });
    return new FormData(form);
  }

  function normalizeTargetsFileText(raw) {
    var lines = String(raw || '').replace(/^\uFEFF/, '').split(/\r\n|\n|\r/);
    var kept = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.charAt(0) === '#') {
        continue;
      }
      kept.push(line);
    }
    return kept;
  }

  function initTargetsFilePickers() {
    var fields = document.querySelectorAll('[data-targets-field]');
    Array.prototype.forEach.call(fields, function (field) {
      var input = field.querySelector('[data-targets-input]');
      var fileInput = field.querySelector('[data-targets-file]');
      var status = field.querySelector('[data-targets-file-status]');
      if (!input || !fileInput) {
        return;
      }

      fileInput.addEventListener('change', function () {
        var file = fileInput.files && fileInput.files[0];
        if (!file) {
          return;
        }
        if (file.size > 2 * 1024 * 1024) {
          if (status) {
            status.textContent = 'Target file exceeds the 2 MiB limit.';
            status.classList.remove('hidden', 'is-ok');
            status.classList.add('is-error');
          }
          fileInput.value = '';
          return;
        }

        var reader = new FileReader();
        reader.onload = function () {
          var lines = normalizeTargetsFileText(reader.result);
          if (!lines.length) {
            if (status) {
              status.textContent = 'No usable targets found in ' + file.name + '.';
              status.classList.remove('hidden', 'is-ok');
              status.classList.add('is-error');
            }
            return;
          }

          var existing = input.value.trim();
          var applyTargets = function () {
            input.value = lines.join('\n');
            input.dispatchEvent(new Event('input', { bubbles: true }));
            // Textarea is now the source of truth; drop the file so submit does
            // not upload the same list twice.
            fileInput.value = '';
            if (status) {
              status.textContent = 'Loaded ' + lines.length + ' target' + (lines.length === 1 ? '' : 's') + ' from ' + file.name + '.';
              status.classList.remove('hidden', 'is-error');
              status.classList.add('is-ok');
            }
          };

          if (!existing) {
            applyTargets();
            return;
          }

          portalConfirm({
            title: 'Replace targets',
            message: 'Replace the current targets with the contents of ' + file.name + '?',
            confirmLabel: 'Replace',
            cancelLabel: 'Keep current',
            danger: false,
            eyebrow: 'Targets'
          }).then(function (ok) {
            if (!ok) {
              fileInput.value = '';
              return;
            }
            applyTargets();
          });
        };
        reader.onerror = function () {
          if (status) {
            status.textContent = 'Unable to read ' + file.name + '.';
            status.classList.remove('hidden', 'is-ok');
            status.classList.add('is-error');
          }
        };
        reader.readAsText(file);
      });
    });
  }

  function syncLockoutProtect(root) {
    var protect = root.querySelector('[data-lockout-protect]');
    var limit = root.querySelector('[data-max-auth-failures]');
    var wrap = root.querySelector('[data-lockout-limit-wrap]');
    if (!protect || !limit) {
      return;
    }
    var on = protect.checked;
    if (wrap) {
      wrap.hidden = !on;
      wrap.classList.toggle('hidden', !on);
    }
    limit.disabled = !on;
    if (!on) {
      if (!limit.dataset.prevLimit) {
        limit.dataset.prevLimit = limit.value && limit.value !== '0' ? limit.value : '5';
      }
      limit.value = '0';
      limit.min = '0';
    } else {
      limit.min = '1';
      if (limit.value === '0') {
        limit.value = limit.dataset.prevLimit || '5';
      }
    }
  }

  function syncAuthAdvanced(root) {
    if (!root) {
      return;
    }
    var form = root.closest('form') || document;
    var enableAuth = form.querySelector('[data-enable-auth]');
    var authEnabled = !enableAuth || enableAuth.checked;
    root.classList.toggle('is-disabled', !authEnabled);
    var modeInput = root.querySelector('[data-auth-mode]:checked');
    var mode = modeInput ? modeInput.value : 'wordlist';
    if (!authEnabled) {
      mode = 'wordlist';
    }
    Array.prototype.forEach.call(root.querySelectorAll('[data-auth-mode]'), function (radio) {
      radio.disabled = !authEnabled;
    });
    Array.prototype.forEach.call(root.querySelectorAll('[data-auth-domain]'), function (field) {
      field.disabled = !authEnabled;
    });
    Array.prototype.forEach.call(root.querySelectorAll('[data-lockout-protect]'), function (box) {
      box.disabled = !authEnabled;
    });
    Array.prototype.forEach.call(root.querySelectorAll('[data-auth-panel]'), function (panel) {
      var key = panel.getAttribute('data-auth-panel');
      var show = false;
      if (key === 'wordlist') {
        show = mode === 'wordlist';
      } else if (key === 'cred') {
        show = mode === 'single' || mode === 'pth' || mode === 'kerberos';
      } else if (key === 'single') {
        show = mode === 'single';
      } else if (key === 'pth') {
        show = mode === 'pth';
      } else if (key === 'kerberos') {
        show = mode === 'kerberos';
      }
      panel.hidden = !show;
      panel.classList.toggle('hidden', !show);
    });
    Array.prototype.forEach.call(root.querySelectorAll('[data-auth-cred-field]'), function (field) {
      var panel = field.closest('[data-auth-panel]');
      var panelKey = panel ? panel.getAttribute('data-auth-panel') : '';
      var active = authEnabled && (
        (panelKey === 'cred' && (mode === 'single' || mode === 'pth' || mode === 'kerberos')) ||
        (panelKey === 'single' && mode === 'single') ||
        (panelKey === 'pth' && mode === 'pth') ||
        (panelKey === 'kerberos' && mode === 'kerberos')
      );
      field.disabled = !active;
    });
    syncLockoutProtect(root);
    if (!authEnabled) {
      var limit = root.querySelector('[data-max-auth-failures]');
      if (limit) {
        limit.disabled = true;
      }
    }
  }

  function initAuthAdvanced() {
    var blocks = document.querySelectorAll('[data-auth-advanced]');
    Array.prototype.forEach.call(blocks, function (root) {
      syncAuthAdvanced(root);
      Array.prototype.forEach.call(root.querySelectorAll('[data-auth-mode]'), function (radio) {
        radio.addEventListener('change', function () {
          if (radio.value === 'single' || radio.value === 'pth' || radio.value === 'kerberos') {
            var form = root.closest('form');
            var enableAuth = form && form.querySelector('[data-enable-auth]');
            if (enableAuth && !enableAuth.checked) {
              enableAuth.checked = true;
            }
          }
          syncAuthAdvanced(root);
        });
      });
      var form = root.closest('form');
      var enableAuth = form && form.querySelector('[data-enable-auth]');
      if (enableAuth) {
        enableAuth.addEventListener('change', function () {
          syncAuthAdvanced(root);
        });
      }
      var protect = root.querySelector('[data-lockout-protect]');
      if (protect) {
        protect.addEventListener('change', function () {
          syncLockoutProtect(root);
        });
      }
      if (form) {
        form.addEventListener('submit', function () {
          var box = root.querySelector('[data-lockout-protect]');
          var limit = root.querySelector('[data-max-auth-failures]');
          if (box && limit && !box.checked) {
            limit.disabled = false;
            limit.value = '0';
          }
        });
      }
    });
  }

  function initWordlistPickers() {
    var pickers = document.querySelectorAll('[data-wordlist-picker]');
    Array.prototype.forEach.call(pickers, function (picker) {
      syncWordlistPicker(picker);

      Array.prototype.forEach.call(picker.querySelectorAll('[data-wordlist-source]'), function (radio) {
        radio.addEventListener('change', function () {
          syncWordlistPicker(picker);
        });
      });

      Array.prototype.forEach.call(picker.querySelectorAll('[data-wordlist-file]'), function (file) {
        file.addEventListener('change', function () {
          if (!file.files || !file.files.length) {
            return;
          }
          var kind = file.getAttribute('data-wordlist-file');
          var upload = picker.querySelector('[data-wordlist-source="' + kind + '"][data-source="upload"]');
          if (upload) {
            upload.checked = true;
            syncWordlistPicker(picker);
          }
        });
      });

      var saveBtn = picker.querySelector('[data-wordlist-save-defaults]');
      var status = picker.querySelector('[data-wordlist-save-status]');
      if (saveBtn) {
        saveBtn.addEventListener('click', function () {
          var userPath = picker.querySelector('[data-wordlist-path="user"]');
          var passwordPath = picker.querySelector('[data-wordlist-path="password"]');
          if (!userPath || !passwordPath) {
            return;
          }
          saveBtn.disabled = true;
          if (status) {
            status.textContent = 'Saving…';
            status.classList.remove('hidden', 'is-error', 'is-ok');
          }
          fetch('/api/v1/settings/wordlists', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              user_wordlist: userPath.value.trim(),
              password_wordlist: passwordPath.value.trim()
            })
          })
            .then(parseJSONResponse)
            .then(function (result) {
              if (!result.ok) {
                var message = (result.body && (result.body.error || result.body.message)) || result.text;
                throw new Error(message || ('save failed (' + result.status + ')'));
              }
              if (result.body) {
                if (result.body.user_wordlist) {
                  userPath.value = result.body.user_wordlist;
                }
                if (result.body.password_wordlist) {
                  passwordPath.value = result.body.password_wordlist;
                }
              }
              if (status) {
                status.textContent = 'Server defaults updated';
                status.classList.add('is-ok');
                status.classList.remove('hidden');
              }
            })
            .catch(function (err) {
              if (status) {
                status.textContent = err.message;
                status.classList.add('is-error');
                status.classList.remove('hidden');
              }
            })
            .then(function () {
              saveBtn.disabled = false;
            });
        });
      }
    });
  }

  function pad2(n) {
    return n < 10 ? '0' + n : String(n);
  }

  function toDatetimeLocalValue(date) {
    return date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) +
      'T' + pad2(date.getHours()) + ':' + pad2(date.getMinutes());
  }

  function initScheduleForm() {
    var form = document.getElementById('schedule-form');
    if (!form) {
      return;
    }
    var errorBox = document.getElementById('schedule-form-error');
    var runAtLocal = form.querySelector('[data-schedule-run-at]');
    var runAtUTC = form.querySelector('[data-schedule-run-at-utc]');
    var runNow = form.querySelector('[data-schedule-run-now]');

    if (runAtLocal && !runAtLocal.value) {
      var soon = new Date();
      soon.setMinutes(0, 0, 0);
      soon.setHours(soon.getHours() + 1);
      runAtLocal.value = toDatetimeLocalValue(soon);
      runAtLocal.min = toDatetimeLocalValue(new Date());
    }

    function syncRunAtUTC() {
      if (!runAtUTC) {
        return true;
      }
      if (runNow && runNow.checked) {
        runAtUTC.value = '';
        if (runAtLocal) {
          runAtLocal.required = false;
        }
        return true;
      }
      if (runAtLocal) {
        runAtLocal.required = true;
      }
      if (!runAtLocal || !runAtLocal.value) {
        runAtUTC.value = '';
        return false;
      }
      var parsed = new Date(runAtLocal.value);
      if (isNaN(parsed.getTime())) {
        runAtUTC.value = '';
        return false;
      }
      runAtUTC.value = parsed.toISOString();
      return true;
    }

    if (runAtLocal) {
      runAtLocal.addEventListener('change', syncRunAtUTC);
      runAtLocal.addEventListener('input', syncRunAtUTC);
    }
    if (runNow) {
      runNow.addEventListener('change', function () {
        if (runAtLocal) {
          runAtLocal.disabled = !!runNow.checked;
        }
        syncRunAtUTC();
      });
    }
    syncRunAtUTC();

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var targets = form.querySelector('[data-targets-input]');
      var targetsFile = form.querySelector('[data-targets-file]');
      var hasTargetsText = targets && targets.value.trim() !== '';
      var hasTargetsFile = targetsFile && targetsFile.files && targetsFile.files.length > 0;
      if (!hasTargetsText && !hasTargetsFile) {
        if (errorBox) {
          errorBox.textContent = 'Enter targets or load them from a file.';
          errorBox.classList.remove('hidden');
        }
        return;
      }
      if (!syncRunAtUTC()) {
        if (errorBox) {
          errorBox.textContent = 'Choose a valid first-run date and time.';
          errorBox.classList.remove('hidden');
        }
        return;
      }
      fetch(form.getAttribute('action') || '/api/v1/schedules', {
        method: 'POST',
        body: prepareWordlistFormData(form)
      })
        .then(parseJSONResponse)
        .then(function (result) {
          if (!result.ok) {
            var message = (result.body && (result.body.error || result.body.message)) || result.text;
            if (errorBox) {
              errorBox.textContent = message || ('request failed (' + result.status + ')');
              errorBox.classList.remove('hidden');
            }
            return;
          }
          window.location.reload();
        })
        .catch(function (err) {
          if (errorBox) {
            errorBox.textContent = err.message;
            errorBox.classList.remove('hidden');
          }
        });
    });
  }

  function initScheduleActions() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-schedule-delete]'), function (button) {
      button.addEventListener('click', function () {
        var id = button.getAttribute('data-schedule-delete');
        if (!id) {
          return;
        }
        portalConfirm({
          title: 'Delete schedule',
          message: 'Delete schedule ' + id + '? Future runs will no longer be queued.',
          confirmLabel: 'Delete',
          cancelLabel: 'Keep schedule',
          danger: true,
          eyebrow: 'Schedules'
        }).then(function (ok) {
          if (!ok) {
            return;
          }
          button.disabled = true;
          fetch('/api/v1/schedules/' + encodeURIComponent(id), { method: 'DELETE' })
            .then(function (resp) {
              if (!resp.ok) {
                throw new Error('delete failed with status ' + resp.status);
              }
              window.location.reload();
            })
            .catch(function (err) {
              button.disabled = false;
              portalNotify(err.message, 'error');
            });
        });
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll('[data-schedule-toggle]'), function (button) {
      button.addEventListener('click', function () {
        var id = button.getAttribute('data-schedule-toggle');
        var enabled = button.getAttribute('data-enabled') === 'true';
        if (!id) {
          return;
        }
        var enabling = !!enabled;
        portalConfirm({
          title: enabling ? 'Enable schedule' : 'Disable schedule',
          message: enabling
            ? 'Enable schedule ' + id + ' so it can queue future runs?'
            : 'Disable schedule ' + id + '? It will stop queuing new runs.',
          confirmLabel: enabling ? 'Enable' : 'Disable',
          cancelLabel: 'Cancel',
          danger: !enabling,
          eyebrow: 'Schedules'
        }).then(function (ok) {
          if (!ok) {
            return;
          }
          button.disabled = true;
          fetch('/api/v1/schedules/' + encodeURIComponent(id), {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
          })
            .then(function (resp) {
              if (!resp.ok) {
                throw new Error('update failed with status ' + resp.status);
              }
              window.location.reload();
            })
            .catch(function (err) {
              button.disabled = false;
              portalNotify(err.message, 'error');
            });
        });
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll('[data-schedule-run]'), function (button) {
      button.addEventListener('click', function () {
        var id = button.getAttribute('data-schedule-run');
        if (!id) {
          return;
        }
        portalConfirm({
          title: 'Run schedule now',
          message: 'Queue an immediate run for schedule ' + id + '?',
          confirmLabel: 'Run now',
          cancelLabel: 'Cancel',
          danger: false,
          eyebrow: 'Schedules'
        }).then(function (ok) {
          if (!ok) {
            return;
          }
          button.disabled = true;
          fetch('/api/v1/schedules/' + encodeURIComponent(id), {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ run_immediately: true })
          })
            .then(function (resp) {
              if (!resp.ok) {
                throw new Error('run request failed with status ' + resp.status);
              }
              window.location.reload();
            })
            .catch(function (err) {
              button.disabled = false;
              portalNotify(err.message, 'error');
            });
        });
      });
    });
  }

  function authHeaders() {
    var headers = { 'Content-Type': 'application/json' };
    try {
      var token = window.localStorage.getItem('rdpshot-session');
      if (token) {
        headers.Authorization = 'Bearer ' + token;
      }
    } catch (err) {
      /* ignore storage errors */
    }
    return headers;
  }

  function initScanMetaForm() {
    var form = document.getElementById('scan-meta-form');
    if (!form) {
      return;
    }
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var id = form.getAttribute('data-scan-meta');
      var engagement = (form.engagement && form.engagement.value) || '';
      var tags = ((form.tags && form.tags.value) || '').split(/[,\s]+/).filter(Boolean);
      fetch('/api/v1/scans/' + encodeURIComponent(id) + '/meta', {
        method: 'PATCH',
        headers: authHeaders(),
        body: JSON.stringify({ engagement: engagement, tags: tags })
      })
        .then(function (resp) {
          if (!resp.ok) {
            throw new Error('unable to save labels');
          }
          portalNotify('Scan labels saved', 'ok');
        })
        .catch(function (err) {
          portalNotify(err.message, 'error');
        });
    });
  }

  function saveFindingTriage(id) {
    var statusEl = document.querySelector('[data-triage-finding="' + id + '"]');
    var noteEl = document.querySelector('[data-triage-note="' + id + '"]');
    if (!statusEl) {
      return;
    }
    fetch('/api/v1/findings/' + encodeURIComponent(id) + '/triage', {
      method: 'PATCH',
      headers: authHeaders(),
      body: JSON.stringify({
        triage_status: statusEl.value,
        triage_note: noteEl ? noteEl.value : ''
      })
    })
      .then(function (resp) {
        if (!resp.ok) {
          throw new Error('unable to update triage');
        }
        portalNotify('Triage updated', 'ok');
      })
      .catch(function (err) {
        portalNotify(err.message, 'error');
      });
  }

  function initFindingTriage() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-triage-finding]'), function (el) {
      el.addEventListener('change', function () {
        saveFindingTriage(el.getAttribute('data-triage-finding'));
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-triage-save]'), function (btn) {
      btn.addEventListener('click', function () {
        saveFindingTriage(btn.getAttribute('data-triage-save'));
      });
    });
    var selectAll = document.getElementById('findings-select-all');
    if (selectAll) {
      selectAll.addEventListener('change', function () {
        Array.prototype.forEach.call(document.querySelectorAll('[data-finding-select]'), function (cb) {
          cb.checked = selectAll.checked;
        });
      });
    }
    var bulkBtn = document.getElementById('bulk-triage-apply');
    if (bulkBtn) {
      bulkBtn.addEventListener('click', function () {
        var ids = [];
        Array.prototype.forEach.call(document.querySelectorAll('[data-finding-select]:checked'), function (cb) {
          var id = Number(cb.getAttribute('data-finding-select'));
          if (id) ids.push(id);
        });
        if (!ids.length) {
          portalNotify('Select at least one finding', 'error');
          return;
        }
        var statusEl = document.getElementById('bulk-triage-status');
        var status = statusEl ? statusEl.value : 'open';
        fetch('/api/v1/findings/bulk-triage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids: ids, status: status, note: '' })
        })
          .then(function (resp) {
            if (!resp.ok) throw new Error('bulk triage failed');
            location.reload();
          })
          .catch(function (err) {
            portalNotify(err.message, 'error');
          });
      });
    }
  }

  function initTrendChart() {
    var canvas = document.getElementById('trend-chart');
    if (!canvas || typeof window.Chart !== 'function') {
      return;
    }
    var empty = document.getElementById('trend-empty');
    var filter = document.getElementById('trend-engagement');
    var chart;

    function load() {
      var q = filter && filter.value ? ('?engagement=' + encodeURIComponent(filter.value.trim())) : '';
      fetch('/api/v1/trend' + q)
        .then(function (resp) { return resp.json(); })
        .then(function (series) {
          var points = (series && series.points) || [];
          if (!points.length) {
            if (empty) {
              empty.classList.remove('hidden');
            }
            if (chart) {
              chart.destroy();
              chart = null;
            }
            return;
          }
          if (empty) {
            empty.classList.add('hidden');
          }
          var labels = points.map(function (p) {
            return (p.at || '').slice(0, 16).replace('T', ' ');
          });
          var data = {
            labels: labels,
            datasets: [
              { label: 'Critical', data: points.map(function (p) { return p.critical; }), borderColor: '#e11d48', tension: 0.25 },
              { label: 'High', data: points.map(function (p) { return p.high; }), borderColor: '#ea580c', tension: 0.25 },
              { label: 'Open triage', data: points.map(function (p) { return p.open_triage; }), borderColor: '#2563eb', tension: 0.25 }
            ]
          };
          if (chart) {
            chart.data = data;
            chart.update();
            return;
          }
          chart = new window.Chart(canvas.getContext('2d'), {
            type: 'line',
            data: data,
            options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
          });
        })
        .catch(function () {
          if (empty) {
            empty.classList.remove('hidden');
          }
        });
    }

    if (filter) {
      filter.addEventListener('change', load);
    }
    load();
  }

  function initBrandingForm() {
    var form = document.getElementById('branding-form');
    if (!form) {
      return;
    }
    fetch('/api/v1/settings/branding')
      .then(function (resp) { return resp.json(); })
      .then(function (b) {
        if (!b) {
          return;
        }
        form.organization.value = b.organization || '';
        form.engagement.value = b.engagement || '';
        form.prepared_by.value = b.prepared_by || '';
        form.footer_note.value = b.footer_note || '';
        if (form.logo_data_uri) {
          form.logo_data_uri.value = b.logo_data_uri || '';
        }
      })
      .catch(function () { /* optional */ });

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      fetch('/api/v1/settings/branding', {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({
          organization: form.organization.value,
          engagement: form.engagement.value,
          prepared_by: form.prepared_by.value,
          footer_note: form.footer_note.value,
          logo_data_uri: form.logo_data_uri ? form.logo_data_uri.value : ''
        })
      })
        .then(function (resp) {
          if (!resp.ok) {
            throw new Error('unable to save branding');
          }
          portalNotify('Branding saved', 'ok');
        })
        .catch(function (err) {
          portalNotify(err.message, 'error');
        });
    });
  }

  function initAlertsForm() {
    var form = document.getElementById('alerts-form');
    if (!form) {
      return;
    }
    var status = document.getElementById('alerts-status');
    var enabled = document.getElementById('alert-enabled');
    var critical = document.getElementById('alert-critical');
    var high = document.getElementById('alert-high');
    var nla = document.getElementById('alert-nla');
    var openCrit = document.getElementById('alert-open-crit');
    fetch('/api/v1/settings/alerts')
      .then(function (resp) { return resp.json(); })
      .then(function (rules) {
        if (!rules) return;
        form.webhook_url.value = rules.webhook_url || '';
        form.on_cred_reuse_min.value = rules.on_cred_reuse_min || 0;
        if (form.min_hardening_score) {
          form.min_hardening_score.value = rules.min_hardening_score || 0;
        }
        if (enabled) enabled.checked = !!rules.enabled;
        if (critical) critical.checked = !!rules.on_critical;
        if (high) high.checked = !!rules.on_high;
        if (nla) nla.checked = !!rules.on_nla_regressed;
        if (openCrit) openCrit.checked = !!rules.on_open_triage_critical;
      })
      .catch(function () { /* optional */ });
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      fetch('/api/v1/settings/alerts', {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({
          webhook_url: form.webhook_url.value,
          enabled: enabled ? enabled.checked : false,
          on_critical: critical ? critical.checked : false,
          on_high: high ? high.checked : false,
          on_nla_regressed: nla ? nla.checked : false,
          on_open_triage_critical: openCrit ? openCrit.checked : false,
          on_cred_reuse_min: Number(form.on_cred_reuse_min.value || 0),
          min_hardening_score: Number(form.min_hardening_score ? form.min_hardening_score.value || 0 : 0)
        })
      })
        .then(function (resp) {
          if (!resp.ok) throw new Error('unable to save alerts');
          if (status) status.textContent = 'Alert rules saved.';
          portalNotify('Alert rules saved', 'ok');
        })
        .catch(function (err) {
          if (status) status.textContent = err.message;
          portalNotify(err.message, 'error');
        });
    });
  }

  function initSIEMForm() {
    var form = document.getElementById('siem-form');
    if (!form) {
      return;
    }
    var status = document.getElementById('siem-status');
    var enabled = document.getElementById('siem-enabled');
    var format = document.getElementById('siem-format');
    fetch('/api/v1/settings/siem')
      .then(function (resp) { return resp.json(); })
      .then(function (cfg) {
        if (!cfg) {
          return;
        }
        form.webhook_url.value = cfg.webhook_url || '';
        if (format) {
          format.value = cfg.format || 'json';
        }
        if (enabled) {
          enabled.checked = !!cfg.enabled;
        }
      })
      .catch(function () { /* optional */ });

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      fetch('/api/v1/settings/siem', {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({
          webhook_url: form.webhook_url.value,
          format: format ? format.value : 'json',
          enabled: enabled ? enabled.checked : false
        })
      })
        .then(function (resp) {
          if (!resp.ok) {
            throw new Error('unable to save SIEM settings');
          }
          if (status) {
            status.textContent = 'SIEM settings saved.';
          }
          portalNotify('SIEM settings saved', 'ok');
        })
        .catch(function (err) {
          if (status) {
            status.textContent = err.message;
          }
          portalNotify(err.message, 'error');
        });
    });
  }

  function initAdminPanels() {
    var setForm = document.getElementById('wordlist-set-form');
    var setList = document.getElementById('wordlist-set-list');
    var userForm = document.getElementById('user-create-form');
    var userList = document.getElementById('user-list');
    var loginForm = document.getElementById('login-form');
    var auditBody = document.getElementById('audit-log-body');
    if (!setForm && !userForm && !auditBody) {
      return;
    }

    function refreshSets() {
      if (!setList) {
        return;
      }
      fetch('/api/v1/wordlist-sets')
        .then(function (resp) { return resp.json(); })
        .then(function (items) {
          setList.innerHTML = '';
          (items || []).forEach(function (item) {
            var li = document.createElement('li');
            li.innerHTML = '<strong>' + item.name + '</strong><br>' + item.user_path + ' / ' + item.password_path +
              ' <button type="button" class="btn btn-ghost btn-sm" data-del-set="' + item.id + '">Delete</button>';
            setList.appendChild(li);
          });
          Array.prototype.forEach.call(setList.querySelectorAll('[data-del-set]'), function (btn) {
            btn.addEventListener('click', function () {
              fetch('/api/v1/wordlist-sets/' + encodeURIComponent(btn.getAttribute('data-del-set')), {
                method: 'DELETE',
                headers: authHeaders()
              }).then(refreshSets);
            });
          });
        });
    }

    function refreshUsers() {
      if (!userList) {
        return;
      }
      fetch('/api/v1/users')
        .then(function (resp) { return resp.json(); })
        .then(function (items) {
          userList.innerHTML = '';
          (items || []).forEach(function (item) {
            var li = document.createElement('li');
            li.innerHTML = '<strong>' + item.username + '</strong> · ' + item.role +
              ' <button type="button" class="btn btn-ghost btn-sm" data-del-user="' + item.id + '">Delete</button>';
            userList.appendChild(li);
          });
          Array.prototype.forEach.call(userList.querySelectorAll('[data-del-user]'), function (btn) {
            btn.addEventListener('click', function () {
              fetch('/api/v1/users/' + encodeURIComponent(btn.getAttribute('data-del-user')), {
                method: 'DELETE',
                headers: authHeaders()
              }).then(refreshUsers);
            });
          });
        });
    }

    function refreshAudit() {
      if (!auditBody) {
        return;
      }
      fetch('/api/v1/audit?limit=50')
        .then(function (resp) { return resp.json(); })
        .then(function (items) {
          if (!items || !items.length) {
            auditBody.innerHTML = '<tr><td colspan="5" class="table-empty">No audit entries yet.</td></tr>';
            return;
          }
          auditBody.innerHTML = items.map(function (e) {
            return '<tr><td class="cell-mono">' + (e.at || '').replace('T', ' ').slice(0, 19) +
              '</td><td>' + (e.actor || '') + '</td><td>' + (e.action || '') +
              '</td><td class="cell-mono">' + (e.target || '') + '</td><td>' + (e.detail || '') + '</td></tr>';
          }).join('');
        });
    }

    if (setForm) {
      setForm.addEventListener('submit', function (ev) {
        ev.preventDefault();
        fetch('/api/v1/wordlist-sets', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            name: setForm.name.value,
            user_path: setForm.user_path.value,
            password_path: setForm.password_path.value
          })
        }).then(function (resp) {
          if (!resp.ok) {
            throw new Error('unable to create wordlist set');
          }
          setForm.reset();
          refreshSets();
        }).catch(function (err) {
          portalNotify(err.message, 'error');
        });
      });
      refreshSets();
    }

    if (userForm) {
      userForm.addEventListener('submit', function (ev) {
        ev.preventDefault();
        fetch('/api/v1/users', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            username: userForm.username.value,
            password: userForm.password.value,
            role: userForm.role.value
          })
        }).then(function (resp) {
          if (!resp.ok) {
            throw new Error('unable to create user');
          }
          userForm.reset();
          refreshUsers();
        }).catch(function (err) {
          portalNotify(err.message, 'error');
        });
      });
      refreshUsers();
    }

    if (loginForm) {
      loginForm.addEventListener('submit', function (ev) {
        ev.preventDefault();
        fetch('/api/v1/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: loginForm.username.value,
            password: loginForm.password.value
          })
        })
          .then(function (resp) { return resp.json().then(function (body) { return { ok: resp.ok, body: body }; }); })
          .then(function (result) {
            if (!result.ok) {
              throw new Error((result.body && result.body.error) || 'login failed');
            }
            try {
              window.localStorage.setItem('rdpshot-session', result.body.token);
            } catch (err) { /* ignore */ }
            var out = document.getElementById('login-token');
            if (out) {
              out.textContent = 'Session stored for ' + result.body.username + ' (' + result.body.role + ')';
            }
            portalNotify('Logged in', 'ok');
          })
          .catch(function (err) {
            portalNotify(err.message, 'error');
          });
      });
    }

    refreshAudit();
  }

  document.addEventListener('DOMContentLoaded', function () {
    initPortal();
    initTheme();
    initProgress();
    initCounters();
    initElapsedTicker();
    initLive();
    initTargetsFilePickers();
    initWordlistPickers();
    initAuthAdvanced();
    initScanForm();
    initScanLifecycleButtons();
    initScanMetaForm();
    initBruteForm();
    initFindingToggles();
    initFindingTriage();
    initPlaybookScripts();
    initKanbanBoard();
    initComplianceRadar();
    initBlastRadiusGraph();
    initLiveTerminalAndAudio();
    initScheduleForm();
    initScheduleActions();
    initExports();
    initRiskChart();
    initTrendChart();
    initBrandingForm();
    initAlertsForm();
    initSIEMForm();
    initAdminPanels();
    initGallery();
    initScansDashboard();
    initEstateMap();
    initMITREHeatmap();
    initDecoyListener();
  });
})();

// ─── MITRE ATT&CK Heatmap ────────────────────────────────────────────────────
function initMITREHeatmap() {
  var loadBtn = document.getElementById('mitreLoadBtn');
  if (!loadBtn) return;

  var grid    = document.getElementById('mitreGrid');
  var kpisEl  = document.getElementById('mitreKPIs');
  var emptyEl = document.getElementById('mitreEmpty');
  var scanSel = document.getElementById('mitreScanId');
  var engSel  = document.getElementById('mitreEngagement');

  loadBtn.addEventListener('click', function () {
    var scanId = scanSel ? scanSel.value : '';
    var eng    = engSel  ? engSel.value  : '';
    var url = scanId
      ? '/api/v1/scans/' + encodeURIComponent(scanId) + '/mitre'
      : '/api/v1/mitre?engagement=' + encodeURIComponent(eng);

    loadBtn.disabled = true;
    loadBtn.textContent = 'Loading...';
    fetch(url)
      .then(function (r) { return r.json(); })
      .then(function (hm) { renderMITREHeatmap(hm, grid, kpisEl, emptyEl); })
      .catch(function (e) { alert('Failed to load heatmap: ' + e); })
      .finally(function () { loadBtn.disabled = false; loadBtn.textContent = 'Load Heatmap'; });
  });
}

function renderMITREHeatmap(hm, grid, kpisEl, emptyEl) {
  grid.innerHTML = '';
  if (!hm.techniques || hm.techniques.length === 0) {
    if (emptyEl) emptyEl.style.display = '';
    if (kpisEl)  kpisEl.classList.add('hidden');
    return;
  }
  if (emptyEl) emptyEl.style.display = 'none';
  if (kpisEl)  kpisEl.classList.remove('hidden');

  var kpiMap = { detected: 'kpiDetected', potential: 'kpiPotential', mitigated: 'kpiMitigated', not_applicable: 'kpiNA' };
  Object.keys(kpiMap).forEach(function (k) {
    var el = document.getElementById(kpiMap[k]);
    if (el) el.textContent = hm[k] || 0;
  });

  hm.techniques.forEach(function (tech) {
    var div = document.createElement('div');
    div.className = 'mitre-card mitre-' + tech.status;
    var evHTML  = (tech.evidence    || []).map(function (e) { return '<span class="evidence-tag">' + escHtml(e) + '</span>'; }).join('');
    var mitHTML = (tech.mitigations || []).map(function (m) { return '<span class="evidence-tag" style="background:rgba(34,197,94,0.2)">' + escHtml(m) + '</span>'; }).join('');
    div.innerHTML =
      '<div class="mitre-tactic">' + escHtml(tech.tactic) + '</div>' +
      '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">' +
        '<div>' +
          '<span style="font-family:monospace;font-size:0.7rem;opacity:0.55">' + escHtml(tech.id) + '</span>' +
          '<div style="font-weight:600;font-size:0.875rem;margin-top:2px">' + escHtml(tech.name) + '</div>' +
        '</div>' +
        '<span class="mitre-badge badge-' + tech.status + '">' + tech.status.replace('_', ' ') + '</span>' +
      '</div>' +
      (tech.description ? '<p style="font-size:0.75rem;opacity:0.55;margin-top:8px;line-height:1.5">' + escHtml(tech.description) + '</p>' : '') +
      (evHTML  ? '<div style="margin-top:8px">'  + evHTML  + '</div>' : '') +
      (mitHTML ? '<div style="margin-top:4px">'  + mitHTML + '</div>' : '');
    grid.appendChild(div);
  });
}

// ─── Decoy / Honeypot Listener ───────────────────────────────────────────────
function initDecoyListener() {
  var startBtn     = document.getElementById('decoyStartBtn');
  if (!startBtn) return;

  var stopBtn      = document.getElementById('decoyStopBtn');
  var refreshBtn   = document.getElementById('decoyRefreshBtn');
  var saveBtn      = document.getElementById('decoySaveBtn');
  var clearBtn     = document.getElementById('decoyClearBtn');
  var saveStatus   = document.getElementById('decoySaveStatus');
  var statusVal    = document.getElementById('decoyStatusValue');
  var statusCard   = document.getElementById('decoyStatusCard');
  var eventCount   = document.getElementById('decoyEventCount');
  var credCount    = document.getElementById('decoyCredCount');
  var bindDisplay  = document.getElementById('decoyBindAddr');
  var tbody        = document.getElementById('decoyEventsTbody');
  var configToggle = document.getElementById('decoyConfigToggle');
  var configPanel  = document.getElementById('decoyConfigPanel');
  var configArrow  = document.getElementById('decoyConfigArrow');

  // Config inputs
  var cfgBind         = document.getElementById('cfgBind');
  var cfgWebhook      = document.getElementById('cfgWebhook');
  var cfgHostName     = document.getElementById('cfgHostName');
  var cfgOrg          = document.getElementById('cfgOrg');
  var cfgDomain       = document.getElementById('cfgDomain');
  var cfgWinVer       = document.getElementById('cfgWinVer');
  var cfgWidth        = document.getElementById('cfgWidth');
  var cfgHeight       = document.getElementById('cfgHeight');
  var cfgBgColor      = document.getElementById('cfgBgColor');
  var cfgBgColorPicker= document.getElementById('cfgBgColorPicker');
  var cfgLoginMsg     = document.getElementById('cfgLoginMsg');
  var cfgFullHandshake= document.getElementById('cfgFullHandshake');

  var pollTimer = null;

  // ── Toggle config panel ──────────────────────────────────────────────────
  if (configToggle) {
    configToggle.addEventListener('click', function () {
      var hidden = configPanel.style.display === 'none';
      configPanel.style.display = hidden ? '' : 'none';
      if (configArrow) configArrow.style.transform = hidden ? '' : 'rotate(-90deg)';
    });
  }

  // ── Color picker sync ────────────────────────────────────────────────────
  if (cfgBgColorPicker && cfgBgColor) {
    cfgBgColorPicker.addEventListener('input', function () { cfgBgColor.value = cfgBgColorPicker.value; });
    cfgBgColor.addEventListener('input', function () {
      if (/^#[0-9a-fA-F]{6}$/.test(cfgBgColor.value)) cfgBgColorPicker.value = cfgBgColor.value;
    });
  }

  // ── Load stored profile ──────────────────────────────────────────────────
  fetch('/api/v1/decoy/profile')
    .then(function (r) { return r.json(); })
    .then(function (cfg) { applyProfileToForm(cfg); })
    .catch(function () {});

  function applyProfileToForm(cfg) {
    if (!cfg) return;
    if (cfgBind && cfg.bind_addr)           cfgBind.value           = cfg.bind_addr;
    if (cfgWebhook && cfg.notify_webhook)   cfgWebhook.value        = cfg.notify_webhook;
    var p = cfg.profile || {};
    if (cfgHostName && p.host_name)         cfgHostName.value       = p.host_name;
    if (cfgOrg && p.organization)           cfgOrg.value            = p.organization;
    if (cfgDomain && p.domain)              cfgDomain.value         = p.domain;
    if (cfgWinVer && p.windows_version)     cfgWinVer.value         = p.windows_version;
    if (cfgWidth && p.desktop_width)        cfgWidth.value          = p.desktop_width;
    if (cfgHeight && p.desktop_height)      cfgHeight.value         = p.desktop_height;
    if (cfgBgColor && p.wallpaper_color)  { cfgBgColor.value = p.wallpaper_color; if (cfgBgColorPicker) cfgBgColorPicker.value = p.wallpaper_color; }
    if (cfgLoginMsg && p.login_message)     cfgLoginMsg.value       = p.login_message;
    if (cfgFullHandshake)                   cfgFullHandshake.checked = !!p.enable_full_handshake;
  }

  function buildPayload() {
    return {
      bind_addr:       cfgBind        ? cfgBind.value        : '0.0.0.0:13389',
      notify_webhook:  cfgWebhook     ? cfgWebhook.value     : '',
      profile: {
        host_name:            cfgHostName     ? cfgHostName.value      : 'WIN-RDPSHOT01',
        organization:         cfgOrg          ? cfgOrg.value           : 'Microsoft Corporation',
        domain:               cfgDomain       ? cfgDomain.value        : 'WORKGROUP',
        windows_version:      cfgWinVer       ? cfgWinVer.value        : '2019',
        desktop_width:        cfgWidth        ? parseInt(cfgWidth.value,10)||1024  : 1024,
        desktop_height:       cfgHeight       ? parseInt(cfgHeight.value,10)||768  : 768,
        wallpaper_color:      cfgBgColor      ? cfgBgColor.value       : '#1a3a5c',
        login_message:        cfgLoginMsg     ? cfgLoginMsg.value      : '',
        enable_full_handshake: cfgFullHandshake ? cfgFullHandshake.checked : false
      }
    };
  }

  // ── Status helper ────────────────────────────────────────────────────────
  function setRunning(running, bindAddr) {
    if (statusVal)   statusVal.textContent = running ? 'RUNNING' : 'STOPPED';
    if (statusCard)  statusCard.style.borderTop = running ? '3px solid #22c55e' : '3px solid #6b7280';
    if (startBtn)    startBtn.disabled = running;
    if (stopBtn) {
      stopBtn.disabled      = !running;
      stopBtn.style.opacity = running ? '1' : '0.4';
      stopBtn.style.cursor  = running ? 'pointer' : 'not-allowed';
    }
    if (bindDisplay) bindDisplay.textContent = bindAddr || '-';
    if (running && !pollTimer) {
      pollTimer = setInterval(refreshEvents, 5000);
    } else if (!running && pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function refreshStatus() {
    fetch('/api/v1/decoy/status')
      .then(function (r) { return r.json(); })
      .then(function (d) { setRunning(d.running, d.bind_addr); })
      .catch(function () {});
  }

  function refreshEvents() {
    fetch('/api/v1/decoy/events')
      .then(function (r) { return r.json(); })
      .then(function (d) { renderDecoyEvents(d.events || [], d.count || 0, tbody, eventCount, credCount); })
      .catch(function () {});
  }

  // ── Start ────────────────────────────────────────────────────────────────
  startBtn.addEventListener('click', function () {
    var payload = buildPayload();
    startBtn.disabled    = true;
    startBtn.textContent = 'Starting...';
    fetch('/api/v1/decoy/start', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload)
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        startBtn.textContent = 'Start Listener';
        if (d.error) { alert('Error: ' + d.error); startBtn.disabled = false; return; }
        setRunning(true, d.bind_addr);
        refreshEvents();
      })
      .catch(function (e) {
        alert('Request failed: ' + e);
        startBtn.disabled    = false;
        startBtn.textContent = 'Start Listener';
      });
  });

  // ── Stop ─────────────────────────────────────────────────────────────────
  if (stopBtn) {
    stopBtn.addEventListener('click', function () {
      stopBtn.disabled = true;
      fetch('/api/v1/decoy/stop', { method: 'POST' })
        .then(function () { setRunning(false, ''); })
        .catch(function () { stopBtn.disabled = false; });
    });
  }

  // ── Save Profile ─────────────────────────────────────────────────────────
  if (saveBtn) {
    saveBtn.addEventListener('click', function () {
      saveBtn.disabled = true;
      if (saveStatus) saveStatus.textContent = 'Saving...';
      fetch('/api/v1/decoy/profile', {
        method:  'PUT',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(buildPayload())
      })
        .then(function (r) { return r.json(); })
        .then(function () {
          if (saveStatus) saveStatus.textContent = 'Saved.';
          setTimeout(function () { if (saveStatus) saveStatus.textContent = ''; }, 2000);
        })
        .catch(function () { if (saveStatus) saveStatus.textContent = 'Save failed.'; })
        .finally(function () { saveBtn.disabled = false; });
    });
  }

  // ── Clear Events (client-side only) ──────────────────────────────────────
  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="13" class="table-empty">Events cleared. New connections will appear here.</td></tr>';
      }
      if (eventCount) eventCount.textContent = '0';
      if (credCount)  credCount.textContent  = '0';
    });
  }

  if (refreshBtn) refreshBtn.addEventListener('click', refreshEvents);

  refreshStatus();
  refreshEvents();
}


function renderDecoyEvents(events, count, tbody, eventCount, credCount) {
  if (eventCount) eventCount.textContent = count;
  if (!tbody) return;
  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="13" class="table-empty">No connections captured yet.</td></tr>';
    return;
  }

  if (credCount) {
    var creds = events.filter(function (e) { return e.full_auth_attempt || e.captured_username; }).length;
    credCount.textContent = creds;
  }

  var stageColors = {
    tcp: '#6b7280', rdp_neg: '#f59e0b', tls: '#3b82f6',
    ntlm: '#8b5cf6', credssp_auth: '#ef4444', mcs_active: '#22c55e'
  };

  tbody.innerHTML = events.map(function (ev) {
    var sc = stageColors[ev.stage] || '#9ca3af';
    var sb = '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;background:' + sc + ';color:#fff">' + escHtml(ev.stage||'-') + '</span>';
    var uc = ev.captured_username ? '<span style="font-weight:700;color:#ef4444">' + escHtml(ev.captured_username) + '</span>' : (ev.ntlm_workstation ? '<span style="opacity:0.5;font-size:0.8rem">' + escHtml(ev.ntlm_workstation) + '</span>' : '<span style="opacity:0.3">&#8212;</span>');
    var dc = ev.captured_domain ? '<span style="font-weight:700;color:#ef4444">' + escHtml(ev.captured_domain) + '</span>' : (ev.ntlm_domain ? '<span style="opacity:0.6">' + escHtml(ev.ntlm_domain) + '</span>' : '<span style="opacity:0.3">&#8212;</span>');
    var pc = ev.captured_password ? '<span style="font-weight:700;color:#ef4444;background:rgba(239,68,68,0.08);padding:1px 6px;border-radius:4px">' + escHtml(ev.captured_password) + '</span>' : '<span style="opacity:0.3">&#8212;</span>';
    var hc = ev.nt_hash ? '<span style="font-family:monospace;font-size:0.65rem;color:#f59e0b">' + escHtml(ev.nt_hash.substring(0,16)) + '&hellip;</span>' : '<span style="opacity:0.3">&#8212;</span>';
    var tc = ev.tls_version ? escHtml(ev.tls_version) + (ev.tls_cipher ? '<br><span style="opacity:0.45;font-size:0.62rem">' + escHtml(ev.tls_cipher.replace('TLS_','').substring(0,20)) + '</span>' : '') : '<span style="opacity:0.3">&#8212;</span>';
    return '<tr' + (ev.full_auth_attempt ? ' style="background:rgba(239,68,68,0.05)"' : '') + '>' +
      '<td style="font-family:monospace;font-size:0.7rem;white-space:nowrap">' + escHtml(ev.at) + '</td>' +
      '<td style="font-family:monospace;font-weight:700;color:#ef4444">' + escHtml(ev.remote_ip||'-') + '</td>' +
      '<td style="font-family:monospace;font-size:0.75rem;opacity:0.7">' + escHtml(ev.remote_port||'-') + '</td>' +
      '<td>' + sb + '</td><td>' + uc + '</td><td>' + dc + '</td><td>' + pc + '</td><td>' + hc + '</td>' +
      '<td style="font-size:0.72rem">' + tc + '</td>' +
      '<td style="font-family:monospace;font-size:0.7rem;color:#f59e0b">' + (ev.rdp_cookie ? escHtml(ev.rdp_cookie) : '<span style="opacity:0.3">&#8212;</span>') + '</td>' +
      '<td style="font-size:0.75rem;color:#a78bfa">' + (ev.ntlm_workstation ? escHtml(ev.ntlm_workstation) : '<span style="opacity:0.3">&#8212;</span>') + '</td>' +
      '<td style="font-family:monospace;font-size:0.62rem;opacity:0.5">' + escHtml(ev.ntlm_flags||'-') + '</td>' +
      '<td style="font-family:monospace;font-size:0.62rem;opacity:0.4;max-width:100px;overflow:hidden;text-overflow:ellipsis">' + escHtml((ev.raw||'').substring(0,24)) + '</td>' +
    '</tr>';
  }).join('');
}

function escHtml(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
