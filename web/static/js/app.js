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

  var MAX_LOG_LINES = 500;

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
      label.textContent = done + '/' + total + ' (' + pct.toFixed(1) + '%)';
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
  /* live terminal + findings (SSE)                                       */
  /* ------------------------------------------------------------------ */

  function appendLogLine(message, cssClass) {
    var log = document.getElementById('live-log');
    if (!log || !message) {
      return;
    }

    var placeholder = log.querySelector('.terminal-placeholder');
    if (placeholder && placeholder.parentNode) {
      placeholder.parentNode.removeChild(placeholder);
    }

    var now = new Date();
    var hh = ('0' + now.getHours()).slice(-2);
    var mm = ('0' + now.getMinutes()).slice(-2);
    var ss = ('0' + now.getSeconds()).slice(-2);

    var line = document.createElement('p');
    line.className = 'log-line' + (cssClass ? ' ' + cssClass : '');

    var ts = document.createElement('span');
    ts.className = 'log-ts';
    ts.textContent = '[' + hh + ':' + mm + ':' + ss + '] ';

    line.appendChild(ts);
    line.appendChild(document.createTextNode(String(message)));
    log.appendChild(line);

    while (log.childNodes.length > MAX_LOG_LINES) {
      log.removeChild(log.firstChild);
    }

    log.scrollTop = log.scrollHeight;
  }

  function prependFinding(payload) {
    var list = document.getElementById('live-findings');
    if (!list) {
      return;
    }

    var empty = list.querySelector('[data-live-empty]');
    if (empty && empty.parentNode) {
      empty.parentNode.removeChild(empty);
    }

    var severity = payload.severity || payload.Severity || 'info';
    var title = payload.title || payload.Title || payload.check_id || payload.CheckID || 'Finding';
    var address = payload.address || payload.Address || payload.host || '';
    var port = payload.port || payload.Port || '';
    var target = address ? address + (port ? ':' + port : '') : 'unknown target';

    var item = document.createElement('li');
    item.className = 'rounded-lg border border-slate-800 bg-slate-950/40 p-3';

    var head = document.createElement('div');
    head.className = 'flex items-center justify-between gap-2';

    var titleEl = document.createElement('p');
    titleEl.className = 'text-sm font-medium text-white';
    titleEl.textContent = String(title);

    var badge = document.createElement('span');
    badge.className = 'badge';
    badge.style.color = severityColor(severity);
    badge.style.borderColor = severityColor(severity);
    badge.textContent = String(severity);

    head.appendChild(titleEl);
    head.appendChild(badge);

    var meta = document.createElement('p');
    meta.className = 'mt-1 font-mono text-xs text-slate-400';
    meta.textContent = target;

    item.appendChild(head);
    item.appendChild(meta);
    list.insertBefore(item, list.firstChild);
  }

  function updateProgressFromPayload(payload) {
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
      if (counterMap[name] !== undefined && counterMap[name] !== null) {
        setCounter(name, counterMap[name]);
      }
    });

    var label = document.getElementById('scan-progress-label');
    if (label && done !== undefined && total !== undefined) {
      var pct = toInt(total) > 0 ? ((toInt(done) / toInt(total)) * 100).toFixed(1) : '0.0';
      label.textContent = done + '/' + total + ' (' + pct + '%)';
    }
  }

  function handleEvent(type, rawData) {
    var payload = {};
    if (rawData) {
      try {
        payload = JSON.parse(rawData);
      } catch (err) {
        payload = { message: String(rawData) };
      }
    }
    if (typeof payload !== 'object' || payload === null) {
      payload = { message: String(payload) };
    }

    var effectiveType = String(payload.type || payload.Type || type || 'message').toLowerCase();

    if (effectiveType === 'progress' || effectiveType === 'scan_progress') {
      updateProgressFromPayload(payload);
    }

    if (effectiveType === 'finding' || effectiveType === 'findings') {
      prependFinding(payload.payload && typeof payload.payload === 'object' ? payload.payload : payload);
    }

    var message = payload.message || payload.Message || payload.msg || payload.log || payload.Log;
    if (!message && payload.payload && typeof payload.payload === 'object') {
      message = payload.payload.message || payload.payload.title || payload.payload.Title;
    }
    if (!message) {
      try {
        message = JSON.stringify(payload);
      } catch (err) {
        message = effectiveType;
      }
    }

    var cssClass = '';
    if (effectiveType === 'error' || effectiveType === 'failed') {
      cssClass = 'log-error';
    } else if (effectiveType === 'finding' || effectiveType === 'findings') {
      cssClass = 'log-finding';
    }

    appendLogLine('[' + effectiveType + '] ' + message, cssClass);
  }

  function initLive() {
    var log = document.getElementById('live-log');
    var findings = document.getElementById('live-findings');
    var progressEl = document.getElementById('scan-progress');
    if (!log && !findings && !progressEl) {
      return;
    }
    if (typeof window.EventSource === 'undefined') {
      appendLogLine('[system] live streaming is not supported by this browser', 'log-error');
      return;
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

    var url = '/api/v1/events' + (scanID ? '?scan=' + encodeURIComponent(scanID) : '');
    var source;
    try {
      source = new EventSource(url);
    } catch (err) {
      appendLogLine('[system] unable to open event stream', 'log-error');
      return;
    }

    var eventTypes = [
      'message', 'log', 'info', 'progress', 'scan_progress',
      'finding', 'findings', 'host', 'cred', 'credential',
      'screenshot', 'scan', 'status', 'error', 'done', 'completed'
    ];

    eventTypes.forEach(function (type) {
      source.addEventListener(type, function (ev) {
        handleEvent(type, ev.data);
      });
    });

    source.addEventListener('error', function () {
      appendLogLine('[system] event stream disconnected, retrying…', 'log-error');
    });
  }

  /* ------------------------------------------------------------------ */
  /* quick scan form                                                     */
  /* ------------------------------------------------------------------ */

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

      var ack = document.getElementById('ack_authorized');
      if (ack && !ack.checked) {
        showError('Please confirm that you are authorized to test these targets.');
        return;
      }

      var body = new URLSearchParams(new FormData(form)).toString();

      fetch(form.getAttribute('action') || '/api/v1/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      })
        .then(function (resp) {
          return resp.text().then(function (text) {
            var parsed = null;
            try {
              parsed = text ? JSON.parse(text) : {};
            } catch (err) {
              parsed = null;
            }
            return { ok: resp.ok, status: resp.status, body: parsed, text: text };
          });
        })
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
  /* cancel scan buttons: [data-cancel-scan]                              */
  /* ------------------------------------------------------------------ */

  function initCancelButtons() {
    var buttons = document.querySelectorAll('[data-cancel-scan]');
    Array.prototype.forEach.call(buttons, function (button) {
      button.addEventListener('click', function () {
        var scanID = button.getAttribute('data-cancel-scan');
        if (!scanID) {
          return;
        }
        if (typeof window.confirm === 'function' &&
            !window.confirm('Cancel scan ' + scanID + '? Running checks will be stopped.')) {
          return;
        }

        button.disabled = true;
        fetch('/api/v1/scans/' + encodeURIComponent(scanID) + '/cancel', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        })
          .then(function (resp) {
            if (!resp.ok) {
              throw new Error('cancel request failed with status ' + resp.status);
            }
            window.location.reload();
          })
          .catch(function (err) {
            button.disabled = false;
            window.alert('Unable to cancel scan: ' + err.message);
          });
      });
    });
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

    Array.prototype.forEach.call(buttons, function (button) {
      button.addEventListener('click', function () {
        var url = button.getAttribute('data-export-url');
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

    new window.Chart(canvas.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: 'rgba(15, 23, 42, 0.8)',
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
              color: '#94a3b8',
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
  }

  /* ------------------------------------------------------------------ */
  /* gallery search fallback: [data-gallery-search]                       */
  /* ------------------------------------------------------------------ */

  function initGallery() {
    var input = document.querySelector('[data-gallery-search]');
    if (!input) {
      return;
    }

    var items = document.querySelectorAll('[data-gallery-item]');
    var counter = document.getElementById('gallery-count');
    var noMatch = document.getElementById('gallery-no-match');

    function applyFilter() {
      var query = input.value.trim().toLowerCase();
      var visible = 0;

      Array.prototype.forEach.call(items, function (item) {
        var haystack = (
          (item.getAttribute('data-address') || '') + ' ' +
          (item.getAttribute('data-username') || '')
        ).toLowerCase();
        var match = !query || haystack.indexOf(query) !== -1;
        item.style.display = match ? '' : 'none';
        if (match) {
          visible += 1;
        }
      });

      if (counter) {
        counter.textContent = query ?
          visible + ' of ' + items.length + ' sessions match' :
          items.length + ' sessions captured';
      }
      if (noMatch) {
        noMatch.classList.toggle('hidden', visible > 0);
      }
    }

    input.addEventListener('input', applyFilter);
    input.addEventListener('search', applyFilter);
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

  document.addEventListener('DOMContentLoaded', function () {
    initProgress();
    initCounters();
    initElapsedTicker();
    initLive();
    initScanForm();
    initCancelButtons();
    initExports();
    initRiskChart();
    initGallery();
  });
})();