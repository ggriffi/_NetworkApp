// ── Settings helpers ──────────────────────────────────────────────────────────

export function getSettings() {
  return {
    apiKey: localStorage.getItem('np_api_key') || '',
  };
}

export function saveSettings(s) {
  localStorage.setItem('np_api_key', s.apiKey || '');
}

// ── REST client ───────────────────────────────────────────────────────────────

export async function apiFetch(path, params = {}, method = 'GET', body = null) {
  const { apiKey } = getSettings();
  const url = new URL(path, location.origin);

  if (method === 'GET') {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== null && v !== undefined && v !== '') url.searchParams.set(k, v);
    });
  }

  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (apiKey) opts.headers['X-API-Key'] = apiKey;
  if (body)   opts.body = JSON.stringify(body);

  const resp = await fetch(url.toString(), opts);
  if (!resp.ok) {
    let detail = resp.statusText;
    try { const j = await resp.json(); detail = j.detail || detail; } catch {}
    throw new Error(`${resp.status}: ${detail}`);
  }
  return resp.json();
}

// ── WebSocket client ──────────────────────────────────────────────────────────

export class WSClient {
  /**
   * @param {string} path   e.g. '/ws/ping'
   * @param {object} params query params (excluding 'key')
   */
  constructor(path, params = {}) {
    this._path   = path;
    this._params = params;
    this._ws     = null;
    this._onResult = null;
    this._onDone   = null;
    this._onError  = null;
  }

  onResult(fn) { this._onResult = fn; return this; }
  onDone(fn)   { this._onDone   = fn; return this; }
  onError(fn)  { this._onError  = fn; return this; }

  connect() {
    const { apiKey } = getSettings();
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url   = new URL(`${proto}//${location.host}${this._path}`);

    Object.entries(this._params).forEach(([k, v]) => {
      if (v !== null && v !== undefined && v !== '') url.searchParams.set(k, v);
    });
    if (apiKey) url.searchParams.set('key', apiKey);

    this._ws = new WebSocket(url.toString());

    this._ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }

      const type = msg.type || '';
      const data = msg.data;

      if (type === 'done')  { this._onDone?.();        return; }
      if (type === 'error') { this._onError?.(data);   return; }
      // result | hop | update all go to onResult
      this._onResult?.(data, type);
    };

    this._ws.onerror = () => {
      this._onError?.('WebSocket connection failed');
    };

    this._ws.onclose = (e) => {
      if (e.code !== 1000 && e.code !== 1005) {
        this._onError?.(`Disconnected (${e.code})`);
      }
    };

    return this;
  }

  send(data) {
    if (this._ws?.readyState === WebSocket.OPEN) {
      this._ws.send(JSON.stringify(data));
    }
  }

  stop() { this.send({ cmd: 'stop' }); }

  close() {
    if (this._ws) {
      this._ws.onclose = null; // suppress error on intentional close
      this._ws.close(1000);
      this._ws = null;
    }
  }

  get readyState() { return this._ws?.readyState ?? WebSocket.CLOSED; }
}

// ── RTT colour helper ─────────────────────────────────────────────────────────

export function rttClass(ms) {
  if (ms < 0)   return 'c-dim';
  if (ms < 50)  return 'c-green';
  if (ms < 150) return 'c-yellow';
  if (ms < 300) return 'c-orange';
  return 'c-red';
}

export function rttStr(ms) {
  if (ms < 0) return '—';
  return ms.toFixed(1) + ' ms';
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

export function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function copyText(text) {
  navigator.clipboard?.writeText(text).catch(() => {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    el.remove();
  });
}

export function formatBytes(bytes) {
  if (bytes < 1024)        return bytes + ' B';
  if (bytes < 1048576)     return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824)  return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

// ── Sparkline canvas ──────────────────────────────────────────────────────────

export class Sparkline {
  constructor(canvas, maxPoints = 60) {
    this._canvas = canvas;
    this._ctx    = canvas.getContext('2d');
    this._data   = [];
    this._max    = maxPoints;
    this._color  = getComputedStyle(document.documentElement)
                     .getPropertyValue('--cyan').trim();
    this._resize();
    window.addEventListener('resize', () => this._resize());
  }

  _resize() {
    const r = this._canvas.getBoundingClientRect();
    this._canvas.width  = r.width  * devicePixelRatio;
    this._canvas.height = r.height * devicePixelRatio;
    this._draw();
  }

  push(val) {
    if (val < 0) { this._data.push(null); }
    else         { this._data.push(val); }
    if (this._data.length > this._max) this._data.shift();
    this._draw();
  }

  _draw() {
    const { _canvas: c, _ctx: ctx, _data: data } = this;
    const W = c.width, H = c.height;
    ctx.clearRect(0, 0, W, H);
    if (data.length < 2) return;

    const valid  = data.filter(v => v !== null);
    if (!valid.length) return;
    const maxVal = Math.max(...valid, 1);

    const step = W / (this._max - 1);

    // Fill gradient
    const grad = ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0,   'rgba(0,217,255,0.25)');
    grad.addColorStop(1,   'rgba(0,217,255,0)');

    ctx.beginPath();
    let started = false;
    data.forEach((v, i) => {
      const x = i * step;
      const y = v === null ? H : H - (v / maxVal) * (H - 4);
      if (!started) { ctx.moveTo(x, y); started = true; }
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(W, H);
    ctx.lineTo(0, H);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    started = false;
    data.forEach((v, i) => {
      if (v === null) { started = false; return; }
      const x = i * step;
      const y = H - (v / maxVal) * (H - 4);
      if (!started) { ctx.moveTo(x, y); started = true; }
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = this._color;
    ctx.lineWidth   = 1.5 * devicePixelRatio;
    ctx.stroke();
  }
}
